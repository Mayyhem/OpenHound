"""Shared source-run context for SCCM collectors.

``SourceContext`` wraps the LDAP/AD client and all CMBP-equivalent CLI knobs
(``--collection-methods``, ``--computers``, ``--sms-provider``, etc.) and
provides the lazy-loaded caches that every ``@app.resource`` in
``collectors/*`` shares:

* ``ldap_computer_hosts()`` — paged ``(&(objectCategory=computer)
  (objectClass=computer))`` query; cached.
* ``adminservice_payloads()`` — per-SMS-Provider AdminService REST payload
  cache. Hits each provider once per source run.
* ``smb_shares(hostname)`` — per-host SMB share enumeration cache.
* ``sccm_discovered_hosts()`` — union of hosts discovered via every SCCM
  channel (SMS Provider LDAP, naming-pattern LDAP, mSSMSManagementPoint LDAP,
  AdminService); the OH equivalent of CMBP's ``TargetManager`` host list.

The helpers ``_collect_adminservice_data``, ``_probe_mssql_epa`` and
``_smb_list_shares`` referenced from this module's methods still live in
``source.py`` (or, once the split is complete, under ``collectors/``).
They're resolved via lazy imports inside each method so this module
imports cleanly without creating cycles.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Optional

from .clients.ad import ADClient
from .log_context import phase_context, target_context

logger = logging.getLogger(__name__)


@dataclass
class SourceContext:
    ad: ADClient
    domain: str
    username: Optional[str] = None
    password: Optional[str] = None
    # ---- CMBP-equivalent CLI knobs (set via SOURCES__SCCM__* env vars by
    # the Typer commands in ``main.py``, or directly by the user). ----------
    # Collection (-m / --collection-methods)
    collection_methods: str = "All"
    # Targets / filters (-c / -cf / -sms / -sc)
    computers: Optional[str] = None
    computer_file: Optional[str] = None
    sms_provider: Optional[str] = None
    site_codes: Optional[str] = None
    # Behavior flags
    disable_possible_edges: bool = False
    enable_bad_opsec: bool = False
    threads: int = 1
    show_cleartext_passwords: bool = False
    # Machine Account / CRED-2 (flags accepted; implementation chain deferred)
    machine_name: Optional[str] = None
    machine_pass: Optional[str] = None
    client_name: Optional[str] = None
    create_machine_account: Optional[str] = None
    use_altauth: bool = False
    registration_sleep: int = 10
    # Network
    socks_proxy: Optional[str] = None
    # ---- Per-host target enumeration (Phase 3a) ----------------------------
    # The Phase 3 per-host phases (RemoteRegistry / MSSQL / AdminService / WMI /
    # HTTP / SMB) need a list of hostnames before preproc has built ``sccm.targets``.
    # Resources can't share state via DLT, but they *can* share state via the
    # ``ctx`` they all close over. We expose two cached helpers below; each is
    # populated lazily on first access and re-used by every resource that
    # iterates targets.
    _ldap_computer_hosts: Optional[list[dict[str, Any]]] = None
    # Phase 3b — AdminService payload cache. Each SMS Provider is queried once
    # per source run; the payload (sites + admins + collections + ...) is
    # cached and re-served to every adminservice_* resource. This avoids 9x
    # HTTP traffic against the same provider.
    _adminservice_payloads: Optional[dict[str, dict[str, Any]]] = None
    # Per-host SMB share enumeration cache. Populated lazily on first access
    # by ``smb_shares()``; re-used by the smb_site_servers /
    # smb_distribution_points / smb_signing_status resources AND by the
    # ldap_sites resource when it folds in SMB-only-discovered site_codes
    # (so that a Secondary site server only reachable via SMB still gets a
    # SCCM_Site node emitted, even when LDAP mSSMSSite + AdminService both
    # miss it). The cache key is the hostname; ``None`` means we tried and
    # the SMB connection failed (auth or unreachable).
    _smb_shares: Optional[dict[str, Optional[list[dict[str, str]]]]] = None
    # Phase 3a — SCCM-discovered host gate. Cached set of FQDN/short hostnames
    # that have been discovered via any SCCM channel (mSSMSManagementPoint,
    # SMS Provider naming pattern, SCCM-naming-pattern LDAP query, DNS SRV,
    # AdminService SMS_Site / SMS_SCI_SiteDefinition / SMS_SCI_SysResUse).
    # Used to gate the MSSQL TDS prelogin sweep so we only emit MSSQL_Server
    # nodes for hosts CMBP would have probed (matches the CMBP per-host
    # pipeline target list — CMBP runs MSSQL phase only on discovered targets,
    # not against every domain computer).
    _sccm_discovered_hosts: Optional[set[str]] = None
    # Site codes (UPPERCASE) emitted into the ``ldap_sites`` DLT table by
    # any of the three resources that write to it: ``ldap_sites`` (Phase 1,
    # LDAP-only mSSMSSite + mSSMSManagementPoint), ``ldap_sites_admin_extra``
    # (Phase 7, AdminService-only SMS_Site / SMS_SCI_SiteDefinition rows
    # missing from LDAP) and ``ldap_sites_smb_extra`` (Phase 10, SMB-share
    # discovered site codes on hosts not surfaced by either of the prior
    # two). DLT writes append-mode by default; without this cross-resource
    # dedup set, a single SCCM site visible from all three channels would
    # produce three SCCM_Site nodes with the same node_id.
    _emitted_site_codes: Optional[set[str]] = None

    @property
    def system_management_dn(self) -> str:
        return f"CN=System Management,CN=System,{self.ad.base_dn}"

    # ---- Collection method gating (CMBP -m / --collection-methods) --------

    def method_enabled(self, method: str) -> bool:
        """Return True when ``method`` (e.g. "AdminService", "WMI", "SMB") is
        enabled by the current ``collection_methods`` setting.

        The value is a comma-separated list of method names (case-insensitive),
        matching CMBP's ``-m`` flag. ``"All"`` (the default) enables every
        method. Unknown method names are ignored so callers can pass in
        arbitrary labels without crashing the pipeline.
        """
        if not self.collection_methods:
            return True
        wanted = {m.strip().lower() for m in self.collection_methods.split(",") if m.strip()}
        if "all" in wanted:
            return True
        return method.lower() in wanted

    # ---- Per-host target filtering (CMBP -c / -cf) ------------------------

    def explicit_target_hosts(self) -> Optional[set[str]]:
        """Return the user-supplied set of target hostnames (lowercased),
        or ``None`` if no filter is active.

        Combines ``--computers`` (CSV) and ``--computer-file`` (one host per
        line; ``#`` comments stripped). The file is read once per source run.
        """
        targets: set[str] = set()
        if self.computers:
            for piece in self.computers.split(","):
                piece = piece.strip().lower()
                if piece:
                    targets.add(piece)
        if self.computer_file:
            try:
                with open(self.computer_file, encoding="utf-8") as fh:
                    for line in fh:
                        host = line.split("#", 1)[0].strip().lower()
                        if host:
                            targets.add(host)
            except OSError as exc:
                logger.warning("computer_file %s unreadable: %s", self.computer_file, exc)
        return targets or None


    def ldap_computer_hosts(self) -> list[dict[str, Any]]:
        """Return cached list of (sid, sam, dnshostname, name) dicts for AD computers.

        Hits LDAP exactly once per source run. Hostname is lowercased; entries
        without a ``dnsHostName`` fall back to ``<sam>.<domain>``. If
        ``--computers`` / ``--computer-file`` is set, the result is filtered
        to that allowlist (FQDN or short-name match) so per-host phases only
        iterate the user-selected targets.
        """
        if self._ldap_computer_hosts is not None:
            return self._ldap_computer_hosts
        # The work this method does is LDAP enumeration. Tag log lines as such
        # even when the *caller* is a per-host phase like RemoteRegistry that
        # incidentally triggers the cache-fill on first access.
        with phase_context("LDAP"), target_context(self.domain):
            return self._build_ldap_computer_hosts()

    def _build_ldap_computer_hosts(self) -> list[dict[str, Any]]:
        explicit = self.explicit_target_hosts()
        out: list[dict[str, Any]] = []
        raw_count = 0
        disabled_count = 0
        try:
            for entry in self.ad.paged_search(
                search_filter="(&(objectCategory=computer)(objectClass=computer))",
                attributes=["objectSid", "sAMAccountName", "dNSHostName", "name", "userAccountControl"],
            ):
                raw_count += 1
                # Skip disabled accounts — they're not reachable hosts.
                uac = entry.get("userAccountControl")
                try:
                    if uac is not None and (int(uac) & 0x2):
                        disabled_count += 1
                        continue
                except (TypeError, ValueError):
                    pass
                sam = (entry.get("sAMAccountName") or "").rstrip("$")
                dns = (entry.get("dNSHostName") or "").lower() or None
                if not dns and sam:
                    dns = f"{sam.lower()}.{self.domain.lower()}"
                if not dns:
                    continue
                if explicit and not (dns in explicit or dns.split(".", 1)[0] in explicit):
                    continue
                out.append({
                    "sid": entry.get("object_sid"),
                    "sam": sam,
                    "hostname": dns,
                    "name": entry.get("name"),
                })
        except Exception as e:  # noqa: BLE001
            logger.warning("ldap_computer_hosts: LDAP enumeration failed: %s", e)
        self._ldap_computer_hosts = out
        if explicit:
            logger.info(
                "ldap_computer_hosts: %d enabled hosts kept "
                "(LDAP returned %d, %d disabled, filtered to %d explicit targets)",
                len(out),
                raw_count,
                disabled_count,
                len(explicit),
            )
        else:
            logger.info(
                "ldap_computer_hosts: %d enabled hosts "
                "(LDAP returned %d total, %d disabled)",
                len(out),
                raw_count,
                disabled_count,
            )
        if raw_count == 0:
            logger.warning(
                "ldap_computer_hosts: LDAP `(&(objectCategory=computer)"
                "(objectClass=computer))` under %s returned 0 entries — "
                "either the bound account cannot read computer objects, or "
                "the domain genuinely has none. All per-host phases (MSSQL, "
                "RemoteRegistry, WMI, HTTP, SMB) will emit no rows.",
                self.ad.base_dn,
            )
        return out

    # ---- AdminService payload cache ----------------------------------------
    # Each SMS Provider's AdminService is queried once per source run. The
    # adminservice_* resources all share this cache so we don't hit each
    # endpoint nine times.

    def adminservice_payloads(self) -> dict[str, dict[str, Any]]:
        """Return ``{hostname: payload}`` mapping for every SMS Provider that
        responds to the AdminService REST API.

        Each payload is a dict with the keys produced by
        ``_collect_adminservice_data`` below: ``site_code``, ``admins``,
        ``collections``, ``collection_members``, ``security_roles``,
        ``client_devices``, ``task_sequences``, ``collection_variables``,
        ``site_systems``. Hosts that fail authentication or aren't reachable
        on TCP 443 are silently skipped (logged at INFO).

        Transport
        ---------
        AdminService HTTPS calls are routed through ``curl.exe`` rather than
        Python ``requests`` because Python 3.14's bundled OpenSSL on Windows
        triggers an ``OPENSSL_Uplink: no OPENSSL_Applink`` process abort on
        any TLS handshake (see HANDOFF.md Risk 8). curl uses Schannel and
        sidesteps the issue entirely. To force-disable the AdminService phase
        regardless, pass ``-m All,-AdminService`` (or omit it from ``-m``).
        """
        if self._adminservice_payloads is not None:
            return self._adminservice_payloads

        if not self.method_enabled("AdminService"):
            with phase_context("AdminService"), target_context(self.domain):
                logger.info("adminservice_payloads: disabled via --collection-methods")
            self._adminservice_payloads = {}
            return self._adminservice_payloads

        # Lazy import to avoid a context.py <-> collectors module-load cycle
        # (collectors all import this module for ``SourceContext``).
        from .collectors import adminservice as _asvc

        with phase_context("AdminService"), target_context(self.domain):
            return self._build_adminservice_payloads(_asvc)

    def _build_adminservice_payloads(self, _asvc) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        # The SMS Provider list comes from the same LDAP filter used by
        # ``ldap_sms_providers``: any computer whose sAMAccountName ends in
        # ``-pss$`` or ``-sms$``. We re-query rather than relying on cross-
        # resource state because DLT's resource execution order isn't
        # guaranteed.
        provider_hosts: list[str] = []
        try:
            for entry in self.ad.paged_search(
                search_filter=(
                    "(&(objectCategory=computer)"
                    "(|(samAccountName=*-pss$)(samAccountName=*-sms$)))"
                ),
                attributes=["sAMAccountName", "dNSHostName"],
            ):
                dns = (entry.get("dNSHostName") or "").lower() or None
                if not dns:
                    sam = (entry.get("sAMAccountName") or "").rstrip("$").lower()
                    if sam:
                        dns = f"{sam}.{self.domain.lower()}"
                if dns:
                    provider_hosts.append(dns)
        except Exception as e:  # noqa: BLE001
            logger.warning("adminservice_payloads: SMS Provider enumeration failed: %s", e)

        # De-dup while preserving order
        seen: set[str] = set()
        ordered: list[str] = []
        for h in provider_hosts:
            if h not in seen:
                seen.add(h)
                ordered.append(h)

        # ``-sms / --sms-provider`` pins the discovery to exactly one host.
        if self.sms_provider:
            pinned = self.sms_provider.strip().lower()
            ordered = [h for h in ordered if h == pinned or h.split(".", 1)[0] == pinned]
            if not ordered:
                logger.warning("adminservice_payloads: --sms-provider %s matched no LDAP-discovered providers", self.sms_provider)

        for host in ordered:
            with target_context(host):
                try:
                    payload = _asvc._collect_adminservice_data(host, self.username, self.password)
                except Exception as e:  # noqa: BLE001
                    logger.info("adminservice: collection failed for %s: %s", host, e)
                    continue
                if payload is None:
                    continue
                out[host] = payload

        self._adminservice_payloads = out
        return out

    # ---- Per-host SMB share enumeration cache ------------------------------

    def smb_shares(self, hostname: str) -> Optional[list[dict[str, str]]]:
        """Return the list of SMB shares on ``hostname``, or ``None`` on
        connect/auth failure. Cached per-hostname so multiple SMB-using
        resources don't pay the cost twice.
        """
        if self._smb_shares is None:
            self._smb_shares = {}
        if hostname in self._smb_shares:
            return self._smb_shares[hostname]
        # Lazy import to avoid a context.py <-> collectors module-load cycle.
        from .collectors import smb as _smb

        with phase_context("SMB"), target_context(hostname):
            result = _smb._smb_list_shares(hostname, self.domain, self.username, self.password)
        self._smb_shares[hostname] = result
        return result

    # ---- SCCM-discovered host gate -----------------------------------------

    def sccm_discovered_hosts(self) -> set[str]:
        """Return the set of host identifiers (lowercased FQDN + short name)
        that have been discovered via any SCCM channel.

        This is the OH equivalent of CMBP's ``TargetManager`` host list —
        the set of hosts CMBP's per-host phases (MSSQL, AdminService, SMB,
        etc.) actually visit. Used to gate the MSSQL TDS prelogin sweep so
        we don't emit phantom MSSQL_Server nodes for arbitrary domain
        computers that happen to listen on 1433 (e.g. lab CAS-DB/PS1-DB
        when running as low-priv user with no AdminService access).

        Sources combined:
          * LDAP-mSSMSManagementPoint (``ldap_sms_providers`` filter)
          * LDAP SCCM-naming-pattern (sccm/mecm/mcm/memcm/configm/cfgm/sms)
          * DNS-SRV management points (probed at runtime via
            ``_dns_management_points`` query — same logic as the
            ``dns_management_points`` resource)
          * AdminService SMS_Site / SMS_SCI_SiteDefinition / SMS_SCI_SysResUse
            — only included if the AdminService payload cache has already
            been populated (i.e. by Phase 7). This method NEVER triggers the
            AdminService cache itself, so calling it from Phases 1/5/6
            (where the cache is still empty) yields the LDAP-only set,
            matching CMBP's pre-AdminService TargetManager.

        Hosts are lowercased; both FQDN (`host.domain.tld`) and short name
        (`host`) variants are inserted so callers can match on either form.

        Cached per-source-run.
        """
        if self._sccm_discovered_hosts is not None:
            return self._sccm_discovered_hosts

        out: set[str] = set()
        # Per-channel host counts (FQDNs only — short-name dupes elided) so
        # the summary line tells the user which channel(s) contributed and
        # which came up empty. Empty across the board → no SCCM deployment
        # in this domain (or insufficient privileges to read its objects).
        channel_counts: dict[str, int] = {
            "SMS-provider-LDAP": 0,
            "naming-pattern-LDAP": 0,
            "mSSMSManagementPoint-LDAP": 0,
            "AdminService": 0,
        }

        def _add(channel: str, name: Optional[str]) -> None:
            if not name:
                return
            n = name.strip().lower()
            if not n:
                return
            # Count the host against this channel only on its first appearance
            # (any channel) and only in FQDN form, so totals reflect distinct
            # hosts rather than 2× (FQDN + short) and the same host isn't
            # double-counted across channels.
            is_new_fqdn = "." in n and n not in out
            out.add(n)
            short = n.split(".", 1)[0]
            if short and short != n:
                out.add(short)
            if is_new_fqdn:
                channel_counts[channel] += 1

        # 1. SMS Provider hostnames (sAMAccountName ends in -pss / -sms) — LDAP work.
        with phase_context("LDAP"), target_context(self.domain):
            try:
                for entry in self.ad.paged_search(
                    search_filter=(
                        "(&(objectCategory=computer)"
                        "(|(samAccountName=*-pss$)(samAccountName=*-sms$)))"
                    ),
                    attributes=["sAMAccountName", "dNSHostName"],
                ):
                    dns = entry.get("dNSHostName")
                    if not dns:
                        sam = (entry.get("sAMAccountName") or "").rstrip("$")
                        if sam:
                            dns = f"{sam}.{self.domain}"
                    _add("SMS-provider-LDAP", dns)
            except Exception as e:  # noqa: BLE001
                logger.warning("sccm_discovered_hosts: SMS-provider LDAP failed: %s", e)

            # 2. SCCM-naming-pattern hostnames — mirror of CMBP's
            # _analyze_naming_patterns (sccm/mecm/mcm/memcm/configm/cfgm/sms).
            try:
                patterns = ["sccm", "mecm", "mcm", "memcm", "configm", "cfgm", "sms"]
                filter_parts: list[str] = []
                for p in patterns:
                    filter_parts.append(f"(samaccountname=*{p}*)")
                    filter_parts.append(f"(name=*{p}*)")
                    filter_parts.append(f"(cn=*{p}*)")
                    filter_parts.append(f"(dnshostname=*{p}*)")
                ldap_filter = (
                    f"(&(objectCategory=computer)(|{''.join(filter_parts)}))"
                )
                for entry in self.ad.paged_search(
                    search_filter=ldap_filter,
                    attributes=["sAMAccountName", "dNSHostName"],
                ):
                    dns = entry.get("dNSHostName")
                    if not dns:
                        sam = (entry.get("sAMAccountName") or "").rstrip("$")
                        if sam:
                            dns = f"{sam}.{self.domain}"
                    _add("naming-pattern-LDAP", dns)
            except Exception as e:  # noqa: BLE001
                logger.warning("sccm_discovered_hosts: name-pattern LDAP failed: %s", e)

            # 3. mSSMSManagementPoint records under the System Management container
            # (the LDAP-mSSMSManagementPoint discovery channel).
            try:
                for entry in self.ad.paged_search(
                    search_filter="(objectClass=mSSMSManagementPoint)",
                    base=self.system_management_dn,
                    attributes=["dNSHostName", "name", "mSSMSMPName"],
                ):
                    dns = (
                        entry.get("dNSHostName")
                        or entry.get("mSSMSMPName")
                        or entry.get("name")
                    )
                    _add("mSSMSManagementPoint-LDAP", dns)
            except Exception as e:  # noqa: BLE001
                logger.warning(
                    "sccm_discovered_hosts: mSSMSManagementPoint LDAP search under %s failed: %s",
                    self.system_management_dn,
                    e,
                )

        # 4. DNS-SRV management points — skipped here. Adding a DNS sweep
        # would duplicate work the ``dns_management_points`` resource already
        # does, and DNS-only-discovered hosts are rarely also MSSQL hosts.
        # If we ever need it, we can have ``dns_management_points`` push its
        # rows back into ``self._sccm_discovered_hosts``.

        # 5. AdminService discovered hosts. We *only* fold these in if the
        # AdminService payload cache has already been populated by the
        # AdminService phase (Phase 7). Calling ``adminservice_payloads()``
        # here would eagerly fire Phase 7's HTTP work during MSSQL/Registry
        # (Phase 5–6) and break the documented phase ordering:
        #   1 LDAP → 2 Local → 3 DNS → 4 DHCP → 5 Registry → 6 MSSQL →
        #   7 AdminService → 8 WMI → 9 HTTP → 10 SMB.
        # Since every current caller of this method runs before Phase 7
        # (mssql_epa_flags, registry_current_users, ldap_sites SMB fold-in),
        # the AdminService cache is normally empty at call time and this
        # branch contributes nothing — matching CMBP, whose pre-AdminService
        # phases see only the LDAP-derived TargetManager set.
        if self._adminservice_payloads:
            try:
                for payload in self._adminservice_payloads.values():
                    # SMS_SCI_SysResUse: per-site role hosts (Site Server, SMS
                    # Provider, MP, DP, Reporting SP, etc.)
                    for ss in payload.get("site_systems", []) or []:
                        _add("AdminService", ss.get("hostname"))
                    # SMS_SCI_SiteDefinition surfaces ``SQLServerName`` (the DB
                    # host for each primary).
                    for sd in payload.get("site_definitions", []) or []:
                        _add("AdminService", sd.get("SQLServerName"))
                    # SMS_Site SiteServerName (the primary site server).
                    for site in payload.get("sites", []) or []:
                        _add("AdminService", site.get("SiteServerName"))
            except Exception as e:  # noqa: BLE001
                with phase_context("AdminService"), target_context(self.domain):
                    logger.warning("sccm_discovered_hosts: AdminService failed: %s", e)

        self._sccm_discovered_hosts = out
        total = len({h for h in out if "." in h})
        per_channel = ", ".join(f"{k}={v}" for k, v in channel_counts.items())
        # The summary line spans every channel — tag it with the domain only
        # (no phase) so it doesn't get bucketed into one specific phase's logs.
        with target_context(self.domain):
            logger.info(
                "sccm_discovered_hosts: %d hosts discovered (%s)",
                total,
                per_channel,
            )
            if total == 0:
                logger.warning(
                    "sccm_discovered_hosts: 0 hosts — every SCCM discovery channel "
                    "returned empty. Likely causes: "
                    "(1) no SCCM deployment in this domain (no SMS Provider host, "
                    "no mSSMSManagementPoint object under %s, no SCCM-named "
                    "computers, no AdminService reachable); "
                    "(2) calling account lacks read on the System Management "
                    "container; "
                    "(3) collector cannot reach AdminService on TCP/443 to a "
                    "provider host. "
                    "With 0 discovered hosts, per-host phases (MSSQL, AdminService, "
                    "WMI, HTTP, SMB, RemoteRegistry) emit no rows.",
                    self.system_management_dn,
                )
        return out
