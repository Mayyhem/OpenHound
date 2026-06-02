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
from dataclasses import dataclass, field
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
    # CmRcService SPN match cache. Populated by ``cmrc_spn_matches()`` when
    # the LDAP phase first asks for it; the network call is bracketed by
    # ``phase_context("LDAP")`` so the resulting log line is tagged as an
    # LDAP event regardless of which resource forces the lazy build. PS1
    # also runs this query exactly once during its LDAP once-phase
    # (``ConfigManBearPig.ps1:3221``).
    _cmrc_spn_matches: Optional[list[dict[str, Any]]] = None
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
    # Mutable per-host probe-target accumulator. PS1's ``Add-DeviceToTargets``
    # appends to a live list and each subsequent per-host phase iterates the
    # *updated* list — so an MP discovered mid-run via MPLIST XML parsing
    # still gets RemoteRegistry / MSSQL / WMI / HTTP / SMB probes. The OH
    # per-host resources call ``target_hosts_snapshot()`` to read this set
    # at iteration time so late additions are picked up.
    #
    # Stored as a dict mapping ``hostname`` (lowercased FQDN or short name)
    # to a metadata dict ``{"hostname", "sid", "sam", "name", "sources"}``.
    # ``sources`` is a list of provenance tags (LDAP-mSSMSManagementPoint,
    # HTTP-MPLIST, AdminService-SMS_Site, etc.) so multiple discovery paths
    # contributing the same host don't lose attribution.
    _target_hosts: dict[str, dict[str, Any]] = field(default_factory=dict)
    _target_hosts_lock: Any = field(default=None)
    # Injected by collect_sccm() via source.set_shared_queue() before each
    # pipeline run. None outside the queue loop (unit tests, manual calls).
    target_queue: Any = field(default=None)
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
    # Phase 3a — Cache of hostnames that the RemoteRegistry phase confirmed
    # as site DB hosts (read from the
    # ``SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers`` registry
    # subkey on each reachable site server). The set is populated as a
    # side-effect of the ``registry_sccm_databases`` resource yielding
    # rows, so it is *only* trustworthy after that resource has run. The
    # ``derived_nodes`` resource (which runs later in the source tuple)
    # reads this set to gate the MSSQL_Database / MSSQL_DatabaseRole
    # synthesis when ``--disable-possible-edges`` is set, matching PS1
    # and CMBP-python's rule that those nodes only exist when registry
    # confirms the host.
    _registry_confirmed_db_hosts: Optional[set[str]] = None

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

    # ---- Mutable target-host accumulator (PS1 ``Add-DeviceToTargets`` mirror) ----
    # The per-host probe resources (registry, mssql, wmi, http, smb) iterate
    # ``target_hosts_snapshot()`` instead of ``ldap_computer_hosts()`` so a
    # host registered mid-extract (e.g. an MP discovered by parsing the
    # MPLIST XML response) gets probed by every subsequent phase.

    def _ensure_target_lock(self) -> Any:
        if self._target_hosts_lock is None:
            import threading
            self._target_hosts_lock = threading.Lock()
        return self._target_hosts_lock

    def register_target(
        self,
        hostname: Optional[str],
        *,
        sid: Optional[str] = None,
        sam: Optional[str] = None,
        name: Optional[str] = None,
        source: Optional[str] = None,
    ) -> None:
        """Append ``hostname`` to the per-host probe target set, merging
        provenance when the host is already known.

        Idempotent and thread-safe. Empty hostnames are silently dropped.
        Mirrors PS1's ``Add-DeviceToTargets`` (CallStack from
        ConfigManBearPig.ps1: LDAP-mSSMSManagementPoint, LDAP-CmRcService,
        LDAP-connectionPoint, LDAP-GenericAll, HTTP-MPKEYINFORMATION,
        HTTP-MPLIST, AdminService-SMS_Site, etc. all hit this helper).
        """
        if not hostname:
            return
        key = hostname.strip().lower()
        if not key:
            return
        with self._ensure_target_lock():
            existing = self._target_hosts.get(key)
            if existing is None:
                existing = {
                    "hostname": key,
                    "sid": sid,
                    "sam": sam,
                    "name": name,
                    "sources": [],
                }
                self._target_hosts[key] = existing
                # New host: enqueue in the phase queue so the collect_sccm()
                # outer loop schedules a subsequent pass against it.
                if self.target_queue is not None:
                    self.target_queue.enqueue(key)
            # Don't overwrite an already-known identifier with None.
            if sid and not existing.get("sid"):
                existing["sid"] = sid
            if sam and not existing.get("sam"):
                existing["sam"] = sam
            if name and not existing.get("name"):
                existing["name"] = name
            if source and source not in existing["sources"]:
                existing["sources"].append(source)

    def _seed_targets_from_ldap_computers(self) -> None:
        """Initialise the target accumulator from the LDAP computer snapshot.
        Called the first time ``target_hosts_snapshot()`` is consulted, but
        also safe to call repeatedly — ``register_target`` is idempotent."""
        for h in self.ldap_computer_hosts():
            self.register_target(
                h.get("hostname"),
                sid=h.get("sid"),
                sam=h.get("sam"),
                name=h.get("name"),
                source="LDAP-Computers",
            )

    def target_hosts_snapshot(self) -> list[dict[str, Any]]:
        """Return the *current* list of probe targets at the moment this is
        called. Per-host resources iterate this so late-registered hosts are
        picked up by phases that haven't started yet.

        First call seeds from ``ldap_computer_hosts()``. Returns a shallow
        copy of the list so iteration is safe against concurrent
        ``register_target`` mutations.
        """
        # Cheap unlocked check first; the seed call (and the snapshot copy) take
        # the lock themselves. ``register_target`` is idempotent, so a benign
        # double-seed under a race only does the LDAP enumeration twice, never
        # corrupts state.
        if not self._target_hosts:
            self._seed_targets_from_ldap_computers()
        with self._ensure_target_lock():
            return [dict(v) for v in self._target_hosts.values()]

    # ---- CmRcService SPN match cache ----------------------------------------
    # PS1 (ConfigManBearPig.ps1:3216-3289) does the ``(servicePrincipalName=
    # CmRcService/*)`` LDAP search exactly once in its LDAP once-phase and
    # creates the LDAP-synth SCCM_ClientDevice nodes from the results.
    # OpenHound previously buried this network call inside
    # ``adminservice_client_devices`` (so it ran during the AdminService
    # extract and the log line was mistagged ``[AdminService]``). This
    # cache + the LDAP-phase resource that drives it move the search back
    # to where it belongs.

    def cmrc_spn_matches(self) -> list[dict[str, Any]]:
        """Return the list of LDAP entries carrying a ``CmRcService/*`` SPN.

        Lazy. The actual LDAP search runs the first time this is called.
        Returns ``[]`` when the LDAP collection method is disabled — that
        matches PS1's gate (``-CollectionMethods`` excludes ``LDAP`` →
        no SPN-based ClientDevice synthesis).
        """
        if self._cmrc_spn_matches is not None:
            return self._cmrc_spn_matches
        if not self.method_enabled("LDAP"):
            self._cmrc_spn_matches = []
            return self._cmrc_spn_matches
        with target_context(self.domain or None), phase_context("LDAP"):
            try:
                rows = list(
                    self.ad.paged_search(
                        search_filter="(servicePrincipalName=CmRcService/*)",
                        attributes=[
                            "objectSid", "sAMAccountName", "name", "dNSHostName",
                        ],
                    )
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("ldap CmRcService search failed: %s", exc)
                rows = []
            logger.info(
                "ldap CmRcService: found %d SCCM client computer(s) via SPN",
                len(rows),
            )
        self._cmrc_spn_matches = rows
        return rows

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
                # Register every host the AdminService payload mentions as a
                # probe target. This is the OH-side equivalent of PS1's
                # ``Add-DeviceToTargets`` calls inside its AdminService
                # collector — devices that SCCM knows about but that didn't
                # show up via LDAP-by-name (e.g. cross-forest clients) still
                # get RemoteRegistry / WMI / HTTP / SMB probes.
                for dev in payload.get("client_devices") or []:
                    dns = (dev.get("dns_host_name") or "").lower() or None
                    machine = (dev.get("machine_name") or "").strip() or None
                    self.register_target(
                        dns or machine,
                        sid=dev.get("ad_object_sid") or None,
                        name=machine,
                        source="AdminService-SMS_R_System",
                    )
                for ss in payload.get("site_systems") or []:
                    self.register_target(
                        (ss.get("hostname") or "").strip() or None,
                        source="AdminService-SMS_SCI_SysResUse",
                    )

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

    def note_registry_confirmed_db_host(self, hostname: str) -> None:
        """Mark *hostname* as a site DB host confirmed via RemoteRegistry.

        Called by the ``registry_sccm_databases`` resource for each
        (site_server, db_host) pair it reads out of the registry. The
        ``derived_nodes`` resource later reads
        ``registry_confirmed_db_hosts()`` to gate MSSQL_Database /
        MSSQL_DatabaseRole synthesis on registry confirmation (PS1's
        rule when ``-DisablePossibleEdges`` is set).
        """
        if self._registry_confirmed_db_hosts is None:
            self._registry_confirmed_db_hosts = set()
        if hostname:
            self._registry_confirmed_db_hosts.add(hostname.lower())

    def registry_confirmed_db_hosts(self) -> set[str]:
        """Return lowercased hostnames confirmed as site DB hosts.

        PS1's literal gate is "RemoteRegistry Multisite Component Servers
        subkey is readable", but impacket's WinReg client can't enumerate
        that subkey as low-privileged users (roanalyst, lowpriv) even
        though PowerShell's native registry remoting can. To keep parity
        with PS1's *intent* — "emit the database hierarchy when the host
        is genuinely a site DB" — we treat the AdminService
        ``SMS_SCI_SiteDefinition.SQLServerName`` field as an equivalent
        confirmation signal. AdminService publishes the same configured
        value, just over a different transport, and it's reachable by
        roanalyst where RemoteRegistry is not. Domainadmin still hits the
        registry path first; lowpriv (no AdminService access) still gets
        the empty set, matching PS1.
        """
        confirmed: set[str] = set(self._registry_confirmed_db_hosts or ())
        for payload in (self._adminservice_payloads or {}).values():
            for sd in payload.get("site_definitions") or []:
                sql_server = (sd.get("SQLServerName") or "").strip().lower()
                if sql_server:
                    confirmed.add(sql_server)
        return confirmed

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

        # 5. AdminService discovered hosts. The MSSQL phase needs to see
        # the site DB hosts (CAS-DB, PS1-DB, ...) which are not reachable
        # through any pure-LDAP channel — they only surface through
        # AdminService SMS_SCI_SysResUse / SMS_SCI_SiteDefinition. We
        # eagerly populate the AdminService cache here so the MSSQL probe
        # set is complete on first call. The cache is idempotent: later
        # AdminService resources just reuse it. For lowpriv (no
        # AdminService access) this returns an empty dict.
        admin_payloads = self.adminservice_payloads()
        if admin_payloads:
            try:
                for payload in admin_payloads.values():
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
