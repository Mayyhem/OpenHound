"""DLT source / resources / transformers for the OpenHound SCCM extension.

Each ``@app.resource`` writes one DLT table (named after the resource) into
``output/sccm/<table>/`` as JSONL during the collect phase. Models read those
tables back in convert.

Phase 1 (LDAP thin slice):
    ldap_sites, ldap_computers, ldap_users, ldap_groups,
    ldap_sms_providers, ldap_group_memberships

Phase 2 (Local / DNS / DHCP once-phases):
    local_management_points, local_distribution_points,
    dns_management_points,
    dhcp_pxe_dps

Per-host transformer chains (RemoteRegistry, MSSQL, AdminService, WMI, HTTP, SMB)
are not yet implemented — they will be added in Phase 3, chained off the parent
resources via DLT's pipe operator.

Credentials are read from ``[sources.sccm]`` in ``.dlt/secrets.toml`` or from
the equivalent ``SOURCES__SCCM__*`` environment variables.

Schema notes
------------
Field naming convention: snake_case. Models normalise to camelCase via aliases
when emitting properties so OpenGraph output matches CMBP byte-for-byte.

The ``transforms.py::_build_targets`` SQL union expects these once-phase tables
to expose the host as the ``hostname`` column:
    local_management_points, local_distribution_points,
    dns_management_points, dhcp_pxe_dps
The resources below honour that contract.

LDAP attributes that flow into multiple downstream tables (e.g. computer SIDs that
appear as Computer nodes AND as group members) are collected once and joined in
``transforms.py`` SQL — not duplicated across resources.
"""

from __future__ import annotations

import logging
import os
import platform
import re
import socket
import subprocess
from dataclasses import dataclass
from typing import Any, Iterable, Optional

import dlt

from .clients.ad import ADClient, ADCredentials
from .main import app
from .models import (
    Computer,
    DerivedEdges,
    DerivedNode,
    Group,
    GroupMembership,
    MSSQLDatabase,
    MSSQLDatabaseRole,
    MSSQLDatabaseUser,
    MSSQLLogin,
    MSSQLServer,
    MSSQLServerRole,
    SCCMAdminUser,
    SCCMClientDevice,
    SCCMCollection,
    SCCMSecurityRole,
    SCCMSite,
    User,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Source context — wraps the LDAP client.
# ---------------------------------------------------------------------------

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
    # OpenHound-specific: opt-in authenticated MSSQL TDS introspection. The
    # impacket TDS path can wedge for many minutes against EPA-enforcing
    # servers, so this stays off by default even when `-m MSSQL` is enabled.
    mssql_introspect: bool = False
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
    # Phase 3a — MSSQL authenticated-introspection cache. Each MSSQL host that
    # responds to TDS prelogin is queried once per source run; the seven
    # introspection lists (logins, databases, db users, server roles, db
    # roles, role members, linked servers) are cached and served to the
    # ``mssql_*`` resources without re-running the queries.
    _mssql_introspection: Optional[dict[str, dict[str, list[dict[str, Any]]]]] = None
    # MSSQL hosts to introspect. Populated lazily by ``mssql_introspection``
    # from a TDS prelogin sweep over ``ldap_computer_hosts``.
    _mssql_hosts: Optional[list[str]] = None
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
            logger.info("adminservice_payloads: disabled via --collection-methods")
            self._adminservice_payloads = {}
            return self._adminservice_payloads

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
            try:
                payload = _collect_adminservice_data(host, self.username, self.password)
            except Exception as e:  # noqa: BLE001
                logger.info("adminservice: collection failed for %s: %s", host, e)
                continue
            if payload is None:
                continue
            out[host] = payload

        self._adminservice_payloads = out
        return out

    # ---- MSSQL authenticated-introspection cache ---------------------------

    def mssql_introspection(self) -> dict[str, dict[str, list[dict[str, Any]]]]:
        """Return ``{hostname: payload}`` of authenticated MSSQL queries.

        Each payload is a dict with seven lists keyed by resource name
        (``mssql_logins``, ``mssql_databases``, ``mssql_database_users``,
        ``mssql_server_roles``, ``mssql_database_roles``, ``mssql_role_members``,
        ``mssql_linked_servers``). Hosts that don't respond to TDS prelogin or
        reject auth are skipped.

        **Opt-in.** Disabled by default because impacket's TDS path can wedge
        for many minutes when the SQL server enforces channel-binding tokens
        (the MAYYHEM lab does on PS1-PSV). Set ``ctx.mssql_introspect = True``
        (via ``SOURCES__SCCM__MSSQL_INTROSPECT=true``) AND have ``MSSQL`` in
        ``--collection-methods`` to attempt the sweep.
        """
        if self._mssql_introspection is not None:
            return self._mssql_introspection

        if not self.method_enabled("MSSQL"):
            logger.info("mssql_introspection: disabled (MSSQL not in --collection-methods)")
            self._mssql_introspection = {}
            return self._mssql_introspection

        if not self.mssql_introspect:
            logger.info(
                "mssql_introspection: opt-in (set SOURCES__SCCM__MSSQL_INTROSPECT=true to enable)"
            )
            self._mssql_introspection = {}
            return self._mssql_introspection

        # Without explicit creds we can't authenticate; skip the whole sweep.
        if not (self.username and self.password):
            logger.info("mssql_introspection: no explicit creds; skipping authenticated introspection")
            self._mssql_introspection = {}
            return self._mssql_introspection

        out: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for host in self.ldap_computer_hosts():
            hostname = host.get("hostname")
            if not hostname:
                continue
            # Only attempt auth on hosts that already responded to a TDS
            # prelogin probe. The probe is cheap (~2s timeout) and avoids
            # expensive Kerberos/NTLM negotiations against dead hosts.
            epa = _probe_mssql_epa(hostname, 1433)
            if not epa:
                continue
            try:
                payload = _collect_mssql_introspection(hostname, self.domain, self.username, self.password, 1433)
            except Exception as exc:  # noqa: BLE001
                logger.info("mssql_introspection: collection failed for %s: %s", hostname, exc)
                continue
            if payload is None:
                continue
            out[hostname] = payload

        self._mssql_introspection = out
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
        result = _smb_list_shares(hostname, self.domain, self.username, self.password)
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
            (only available when AdminService is reachable; for low-priv
            this is empty and that's fine — matches CMBP)

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

        # 1. SMS Provider hostnames (sAMAccountName ends in -pss / -sms)
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
                search_base=self.system_management_dn,
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

        # 5. AdminService discovered hosts (only if AdminService is reachable).
        try:
            for payload in self.adminservice_payloads().values():
                # SMS_SCI_SysResUse: per-site role hosts (Site Server, SMS
                # Provider, MP, DP, Reporting SP, etc.)
                for ss in payload.get("site_systems", []) or []:
                    _add("AdminService", ss.get("hostname"))
                # SMS_SCI_SiteDefinition surfaces ``SQLServerName`` (the DB
                # host for each primary). CMBP adds these as targets via
                # ``add_device(sql_server, source="AdminService-SMS_SCI_SiteDefinition")``
                # so we need to recognise them as SCCM-discovered.
                for sd in payload.get("site_definitions", []) or []:
                    _add("AdminService", sd.get("SQLServerName"))
                # SMS_Site SiteServerName (the primary site server).
                for site in payload.get("sites", []) or []:
                    _add("AdminService", site.get("SiteServerName"))
        except Exception as e:  # noqa: BLE001
            logger.warning("sccm_discovered_hosts: AdminService failed: %s", e)

        self._sccm_discovered_hosts = out
        total = len({h for h in out if "." in h})
        per_channel = ", ".join(f"{k}={v}" for k, v in channel_counts.items())
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


# ---------------------------------------------------------------------------
# LDAP resources (Phase 1 thin slice)
# ---------------------------------------------------------------------------

_COMPUTER_ATTRS = [
    "objectSid",
    "objectGUID",
    "sAMAccountName",
    "name",
    "distinguishedName",
    "dNSHostName",
    "operatingSystem",
    "operatingSystemVersion",
    "userAccountControl",
    "servicePrincipalName",
    "memberOf",
    "primaryGroupID",
]


@app.resource(name="ldap_computers", parallelized=False, columns=Computer)
def ldap_computers(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """All computer accounts in the domain (one row per AD computer)."""
    for entry in ctx.ad.paged_search(
        search_filter="(&(objectCategory=computer)(objectClass=computer))",
        attributes=_COMPUTER_ATTRS,
    ):
        yield _normalize_computer(entry, ctx.domain)


_USER_ATTRS = [
    "objectSid",
    "objectGUID",
    "sAMAccountName",
    "userPrincipalName",
    "name",
    "displayName",
    "distinguishedName",
    "userAccountControl",
    "memberOf",
    "primaryGroupID",
    "servicePrincipalName",
]


@app.resource(name="ldap_users", parallelized=False, columns=User)
def ldap_users(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """All user accounts in the domain (one row per AD user)."""
    for entry in ctx.ad.paged_search(
        search_filter="(&(objectCategory=person)(objectClass=user)(!(objectClass=computer)))",
        attributes=_USER_ATTRS,
    ):
        yield _normalize_user(entry, ctx.domain)


_GROUP_ATTRS = [
    "objectSid",
    "objectGUID",
    "sAMAccountName",
    "name",
    "distinguishedName",
    "groupType",
    "member",
]


@app.resource(name="ldap_groups", parallelized=False, columns=Group)
def ldap_groups(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """All groups in the domain (one row per AD group).

    Also synthesises a row for the well-known Authenticated Users
    pseudo-group (``S-1-5-11``). LDAP doesn't expose it as a regular
    ``group`` object but every CoerceAndRelay edge in the SCCM model
    starts from it, so a Group node has to exist for the edges to be
    valid in the BloodHound graph. CMBP synthesises this node too.
    """
    for entry in ctx.ad.paged_search(
        search_filter="(objectClass=group)",
        attributes=_GROUP_ATTRS,
    ):
        yield _normalize_group(entry, ctx.domain)

    domain_upper = (ctx.domain or "").upper()
    if domain_upper:
        yield {
            "object_sid": f"{domain_upper}-S-1-5-11",
            "object_guid": None,
            "sam_account_name": "Authenticated Users",
            "name": "Authenticated Users",
            "distinguished_name": None,
            "group_type": None,
            "member": [],
            "domain": ctx.domain,
        }


@app.resource(name="ldap_group_memberships", parallelized=False, columns=GroupMembership)
def ldap_group_memberships(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """One row per (group, member-DN) pair.

    Re-runs the same LDAP search as ``ldap_groups`` (groups are small relative to
    the AD index; the second pass costs ~30ms in the test domain) and emits a flat
    membership row for each ``member`` value. Originally written as a DLT
    transformer chained off ``ldap_groups`` but DLT's pipe operator wasn't
    producing a separate destination table for the chained output here, so we
    implement the membership table as a top-level resource. The cost is one extra
    paged search; the benefit is a guaranteed-separate JSONL the convert phase can
    read.
    """
    for entry in ctx.ad.paged_search(
        search_filter="(objectClass=group)",
        attributes=_GROUP_ATTRS,
    ):
        members = entry.get("member") or []
        if isinstance(members, str):
            members = [members]
        group_sid = entry.get("object_sid") or ""
        group_name = entry.get("sAMAccountName") or entry.get("name") or ""
        for member_dn in members:
            if not isinstance(member_dn, str) or not member_dn:
                continue
            yield {
                "group_sid": group_sid,
                "group_name": group_name,
                "member_dn": member_dn,
            }


_SITE_ATTRS = [
    "mSSMSSiteCode",
    "mSSMSHealthState",
    "mSSMSSourceForest",
    "objectClass",
    "distinguishedName",
    "name",
]


@app.resource(name="ldap_sites", parallelized=False, columns=SCCMSite)
def ldap_sites(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """SCCM sites discovered via mSSMSSite objects in the System Management container.

    Also folds in any sites returned by ``wmi/SMS_Site`` from the AdminService
    payload — CMBP creates a SCCM_Site per row from both ``ldap_sites`` AND
    SMS_Site (e.g. a Secondary site that is hierarchy-discovered via the
    SMS Provider but not registered in the System Management container).
    """
    seen_codes: set[str] = set()
    try:
        for entry in ctx.ad.paged_search(
            search_filter="(objectClass=mSSMSSite)",
            base=ctx.system_management_dn,
            attributes=_SITE_ATTRS,
        ):
            site_code = (entry.get("mSSMSSiteCode") or "").strip()
            if not site_code:
                continue
            site_guid = None
            health = entry.get("mSSMSHealthState")
            if health:
                m = re.search(rf"{re.escape(site_code)}\.(\{{[^}}]+\}})", str(health))
                if m:
                    site_guid = m.group(1)
            seen_codes.add(site_code.upper())
            yield {
                "site_code": site_code,
                "site_guid": site_guid,
                "distinguished_name": entry.get("distinguishedName"),
                "source_forest": entry.get("mSSMSSourceForest"),
                "site_type": None,        # determined in transforms via parent_site_code recursion
                "parent_site_code": None,  # populated by AdminService in Phase 3
            }
    except Exception as e:
        logger.warning("ldap_sites resource failed: %s", e)

    # Fold in AdminService-discovered sites (SMS_Site + SMS_SCI_SiteDefinition).
    # This closes the gap where a Secondary site is registered with the SMS
    # Provider but doesn't have an mSSMSSite object in the System Management
    # container (low-priv users can't enumerate the container, full-access
    # users sometimes lack the second hierarchy level there).
    try:
        for _host, payload in ctx.adminservice_payloads().items():
            sites = payload.get("sites") or []
            for entry in sites:
                site_code = (entry.get("SiteCode") or "").strip()
                if not site_code or site_code.upper() in seen_codes:
                    continue
                seen_codes.add(site_code.upper())
                site_type_num = entry.get("Type")
                # SMS_Site Type field: 1=Secondary, 2=Primary, 4=CAS
                if site_type_num == 1:
                    site_type_str = "Secondary"
                elif site_type_num == 2:
                    site_type_str = "Primary"
                elif site_type_num == 4:
                    site_type_str = "CAS"
                else:
                    site_type_str = None
                parent = (entry.get("ReportingSiteCode") or "").strip() or None
                if parent and parent == site_code:
                    parent = None
                yield {
                    "site_code": site_code,
                    "site_guid": None,
                    "distinguished_name": None,
                    "source_forest": None,
                    "site_type": site_type_str,
                    "parent_site_code": parent,
                }
    except Exception as e:
        logger.warning("ldap_sites adminservice fold-in failed: %s", e)

    # mSSMSManagementPoint fold-in: each Site (CAS, Primary, Secondary) has a
    # corresponding MP record under the System Management container, and the
    # MP's ``mSSMSCapabilities`` XML lets us classify the site even when the
    # mSSMSSite object isn't readable / present (Secondary sites in
    # particular often only surface via their MP). CMBP's
    # ``_collect_management_points`` runs this same parse to derive
    # siteType + parentSiteCode for SMB-only-discovered hierarchies.
    # Site classification details are emitted separately via the
    # ``ldap_mp_site_classifications`` resource so the transforms can
    # consume them; here we only need to ensure a SCCM_Site node fires
    # for any site discovered via its MP.
    try:
        for entry in ctx.ad.paged_search(
            search_filter="(objectClass=mSSMSManagementPoint)",
            base=ctx.system_management_dn,
            attributes=["mSSMSSiteCode"],
        ):
            mp_site_code = (entry.get("mSSMSSiteCode") or "").strip()
            if not mp_site_code:
                continue
            if mp_site_code.upper() in seen_codes:
                continue
            seen_codes.add(mp_site_code.upper())
            yield {
                "site_code": mp_site_code,
                "site_guid": None,
                "distinguished_name": None,
                "source_forest": None,
                "site_type": None,
                "parent_site_code": None,
            }
    except Exception as e:
        logger.warning("ldap_sites mp fold-in failed: %s", e)

    # SMB fold-in: a Secondary site server is sometimes only discoverable
    # via SMB share enumeration (no mSSMSSite object in the System
    # Management container, no AdminService access for the calling user).
    # CMBP emits a SCCM_Site node for these too; without one, low-priv
    # SCCM_AdminsReplicatedTo edges that point at the Secondary have no
    # endpoint. We share the SMB-share results with smb_site_servers /
    # smb_distribution_points via ``ctx.smb_shares()`` so this loop pays
    # zero extra SMB cost when the smb_* resources are also enabled
    # (they always are unless SMB is removed from --collection-methods,
    # in which case this branch is also skipped to keep behaviour consistent).
    #
    # Gating: we only fold in SCCM_Sites for hosts that are *also* in
    # ``ctx.sccm_discovered_hosts()`` — i.e. hosts CMBP would have
    # SMB-probed via its target list. Without this gate, OH iterates
    # every domain computer; CMBP only iterates its discovered targets.
    # For low-priv users that means OH would surface SEC (via ps1-sec's
    # SMS_SITE share) where CMBP wouldn't, since ps1-sec isn't in
    # CMBP's lowpriv target list.
    if ctx.method_enabled("SMB"):
        discovered = ctx.sccm_discovered_hosts()
        try:
            for host in ctx.ldap_computer_hosts():
                hostname = host.get("hostname")
                if not hostname:
                    continue
                host_low = hostname.lower()
                host_short = host_low.split(".", 1)[0]
                if host_low not in discovered and host_short not in discovered:
                    continue
                shares = ctx.smb_shares(hostname)
                if not shares:
                    continue
                discovered_code: Optional[str] = None
                for s in shares:
                    name = s.get("name") or ""
                    comment = s.get("comment") or ""
                    m = re.match(r"^SMS_(\w{3})$", name)
                    if name == "SMS_SITE" or m:
                        cm = re.search(r"SMS Site (\w{3})", comment)
                        if cm:
                            discovered_code = cm.group(1)
                            break
                        elif m:
                            discovered_code = m.group(1)
                            break
                    cm = re.search(r"SMS Site (\w{3})", comment)
                    if cm and (name == "SMS_DP$" or name == "SCCMContentLib$" or name == "REMINST"):
                        discovered_code = cm.group(1)
                        break
                if not discovered_code:
                    continue
                if discovered_code.upper() in seen_codes:
                    continue
                seen_codes.add(discovered_code.upper())
                yield {
                    "site_code": discovered_code,
                    "site_guid": None,
                    "distinguished_name": None,
                    "source_forest": None,
                    "site_type": None,
                    "parent_site_code": None,
                }
        except Exception as e:
            logger.warning("ldap_sites smb fold-in failed: %s", e)


@app.resource(name="ldap_mp_site_classifications", parallelized=False)
def ldap_mp_site_classifications(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """Per-site (siteType, parent_site_code) classification derived from
    each ``mSSMSManagementPoint`` object's ``mSSMSCapabilities`` XML.

    Mirrors CMBP's ``ldap_collector::_collect_management_points`` parse:

      * commandLineSiteCode == mp_site_code AND rootSiteCode != mp -> Primary, parent=root
      * rootSiteCode == mp_site_code AND commandLine != mp         -> CAS, parent=None
      * (default)                                                  -> Secondary,
            parent = rootSiteCode (which is the parent Primary), or
                     commandLineSiteCode if rootSiteCode is missing

    The transforms read this table at preproc to set ``site_types`` even
    when AdminService is unavailable (low-priv users), closing the
    ``SCCM_AdminsReplicatedTo`` gap for Secondary sites.
    """
    try:
        import xml.etree.ElementTree as ET
        for entry in ctx.ad.paged_search(
            search_filter="(objectClass=mSSMSManagementPoint)",
            base=ctx.system_management_dn,
            attributes=["mSSMSSiteCode", "mSSMSCapabilities", "mSSMSMPName"],
        ):
            mp_site_code = (entry.get("mSSMSSiteCode") or "").strip()
            if not mp_site_code:
                continue
            mp_code_upper = mp_site_code.upper()
            capabilities_str = entry.get("mSSMSCapabilities")
            command_line_site_code: Optional[str] = None
            root_site_code: Optional[str] = None
            if capabilities_str:
                try:
                    clean_xml = re.sub(
                        r"&(?!amp;|lt;|gt;|quot;|apos;)", "&amp;", str(capabilities_str)
                    )
                    root = ET.fromstring(clean_xml)
                    ccm = root.find(".//CCM")
                    if ccm is not None:
                        cmd = ccm.get("CommandLine", "") or ""
                        if not cmd:
                            cl_elem = ccm.find("CommandLine")
                            cmd = (cl_elem.text or "") if cl_elem is not None else (ccm.text or "")
                        cmd_match = re.search(r"SMSSITECODE=([A-Z0-9]{3})", cmd, re.IGNORECASE)
                        if cmd_match:
                            command_line_site_code = cmd_match.group(1).upper()
                    rs = root.find("RootSiteCode")
                    if rs is None:
                        rs = root.find(".//RootSiteCode")
                    if rs is not None and rs.text:
                        root_site_code = rs.text.strip().upper()
                except Exception as parse_err:
                    logger.debug(
                        "mSSMSCapabilities parse failed for %s: %s", mp_site_code, parse_err
                    )

            site_type: str
            parent: Optional[str] = None
            if command_line_site_code == mp_code_upper:
                site_type = "Primary"
                if root_site_code and root_site_code != mp_code_upper:
                    parent = root_site_code
            elif root_site_code == mp_code_upper and command_line_site_code != mp_code_upper:
                site_type = "CAS"
            else:
                site_type = "Secondary"
                if root_site_code and root_site_code != mp_code_upper:
                    parent = root_site_code
                elif command_line_site_code and command_line_site_code != mp_code_upper:
                    parent = command_line_site_code

            yield {
                "site_code": mp_site_code,
                "site_type": site_type,
                "parent_site_code": parent,
                "command_line_site_code": command_line_site_code,
                "root_site_code": root_site_code,
            }
    except Exception as e:
        logger.warning("ldap_mp_site_classifications resource failed: %s", e)


@app.resource(name="ldap_sms_providers", parallelized=False)
def ldap_sms_providers(ctx: SourceContext) -> Iterable[dict[str, Any]]:
    """Computers that host the SMS Provider role (lookup table — no node emitted).

    Discovered via the ``intellimirrorSCP`` and ``connectionPoint`` SPN patterns plus
    the ``ServiceConnectionPoint`` objectClass under each SCCM site DN. Phase 1 emits
    rows from a simple sAMAccountName naming pattern (``*-sms``, ``*-pss``); Phase 3
    enriches via the AdminService discovery.

    Intentionally has no ``columns=`` (i.e. no Pydantic validator/asset). If the
    Computer asset were attached, the convert phase would map ``Computer`` to this
    table instead of ``ldap_computers`` (DLT framework limitation: one asset class
    maps to exactly one source table). The SMS-provider rows already appear in
    ``ldap_computers`` via the broader LDAP query; this resource only feeds
    ``transforms.py`` (``assign_all_permissions_edges`` etc).
    """
    seen_sids: set[str] = set()
    for entry in ctx.ad.paged_search(
        search_filter="(&(objectCategory=computer)(|(samAccountName=*-pss$)(samAccountName=*-sms$)))",
        attributes=_COMPUTER_ATTRS,
    ):
        sid = entry.get("object_sid")
        if not sid or sid in seen_sids:
            continue
        seen_sids.add(sid)
        yield _normalize_computer(entry, ctx.domain, source_tag="LDAP-SMSProvider")


# ---------------------------------------------------------------------------
# Normalisers — flatten ldap3-shaped dicts into the schema expected by models.
# ---------------------------------------------------------------------------

def _list_or_none(value) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, list):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def _account_disabled(uac: Any) -> bool | None:
    if uac is None:
        return None
    try:
        return bool(int(uac) & 0x2)
    except (TypeError, ValueError):
        return None


def _normalize_computer(entry: dict[str, Any], domain: str, *, source_tag: str = "LDAP") -> dict[str, Any]:
    sam = entry.get("sAMAccountName") or ""
    return {
        "object_sid": entry.get("object_sid") or "",
        "object_guid": entry.get("object_guid"),
        "sam_account_name": sam,
        "name": entry.get("name") or sam.rstrip("$"),
        "distinguished_name": entry.get("distinguishedName"),
        "dns_host_name": (entry.get("dNSHostName") or "").lower() or None,
        "operating_system": entry.get("operatingSystem"),
        "operating_system_version": entry.get("operatingSystemVersion"),
        "enabled": (False if _account_disabled(entry.get("userAccountControl")) else True),
        "service_principal_names": _list_or_none(entry.get("servicePrincipalName")),
        "member_of_dns": _list_or_none(entry.get("memberOf")),
        "primary_group_id": entry.get("primaryGroupID"),
        "source": source_tag,
        "domain": domain,
    }


def _normalize_user(entry: dict[str, Any], domain: str) -> dict[str, Any]:
    sam = entry.get("sAMAccountName") or ""
    return {
        "object_sid": entry.get("object_sid") or "",
        "object_guid": entry.get("object_guid"),
        "sam_account_name": sam,
        "user_principal_name": entry.get("userPrincipalName"),
        "name": entry.get("name") or sam,
        "display_name": entry.get("displayName"),
        "distinguished_name": entry.get("distinguishedName"),
        "enabled": (False if _account_disabled(entry.get("userAccountControl")) else True),
        "member_of_dns": _list_or_none(entry.get("memberOf")),
        "primary_group_id": entry.get("primaryGroupID"),
        "service_principal_names": _list_or_none(entry.get("servicePrincipalName")),
        "domain": domain,
    }


def _normalize_group(entry: dict[str, Any], domain: str) -> dict[str, Any]:
    sam = entry.get("sAMAccountName") or ""
    return {
        "object_sid": entry.get("object_sid") or "",
        "object_guid": entry.get("object_guid"),
        "sam_account_name": sam,
        "name": entry.get("name") or sam,
        "distinguished_name": entry.get("distinguishedName"),
        "group_type": entry.get("groupType"),
        "member": _list_or_none(entry.get("member")) or [],
        "domain": domain,
    }


# ---------------------------------------------------------------------------
# Phase 2 once-phase resources: Local, DNS, DHCP
# ---------------------------------------------------------------------------
# These resources extend Computer-node properties via the ``sccm.targets`` SQL
# union in ``transforms.py``. They do NOT introduce new node kinds. Each row
# uses ``hostname`` as the host column (matching ``_build_targets``'s contract)
# plus a small fixed set of provenance fields. CRED-4 CIM-repository scraping
# from CMBP's ``local_collector.py`` is intentionally NOT ported — those are
# secret-emitting paths that belong to Phase 4 post-processing.


def _normalize_host(value: Any) -> Optional[str]:
    if not value:
        return None
    text = str(value).strip().lower()
    return text or None


# ---- Local collector ------------------------------------------------------

@app.resource(name="local_management_points", parallelized=False)
def local_management_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield rows for management points discovered locally on the collector host.

    On Windows, reads the SCCM client registry (``HKLM\\SOFTWARE\\Microsoft\\SMS``)
    to pull the assigned site code and the management point hostnames the local
    client knows about. On non-Windows or with no SCCM client installed, yields
    nothing — this is the expected case for an LDAP-only domainadmin run.

    CMBP reference: ``lib/collectors/local_collector.py::_check_sccm_registry``.
    The CRED-4 CIM-repository scraping from the same module is *not* ported
    here — that path emits SCCM_Secret nodes which are a Phase 4 concern.
    """
    if not ctx.method_enabled("Local"):
        return
    if platform.system() != "Windows":
        logger.debug("local_management_points: not on Windows, yielding 0 rows")
        return

    ccm_dir = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "CCM")
    if not os.path.isdir(ccm_dir):
        logger.debug("local_management_points: no CCM directory at %s, yielding 0 rows", ccm_dir)
        return

    try:
        import winreg  # type: ignore[import-not-found]
    except ImportError:
        logger.debug("local_management_points: winreg unavailable on this platform")
        return

    site_code: Optional[str] = None
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\SMS\Mobile Client",
        ) as key:
            site_code, _ = winreg.QueryValueEx(key, "AssignedSiteCode")
    except (FileNotFoundError, OSError) as e:
        logger.debug("local_management_points: AssignedSiteCode read failed: %s", e)

    if not site_code:
        # Without a site code we can't enumerate Sites\SMS:<site>; nothing to yield
        return

    # The site server (assigned MP) hostname comes from
    # HKLM\SOFTWARE\Microsoft\SMS\Client\Sites\SMS:<site>
    mp_host: Optional[str] = None
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\SMS\Client\Sites",
        ) as key:
            mp_host, _ = winreg.QueryValueEx(key, f"SMS:{site_code}")
    except (FileNotFoundError, OSError) as e:
        logger.debug("local_management_points: SMS:%s read failed: %s", site_code, e)

    host = _normalize_host(mp_host)
    if not host:
        return

    yield {
        "hostname": host,
        "mp_url": f"http://{host}",
        "site_code": site_code,
        "source": "Local-Registry",
        "domain": ctx.domain,
    }


@app.resource(name="local_distribution_points", parallelized=False)
def local_distribution_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield rows for distribution points discovered via local SCCM client log scrape.

    SCCM client logs (``CCM\\Logs\\*.log``, ``CCMSetup\\Logs\\*.log``) frequently
    reference DP UNC and HTTP endpoints. Phase 1 already feeds Computer nodes from
    LDAP for any DP that's an AD computer; this resource just contributes provenance
    rows so ``sccm.targets`` records the discovery as ``Local-DP``.

    CMBP reference: ``lib/collectors/local_collector.py::_parse_sccm_logs``.
    """
    if not ctx.method_enabled("Local"):
        return
    if platform.system() != "Windows":
        return

    system_root = os.environ.get("SystemRoot", "C:\\Windows")
    log_dirs = [
        os.path.join(system_root, "CCM", "Logs"),
        os.path.join(system_root, "CCMSetup", "Logs"),
    ]
    smscfg = os.path.join(system_root, "SMSCFG.ini")

    url_pattern = re.compile(r"https?://([a-zA-Z0-9\-\.]+(?:\.\w+)+)", re.IGNORECASE)
    unc_pattern = re.compile(r"\\\\([a-zA-Z0-9\-\.]+(?:\.\w+)+)\\", re.IGNORECASE)

    discovered: set[str] = set()
    domain_lower = ctx.domain.lower() if ctx.domain else ""

    def _parse(path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    for m in url_pattern.finditer(line):
                        discovered.add(m.group(1).lower())
                    for m in unc_pattern.finditer(line):
                        discovered.add(m.group(1).lower())
        except (PermissionError, OSError):
            pass

    for log_dir in log_dirs:
        if os.path.isdir(log_dir):
            try:
                for filename in os.listdir(log_dir):
                    if filename.endswith(".log"):
                        _parse(os.path.join(log_dir, filename))
            except PermissionError:
                continue
    if os.path.isfile(smscfg):
        _parse(smscfg)

    for host in sorted(discovered):
        # Only emit hosts that look like they belong to our domain — others are
        # internet endpoints and noise.
        if domain_lower and not host.endswith(f".{domain_lower}"):
            continue
        yield {
            "hostname": host,
            "source": "Local-LogParsing",
            "domain": ctx.domain,
        }


# ---- DNS collector --------------------------------------------------------

@app.resource(name="dns_management_points", parallelized=False)
def dns_management_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield rows for management points discovered via SRV records.

    For each known site code, queries ``_mssms_mp_<sitecode>._tcp.<domain>``.
    Site codes come from the LDAP-discovered ``mSSMSSite`` objects (re-ran here
    against the same AD client; cheap) plus anything passed via
    ``-sc / --site-codes``. If neither LDAP nor the CLI flag yields a code,
    the resource skips — there is no hardcoded fallback list (it used to mirror
    CMBP's ``CAS/PS1/PS2/SEC/SS1`` greenfield guesses, which produced misleading
    SRV traffic against environments that have no SCCM deployment at all).

    CMBP reference: ``lib/collectors/dns_collector.py``.
    """
    if not ctx.method_enabled("DNS"):
        return
    try:
        import dns.exception
        import dns.resolver
        has_dnspython = True
    except ImportError:
        logger.warning("dns_management_points: dnspython not installed; skipping SRV probe")
        has_dnspython = False

    # Discover site codes from LDAP (re-using the existing AD client). The
    # ldap_sites resource already runs in this same source, but resources don't
    # share state at collect time, so we re-query — it's a tiny lookup.
    site_codes: set[str] = set()
    try:
        for entry in ctx.ad.paged_search(
            search_filter="(objectClass=mSSMSSite)",
            base=ctx.system_management_dn,
            attributes=["mSSMSSiteCode"],
        ):
            sc = (entry.get("mSSMSSiteCode") or "").strip()
            if sc:
                site_codes.add(sc)
    except Exception as e:  # noqa: BLE001
        logger.debug("dns_management_points: LDAP site enumeration failed: %s", e)

    # CMBP `-sc / --site-codes` augments / overrides the auto-discovered set.
    # Accepts a CSV value OR a path to a file with one site code per line.
    if ctx.site_codes:
        cli_codes: set[str] = set()
        sc_val = ctx.site_codes.strip()
        if sc_val:
            try:
                from pathlib import Path as _Path
                p = _Path(sc_val)
                if p.exists() and p.is_file():
                    for line in p.read_text(encoding="utf-8").splitlines():
                        code = line.split("#", 1)[0].strip()
                        if code:
                            cli_codes.add(code.upper())
                else:
                    cli_codes.update(c.strip().upper() for c in sc_val.split(",") if c.strip())
            except OSError as exc:
                logger.warning("dns_management_points: --site-codes %s unreadable: %s", sc_val, exc)
        if cli_codes:
            logger.info("dns_management_points: using user-supplied site codes %s", sorted(cli_codes))
            site_codes = cli_codes

    if not site_codes:
        logger.warning(
            "dns_management_points: no site codes available "
            "(LDAP mSSMSSite search under %s returned 0; --site-codes / "
            "SOURCES__SCCM__SITE_CODES not set) — skipping DNS SRV probe. "
            "Pass --site-codes PS1,CAS,... to probe specific codes.",
            ctx.system_management_dn,
        )
        return

    if has_dnspython:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        if ctx.ad.creds.domain_controller:
            resolver.nameservers = [_resolve_v4(ctx.ad.creds.domain_controller) or ctx.ad.creds.domain_controller]

        for site_code in sorted(site_codes):
            srv_name = f"_mssms_mp_{site_code.lower()}._tcp.{ctx.domain}"
            try:
                answers = resolver.resolve(srv_name, "SRV")
            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.exception.Timeout,
            ) as e:
                logger.debug("dns_management_points: %s -> %s", srv_name, e.__class__.__name__)
                continue
            except Exception as e:  # noqa: BLE001
                logger.debug("dns_management_points: %s failed: %s", srv_name, e)
                continue

            for rdata in answers:
                target_host = _normalize_host(str(rdata.target).rstrip("."))
                if not target_host:
                    continue
                yield {
                    "hostname": target_host,
                    "site_code": site_code,
                    "port": getattr(rdata, "port", None),
                    "srv_name": srv_name,
                    "source": f"DNS-SRV-{site_code}",
                    "domain": ctx.domain,
                }
    else:
        # ADIDNS fallback via LDAP — searches dnsNode objects under MicrosoftDNS.
        # We just discover names; full record parsing is left for a richer
        # phase. Nothing emitted unless real records exist.
        for site_code in sorted(site_codes):
            search_filter = f"(&(objectClass=dnsNode)(name=_mssms_mp_{site_code.lower()}*))"
            base = f"DC={ctx.domain},CN=MicrosoftDNS,DC=DomainDnsZones,{ctx.ad.base_dn}"
            try:
                for entry in ctx.ad.paged_search(
                    search_filter=search_filter,
                    base=base,
                    attributes=["name"],
                ):
                    name = entry.get("name")
                    host = _normalize_host(name)
                    if host:
                        yield {
                            "hostname": host,
                            "site_code": site_code,
                            "port": None,
                            "srv_name": None,
                            "source": f"DNS-ADIDNS-{site_code}",
                            "domain": ctx.domain,
                        }
            except Exception as e:  # noqa: BLE001
                logger.debug("dns_management_points: ADIDNS for %s failed: %s", site_code, e)


def _resolve_v4(host: str) -> Optional[str]:
    """Resolve a hostname to its first IPv4 address, or None."""
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET)
        if infos:
            return infos[0][4][0]
    except (socket.gaierror, OSError):
        pass
    return None


# ---- DHCP collector -------------------------------------------------------

@app.resource(name="dhcp_pxe_dps", parallelized=False)
def dhcp_pxe_dps(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield rows for PXE-enabled distribution points discovered via DHCP.

    Sends a single DHCPINFORM with vendor class ``PXEClient`` to
    ``255.255.255.255:4011`` and parses any responses. Each PXE-capable
    response yields a row with the resolved hostname, the next-server IP, and
    boot-file metadata. Skipped silently if:
      - we don't have UDP broadcast permission, or
      - no SCCM PXE infrastructure responds within the 6s timeout window.

    CMBP reference: ``lib/collectors/dhcp_collector.py``. The TFTP-based
    media-variable-file fetch + decryption (CRED-1) is *not* ported here —
    that's Phase 4 secret-policy material. We only do the discovery probe.
    SOCKS5 mode is also deferred.
    """
    import random
    import struct
    import time

    if not ctx.method_enabled("DHCP"):
        return

    if not _have_udp_broadcast_priv():
        logger.info("dhcp_pxe_dps: no UDP broadcast permission; skipping (run elevated for PXE discovery)")
        return

    mac = _get_local_mac()
    packet = _build_dhcp_inform_packet(mac)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind(("0.0.0.0", 0))
        except OSError as e:
            logger.debug("dhcp_pxe_dps: bind failed (%s); continuing on ephemeral port", e)
        logger.info("dhcp_pxe_dps: sending DHCPINFORM (%d bytes) -> 255.255.255.255:4011", len(packet))
        sock.sendto(packet, ("255.255.255.255", 4011))
    except (PermissionError, OSError) as e:
        logger.info("dhcp_pxe_dps: DHCPINFORM send failed: %s", e)
        return

    # Collect responses for ~6s
    deadline = time.monotonic() + 6.0
    sock.settimeout(min(6.0, max(0.1, deadline - time.monotonic())))
    seen_servers: set[str] = set()
    try:
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            except OSError:
                break

            sender_ip = addr[0]
            if sender_ip in seen_servers:
                continue

            parsed = _parse_dhcp_response(data)
            if parsed is None:
                continue
            if not _is_pxe_response(parsed):
                continue

            seen_servers.add(sender_ip)
            hint_ip = parsed.get("tftp_server") or (parsed.get("siaddr") if parsed.get("siaddr") not in (None, "0.0.0.0") else sender_ip)
            host = _resolve_ip_to_hostname(hint_ip) or hint_ip
            host_norm = _normalize_host(host)
            if not host_norm:
                continue

            yield {
                "hostname": host_norm,
                "pxe_next_server": parsed.get("siaddr"),
                "pxe_boot_file": parsed.get("boot_file_option") or parsed.get("boot_file"),
                "pxe_tftp_server": parsed.get("tftp_server"),
                "pxe_vendor_class": parsed.get("vendor_class"),
                "source": "DHCP-PXE",
                "domain": ctx.domain,
            }

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            sock.settimeout(remaining)
    finally:
        try:
            sock.close()
        except Exception:
            pass


# ---- DHCP helpers (subset of CMBP dhcp_collector) -------------------------

def _have_udp_broadcast_priv() -> bool:
    """Best-effort check that this process can send a UDP broadcast.

    On Windows, sending broadcast generally works without elevation. On Linux,
    raw UDP broadcast typically requires root or CAP_NET_RAW.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:  # type: ignore[attr-defined]
        return True
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.sendto(b"\x00", ("255.255.255.255", 0))
        s.close()
        return True
    except (PermissionError, OSError):
        return False


def _get_local_mac() -> bytes:
    """Return the first non-loopback active interface's MAC address.

    On Linux: reads /sys/class/net. On Windows: enumerates via uuid.getnode()
    fallback. Returns 6 zero bytes if none found.
    """
    # Linux fast path
    net_dir = "/sys/class/net"
    if os.path.isdir(net_dir):
        try:
            for iface in sorted(os.listdir(net_dir)):
                if iface == "lo":
                    continue
                operstate_path = os.path.join(net_dir, iface, "operstate")
                addr_path = os.path.join(net_dir, iface, "address")
                try:
                    with open(operstate_path) as f:
                        if f.read().strip() != "up":
                            continue
                    with open(addr_path) as f:
                        mac_str = f.read().strip()
                        if mac_str and mac_str != "00:00:00:00:00:00":
                            parts = mac_str.split(":")
                            if len(parts) == 6:
                                return bytes(int(p, 16) for p in parts)
                except (IOError, OSError, ValueError):
                    continue
        except OSError:
            pass

    # Windows / generic fallback via uuid.getnode()
    import uuid
    try:
        node = uuid.getnode()
        # If getnode() returned a randomly-generated locally-administered MAC,
        # the 41st bit is set (RFC 4122). Still usable for our purposes.
        return node.to_bytes(6, "big")
    except Exception:
        pass

    logger.warning("dhcp_pxe_dps: could not detect MAC address, using zeros")
    return b"\x00" * 6


def _build_dhcp_inform_packet(mac: bytes) -> bytes:
    """Build a DHCPINFORM packet for PXE proxy discovery (port 4011).

    Options: 53=INFORM(8), 60="PXEClient", 55=[60,66,67], 255=end.
    """
    import random
    import struct

    xid = random.randbytes(4)

    header = bytearray(236)
    header[0] = 0x01   # op: BOOTREQUEST
    header[1] = 0x01   # htype: Ethernet
    header[2] = 0x06   # hlen
    header[3] = 0x00   # hops
    header[4:8] = xid
    header[10] = 0x80  # flags: broadcast
    header[28 : 28 + len(mac)] = mac

    options = bytearray(b"\x63\x82\x53\x63")
    options.extend(b"\x35\x01\x08")  # 53: INFORM (8)
    vendor = b"PXEClient"
    options.extend(bytes([60, len(vendor)]) + vendor)
    options.extend(b"\x37\x03\x3c\x42\x43")  # 55: [60, 66, 67]
    options.append(0xFF)  # end

    return bytes(header) + bytes(options)


def _parse_dhcp_response(data: bytes) -> Optional[dict[str, Any]]:
    """Parse a DHCP response packet enough to identify a PXE responder."""
    if len(data) < 240:
        return None
    if data[236:240] != b"\x63\x82\x53\x63":
        return None

    siaddr = socket.inet_ntoa(data[20:24])
    boot_file = data[108:236].split(b"\x00")[0].decode("ascii", errors="ignore")

    vendor_class: Optional[str] = None
    tftp_server: Optional[str] = None
    boot_file_option: Optional[str] = None

    idx = 240
    while idx < len(data):
        code = data[idx]
        idx += 1
        if code == 255:
            break
        if code == 0:
            continue
        if idx >= len(data):
            break
        length = data[idx]
        idx += 1
        if idx + length > len(data):
            break
        value = data[idx : idx + length]
        idx += length
        if code == 60:
            vendor_class = value.decode("ascii", errors="ignore")
        elif code == 66:
            tftp_server = _convert_opt66_to_host(value)
        elif code == 67:
            boot_file_option = value.decode("ascii", errors="ignore")

    return {
        "siaddr": siaddr,
        "boot_file": boot_file,
        "vendor_class": vendor_class,
        "tftp_server": tftp_server,
        "boot_file_option": boot_file_option,
    }


def _convert_opt66_to_host(val: bytes) -> Optional[str]:
    """Parse DHCP option 66 (TFTP Server Name) — IPv4 or hostname."""
    if not val:
        return None
    if len(val) == 4:
        try:
            return socket.inet_ntoa(val)
        except Exception:  # noqa: BLE001
            pass
    try:
        return val.decode("ascii", errors="ignore").rstrip("\x00")
    except Exception:  # noqa: BLE001
        return None


def _is_pxe_response(parsed: dict[str, Any]) -> bool:
    """Heuristic: any of vendor=PXEClient / boot_file / option-67 means PXE."""
    if (parsed.get("vendor_class") or "").find("PXEClient") >= 0:
        return True
    if parsed.get("boot_file"):
        return True
    if parsed.get("boot_file_option"):
        return True
    return False


def _resolve_ip_to_hostname(ip: Optional[str]) -> Optional[str]:
    """Reverse-DNS an IP, falling back to the IP literal."""
    if not ip:
        return None
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return ip


# ---------------------------------------------------------------------------
# Phase 3a — Per-host RemoteRegistry + MSSQL probes.
# ---------------------------------------------------------------------------
# These resources iterate ``ctx.ldap_computer_hosts()`` and probe each host
# directly. RemoteRegistry uses impacket's RPC-over-SMB to read SCCM
# configuration from HKLM; MSSQL sends a TDS PRELOGIN packet to TCP/1433 to
# detect Extended Protection for Authentication.
#
# CMBP references:
#   - ``lib/collectors/registry_collector.py``     (~752 LOC)
#   - ``lib/collectors/mssql_collector.py``        (~621 LOC)
#
# Phase 3a does NOT do authenticated MSSQL introspection — that requires a
# pymssql / impacket-mssql round-trip with credentials and is best done in
# Phase 3b alongside AdminService. The login/database/role/etc. resources
# below currently yield empty so the convert phase doesn't crash if the
# JSONL is missing.

# -- Registry ----------------------------------------------------------------

_SCCM_REG_KEYS = {
    "triggers": r"SOFTWARE\Microsoft\SMS\Identification",
    "component_servers": r"SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Component Servers",
    "multisite_components": r"SOFTWARE\Microsoft\SMS\COMPONENTS\SMS_SITE_COMPONENT_MANAGER\Multisite Component Servers",
    "current_user": r"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
}


def _split_user_domain(username: Optional[str], default_domain: str) -> tuple[str, str]:
    """Split a ``DOMAIN\\user`` or ``user@domain`` into ``(domain, user)``.

    Falls back to the first component of the configured AD ``domain`` when no
    explicit prefix is present.
    """
    if not username:
        return default_domain.split(".")[0], ""
    if "\\" in username:
        d, u = username.split("\\", 1)
        return d, u
    if "@" in username:
        u, d = username.split("@", 1)
        return d, u
    return default_domain.split(".")[0], username


class _RegistryProbe:
    """Lightweight remote-registry helper used by the Phase 3a registry resources.

    Wraps an SMB connection + a winreg DCE/RPC binding. ``read_value`` /
    ``read_dword`` / ``enum_keys`` are slimmed-down versions of the helpers
    in ``lib/collectors/registry_collector.py`` — same APIs, same error model
    (return None on failure), no GraphStore writes.
    """

    def __init__(self, hostname: str, domain: str, username: Optional[str], password: Optional[str]) -> None:
        self.hostname = hostname
        self.domain = domain
        self.username = username
        self.password = password
        self.smb = None
        self.dce = None
        self.root_key = None

    def __enter__(self) -> Optional["_RegistryProbe"]:
        # Fast TCP probe to avoid 30-second SMB timeouts on dead hosts.
        try:
            with socket.create_connection((self.hostname, 445), timeout=3):
                pass
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            logger.debug("registry: SMB/445 not reachable on %s: %s", self.hostname, e)
            return None

        try:
            from impacket.dcerpc.v5 import rrp, transport
            from impacket.smbconnection import SMBConnection
        except ImportError:
            logger.warning("registry: impacket not installed; skipping host %s", self.hostname)
            return None

        d, u = _split_user_domain(self.username, self.domain)
        try:
            smb = SMBConnection(self.hostname, self.hostname, timeout=5)
            if u and self.password:
                smb.login(u, self.password, d)
            else:
                # Current Kerberos session — best-effort
                smb.login("", "", d)
            self.smb = smb
        except Exception as e:  # noqa: BLE001
            logger.debug("registry: SMB login to %s failed: %s", self.hostname, e)
            return None

        try:
            rpc = transport.SMBTransport(smb.getRemoteHost(), filename=r"\winreg", smb_connection=smb)
            rpc.connect()
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(rrp.MSRPC_UUID_RRP)
            resp = rrp.hOpenLocalMachine(dce)
            self.dce = dce
            self.root_key = resp["phKey"]
            return self
        except Exception as e:  # noqa: BLE001
            # Most common cause: RemoteRegistry service not running, or no perm.
            logger.debug("registry: winreg bind on %s failed: %s", self.hostname, e)
            try:
                smb.logoff()
            except Exception:
                pass
            return None

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        try:
            if self.dce is not None:
                self.dce.disconnect()
        except Exception:
            pass
        try:
            if self.smb is not None:
                self.smb.logoff()
        except Exception:
            pass

    # ----- read helpers ------------------------------------------------------

    def read_value(self, key_path: str, value_name: str) -> Optional[str]:
        from impacket.dcerpc.v5 import rrp
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                _, value = rrp.hBaseRegQueryValue(self.dce, sub, value_name)
                if isinstance(value, bytes):
                    value = value.decode("utf-16-le", errors="replace")
                return str(value).rstrip("\x00").strip()
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except Exception:
            return None

    def read_dword(self, key_path: str, value_name: str) -> Optional[int]:
        from impacket.dcerpc.v5 import rrp
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                _, value = rrp.hBaseRegQueryValue(self.dce, sub, value_name)
                if isinstance(value, int):
                    return value
                if isinstance(value, bytes) and len(value) >= 4:
                    import struct
                    return struct.unpack("<I", value[:4])[0]
                return int(value) if value else None
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except Exception:
            return None

    def enum_keys(self, key_path: str) -> Optional[list[str]]:
        from impacket.dcerpc.v5 import rrp
        try:
            sub = rrp.hBaseRegOpenKey(self.dce, self.root_key, key_path)["phkResult"]
            try:
                names: list[str] = []
                i = 0
                while True:
                    try:
                        resp = rrp.hBaseRegEnumKey(self.dce, sub, i)
                        name = resp["lpNameOut"]
                        if isinstance(name, bytes):
                            name = name.decode("utf-16-le", errors="replace")
                        names.append(str(name).rstrip("\x00").strip())
                        i += 1
                    except Exception:
                        break
                return names
            finally:
                rrp.hBaseRegCloseKey(self.dce, sub)
        except Exception:
            return None


@app.resource(name="registry_sccm_components", parallelized=False)
def registry_sccm_components(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per (host, role) discovered via remote registry.

    For each host with SMB/445 + RemoteRegistry reachable, reads:
    - ``HKLM\\SOFTWARE\\Microsoft\\SMS\\Identification::Site Code`` to record
      the site code the host is part of (role = ``"Site System"``).
    - The ``Component Servers`` subkey — each subkey name is the FQDN of a
      site system server (passive site server, SCP, MP, DP, SUP). One row
      per FQDN with role = ``"SMS Component Server"``.

    A successful read (even if the keys are empty) implies this host is the
    SCCM site server. Hosts without the SCCM key tree silently yield nothing.
    """
    if not ctx.method_enabled("RemoteRegistry"):
        return
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        with _RegistryProbe(hostname, ctx.domain, ctx.username, ctx.password) as probe:
            if probe is None:
                continue
            site_code = probe.read_value(_SCCM_REG_KEYS["triggers"], "Site Code")
            if site_code:
                yield {
                    "hostname": hostname,
                    "site_code": site_code,
                    "role": "SMS Site Server",
                    "computer_sid": host.get("sid"),
                    "source": "RemoteRegistry-Identification",
                    "domain": ctx.domain,
                }
                components = probe.enum_keys(_SCCM_REG_KEYS["component_servers"]) or []
                for fqdn in components:
                    if not fqdn:
                        continue
                    yield {
                        "hostname": fqdn.lower(),
                        "site_code": site_code,
                        "role": "SMS Component Server",
                        "computer_sid": None,
                        "source": "RemoteRegistry-ComponentServer",
                        "domain": ctx.domain,
                    }


@app.resource(name="registry_sccm_databases", parallelized=False)
def registry_sccm_databases(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per (site_code, db_hostname) discovered via remote registry.

    Reads the ``SMS_SITE_COMPONENT_MANAGER\\Multisite Component Servers``
    subkey on each reachable host. Empty subkey = local DB (we do not emit a
    row in that case; the registry path doesn't reveal a remote DB host).
    Populated subkey = the listed FQDN(s) are SQL servers hosting the site DB.
    """
    if not ctx.method_enabled("RemoteRegistry"):
        return
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        with _RegistryProbe(hostname, ctx.domain, ctx.username, ctx.password) as probe:
            if probe is None:
                continue
            site_code = probe.read_value(_SCCM_REG_KEYS["triggers"], "Site Code")
            if not site_code:
                continue
            multisite = probe.enum_keys(_SCCM_REG_KEYS["multisite_components"]) or []
            for db_fqdn in multisite:
                if not db_fqdn:
                    continue
                yield {
                    "hostname": db_fqdn.lower(),
                    "site_code": site_code,
                    "site_server": hostname,
                    "source": "RemoteRegistry-MultisiteComponentServers",
                    "domain": ctx.domain,
                }


@app.resource(name="registry_current_users", parallelized=False)
def registry_current_users(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per (host, last-logged-on-user) discovered via remote registry.

    Reads ``HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI::LastLoggedOnSAMUser``.
    Only emits when the value is non-empty. Username is captured raw
    (typically ``DOMAIN\\sam``); SID resolution happens at convert time via
    ``SCCMLookup.user_by_sam``.

    Gated on :meth:`SourceContext.sccm_discovered_hosts` — CMBP's per-host
    registry walk only iterates the ``TargetManager`` host list (hosts
    surfaced by LDAP-mSSMSManagementPoint / LDAP naming pattern / SMS
    Provider sAMAccountName / AdminService SMS_Site / SMS_SCI_*). Without
    this gate OH walks the full LDAP computer set and reads the DC's
    registry, surfacing a phantom ``DC -> domainadmin`` HasSession edge
    that CMBP never produces.
    """
    if not ctx.method_enabled("RemoteRegistry"):
        return
    discovered = ctx.sccm_discovered_hosts()
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        # Same canonicalisation as ``mssql_epa_flags``: the discovered set
        # carries lowercase short-host AND lowercase fqdn forms.
        short = (hostname or "").split(".", 1)[0].lower()
        fqdn = (hostname or "").lower()
        if discovered and short not in discovered and fqdn not in discovered:
            continue
        with _RegistryProbe(hostname, ctx.domain, ctx.username, ctx.password) as probe:
            if probe is None:
                continue
            last_user = probe.read_value(_SCCM_REG_KEYS["current_user"], "LastLoggedOnSAMUser")
            if not last_user:
                continue
            yield {
                "hostname": hostname,
                "user_name": last_user,
                "computer_sid": host.get("sid"),
                "source": "RemoteRegistry-CurrentUser",
                "domain": ctx.domain,
            }


# -- MSSQL EPA prelogin probe ------------------------------------------------

_TDS_PRELOGIN_VERSION = 0x00
_TDS_PRELOGIN_ENCRYPTION = 0x01
_TDS_PRELOGIN_INSTOPT = 0x02
_TDS_PRELOGIN_THREADID = 0x03
_TDS_PRELOGIN_MARS = 0x04
_TDS_PRELOGIN_TERMINATOR = 0xFF


def _build_tds_prelogin_payload() -> bytes:
    """Build the TDS PRELOGIN payload (5 options + terminator).

    Direct port of ``mssql_collector._build_tds_prelogin``.
    """
    import struct

    num_options = 5
    option_header_size = num_options * 5 + 1
    version_data = struct.pack(">BBBBH", 16, 0, 0, 1, 0)
    encryption_data = bytes([0x00])
    instopt_data = bytes([0x00])
    threadid_data = struct.pack(">I", 0)
    mars_data = bytes([0x00])

    offset = option_header_size
    options = bytearray()
    for token, data in (
        (_TDS_PRELOGIN_VERSION, version_data),
        (_TDS_PRELOGIN_ENCRYPTION, encryption_data),
        (_TDS_PRELOGIN_INSTOPT, instopt_data),
        (_TDS_PRELOGIN_THREADID, threadid_data),
        (_TDS_PRELOGIN_MARS, mars_data),
    ):
        options.extend(struct.pack(">BHH", token, offset, len(data)))
        offset += len(data)
    options.append(_TDS_PRELOGIN_TERMINATOR)
    payload = bytes(options) + version_data + encryption_data + instopt_data + threadid_data + mars_data
    return payload


def _parse_tds_prelogin_response(payload: bytes) -> Optional[int]:
    """Return the encryption byte (0x00..0x03) or None if not present.

    Same parsing as ``mssql_collector._parse_prelogin_response`` but returns
    the raw byte so callers can label EPA themselves (Off/Allowed/Required).
    """
    import struct

    offset = 0
    while offset < len(payload):
        token = payload[offset]
        if token == _TDS_PRELOGIN_TERMINATOR:
            break
        if offset + 5 > len(payload):
            break
        data_offset = struct.unpack(">H", payload[offset + 1:offset + 3])[0]
        data_length = struct.unpack(">H", payload[offset + 3:offset + 5])[0]
        if token == _TDS_PRELOGIN_ENCRYPTION and data_offset + data_length <= len(payload):
            return payload[data_offset]
        offset += 5
    return None


def _probe_mssql_epa(hostname: str, port: int = 1433) -> Optional[dict[str, Any]]:
    """Send a TDS PRELOGIN to ``hostname:port`` and return EPA metadata.

    Returns ``None`` if the TCP connect or the prelogin handshake fails.
    Returns a dict with the encryption byte + a textual EPA label otherwise.
    """
    import struct

    try:
        sock = socket.create_connection((hostname, port), timeout=5)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug("mssql: %s:%d unreachable: %s", hostname, port, e)
        return None

    try:
        payload = _build_tds_prelogin_payload()
        header = struct.pack(">BBHHBB", 0x12, 0x01, len(payload) + 8, 0, 1, 0)
        sock.sendall(header + payload)

        sock.settimeout(5.0)
        # Read TDS header (8 bytes), then payload of length-8.
        head = b""
        while len(head) < 8:
            chunk = sock.recv(8 - len(head))
            if not chunk:
                return None
            head += chunk
        total_len = struct.unpack(">H", head[2:4])[0]
        body = b""
        while len(body) < total_len - 8:
            chunk = sock.recv(total_len - 8 - len(body))
            if not chunk:
                break
            body += chunk
        encryption_byte = _parse_tds_prelogin_response(body)
    except Exception as e:  # noqa: BLE001
        logger.debug("mssql: TDS PRELOGIN to %s:%d failed: %s", hostname, port, e)
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass

    if encryption_byte is None:
        return None
    # 0x00=ENCRYPT_OFF, 0x01=ENCRYPT_ON, 0x02=ENCRYPT_NOT_SUP, 0x03=ENCRYPT_REQ
    label_map = {0x00: "Off", 0x01: "Allowed", 0x02: "NotSupported", 0x03: "Required"}
    return {
        "encryption_byte": int(encryption_byte),
        "epa": label_map.get(encryption_byte, f"Unknown(0x{encryption_byte:02x})"),
        "epa_enabled": encryption_byte in (0x01, 0x03),
    }


@app.resource(name="mssql_epa_flags", parallelized=False, columns=MSSQLServer)
def mssql_epa_flags(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per MSSQL host that responds to a TDS PRELOGIN on TCP/1433.

    EPA detection is the most valuable Phase 3a signal because it drives the
    Phase 4 ``CoerceAndRelayToMSSQL`` derived edges. Hosts not listening on
    1433 silently yield no row.

    The probe set is gated by ``ctx.sccm_discovered_hosts()`` — i.e. we only
    probe hosts that have been discovered through an SCCM channel (SMS
    provider, MP record, SCCM-naming pattern, or AdminService SMS_Site /
    SMS_SCI_SiteDefinition / SMS_SCI_SysResUse). This matches CMBP's
    per-host MSSQL phase scoping (CMBP's ``TargetManager`` only includes
    hosts surfaced by these same channels) and avoids emitting phantom
    MSSQL_Server nodes for arbitrary domain computers that happen to be
    listening on TCP/1433. Without the gate, a low-priv user with no
    AdminService access would still see CAS-DB / PS1-DB nodes via raw
    LDAP-walk + 1433 scan, while CMBP correctly emits zero such nodes.
    """
    if not ctx.method_enabled("MSSQL"):
        return
    discovered = ctx.sccm_discovered_hosts()
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        host_low = hostname.lower()
        host_short = host_low.split(".", 1)[0]
        if host_low not in discovered and host_short not in discovered:
            continue
        epa = _probe_mssql_epa(hostname, 1433)
        if not epa:
            continue
        yield {
            "hostname": hostname,
            "port": 1433,
            "fqdn": hostname,
            "epa": epa["epa"],
            "epa_value": epa["encryption_byte"],
            "epa_enabled": epa["epa_enabled"],
            "computer_sid": host.get("sid"),
            "source": "MSSQL-TDS",
            "domain": ctx.domain,
        }


# -- MSSQL authenticated introspection (best-effort) -------------------------
#
# For each host that responded to ``mssql_epa_flags`` (TCP/1433 + TDS prelogin),
# open an authenticated TDS session via ``impacket.tds`` and run the canonical
# SCCM-introspection queries against ``sys.server_principals`` / ``sys.databases``
# / ``sys.server_role_members`` / ``sys.database_role_members`` / ``sys.servers``.
#
# Auth model:
# - SourceContext threads (username, password) through; the TDS connect
#   path uses ``ms.kerberosLogin(...)`` when explicit creds are present
#   (impacket's NTLM path doesn't honour CBT against Schannel; Kerberos with
#   ``useCache=False`` works because we pass an explicit (user, password)
#   tuple).
# - Hosts that reject auth or aren't listening for SQL are silently skipped
#   (lowpriv typically can't open ``master`` at all and yields zero rows).
#
# Cache:
# - ``ctx.mssql_introspection()`` runs the full sweep once per source run and
#   memoises the result (mirrors ``ctx.adminservice_payloads()``). Each
#   ``mssql_*`` resource below yields its slice of that cached payload.

def _mssql_connect(
    hostname: str,
    domain: str,
    username: Optional[str],
    password: Optional[str],
    port: int = 1433,
):
    """Open an authenticated TDS session against ``hostname:port``.

    Returns the connected ``impacket.tds.MSSQL`` instance on success, ``None``
    on any auth / network failure. Caller is responsible for ``disconnect()``.
    """
    try:
        from impacket.tds import MSSQL
    except ImportError:
        logger.warning("mssql: impacket.tds not installed; skipping host %s", hostname)
        return None

    d, u = _split_user_domain(username, domain)
    if not (u and password):
        logger.debug("mssql: no explicit creds; skipping authenticated introspection of %s", hostname)
        return None

    try:
        ms = MSSQL(hostname, port)
        ms.connect()
        # Cap blocking-socket waits so a half-broken Kerberos handshake or a
        # long-running query can't wedge the whole collect for minutes.
        try:
            if ms.socket is not None:
                ms.socket.settimeout(15)
        except Exception:
            pass
    except Exception as exc:  # noqa: BLE001
        logger.debug("mssql: TDS connect to %s:%d failed: %s", hostname, port, exc)
        return None

    # Skip Kerberos in this lab — the lab DC is reachable but the impacket
    # kerberosLogin path tends to wedge the whole collect when CBT is enforced
    # on the SQL server. NTLM login works for sysadmin sweeps when the user
    # has a server-level login. Caller is expected to gate by epa probe.
    ok = False
    try:
        ok = bool(ms.login(None, u, password, d, None, None, True))
    except Exception as exc:  # noqa: BLE001
        logger.debug("mssql: NTLM login to %s failed: %s", hostname, exc)
        ok = False
    if not ok:
        try:
            ms.disconnect()
        except Exception:
            pass
        return None
    return ms


def _mssql_run(ms, query: str) -> list[dict[str, Any]]:
    """Run ``query`` and return ``ms.rows`` as a list of dicts.

    Drains ``ms.rows`` after execution so subsequent queries see a clean slate.
    Returns an empty list on any execution error so callers don't need to
    wrap individual queries.
    """
    try:
        ms.sql_query(query)
        rows = list(ms.rows or [])
        # Reset the buffer to avoid bleed-through on the next query.
        ms.rows = []
        return rows
    except Exception as exc:  # noqa: BLE001
        logger.debug("mssql: query failed (%s): %s", query[:60], exc)
        try:
            ms.rows = []
        except Exception:
            pass
        return []


def _collect_mssql_introspection(
    hostname: str,
    domain: str,
    username: Optional[str],
    password: Optional[str],
    port: int = 1433,
) -> Optional[dict[str, list[dict[str, Any]]]]:
    """Run the full SCCM introspection query set against ``hostname:port``.

    Returns ``None`` if the host can't be authenticated, otherwise a dict
    with seven lists keyed by resource name.
    """
    ms = _mssql_connect(hostname, domain, username, password, port)
    if ms is None:
        return None

    out: dict[str, list[dict[str, Any]]] = {
        "mssql_logins": [],
        "mssql_databases": [],
        "mssql_database_users": [],
        "mssql_server_roles": [],
        "mssql_database_roles": [],
        "mssql_role_members": [],
        "mssql_linked_servers": [],
    }

    try:
        # ---- server-level principals (logins) -------------------------
        for row in _mssql_run(ms, (
            "SELECT name, type_desc, is_disabled, "
            "CAST(IS_SRVROLEMEMBER('sysadmin', name) AS int) AS is_sysadmin "
            "FROM master.sys.server_principals "
            "WHERE type IN ('S','U','G') "
            "  AND name NOT LIKE '##%##' "
            "  AND name NOT LIKE 'NT SERVICE\\%'"
        )):
            login_name = (row.get("name") or "").strip()
            if not login_name:
                continue
            type_desc = (row.get("type_desc") or "").strip()
            out["mssql_logins"].append({
                "hostname": hostname,
                "port": port,
                "login_name": login_name,
                "login_type": type_desc or None,
                "is_disabled": bool(row.get("is_disabled")) if row.get("is_disabled") is not None else None,
                "is_sysadmin": bool(row.get("is_sysadmin")),
                "domain": domain,
                "source": "MSSQL-Auth",
            })

        # ---- databases ----------------------------------------------
        databases: list[str] = []
        for row in _mssql_run(ms, (
            "SELECT name, is_trustworthy_on FROM master.sys.databases "
            "WHERE name NOT IN ('master','tempdb','model','msdb')"
        )):
            db_name = (row.get("name") or "").strip()
            if not db_name:
                continue
            databases.append(db_name)
            out["mssql_databases"].append({
                "hostname": hostname,
                "port": port,
                "database_name": db_name,
                "is_trustworthy": bool(row.get("is_trustworthy_on")) if row.get("is_trustworthy_on") is not None else None,
                "site_code": db_name[3:] if db_name.upper().startswith("CM_") else None,
                "domain": domain,
                "source": "MSSQL-Auth",
            })

        # ---- server-level role membership ---------------------------
        for row in _mssql_run(ms, (
            "SELECT r.name AS role_name, p.name AS member_name "
            "FROM master.sys.server_role_members rm "
            "JOIN master.sys.server_principals r ON r.principal_id = rm.role_principal_id "
            "JOIN master.sys.server_principals p ON p.principal_id = rm.member_principal_id "
            "WHERE r.is_fixed_role = 1"
        )):
            role_name = (row.get("role_name") or "").strip()
            member_name = (row.get("member_name") or "").strip()
            if not role_name:
                continue
            out["mssql_server_roles"].append({
                "hostname": hostname,
                "port": port,
                "role_name": role_name,
                "is_fixed_role": True,
                "domain": domain,
                "source": "MSSQL-Auth",
            })
            if member_name:
                out["mssql_role_members"].append({
                    "hostname": hostname,
                    "port": port,
                    "scope": "server",
                    "database_name": None,
                    "role_name": role_name,
                    "member_name": member_name,
                    "domain": domain,
                    "source": "MSSQL-Auth",
                })

        # ---- per-database introspection ------------------------------
        for db_name in databases:
            # database_principals (database users)
            for row in _mssql_run(ms, (
                f"SELECT name, type_desc FROM [{db_name}].sys.database_principals "
                "WHERE type IN ('S','U','G') "
                "  AND name NOT IN ('dbo','guest','INFORMATION_SCHEMA','sys') "
                "  AND name NOT LIKE '##%##'"
            )):
                user_name = (row.get("name") or "").strip()
                if not user_name:
                    continue
                out["mssql_database_users"].append({
                    "hostname": hostname,
                    "port": port,
                    "database_name": db_name,
                    "user_name": user_name,
                    "user_type": (row.get("type_desc") or "").strip() or None,
                    "domain": domain,
                    "source": "MSSQL-Auth",
                })

            # database_role_members (database roles + memberships)
            for row in _mssql_run(ms, (
                f"SELECT r.name AS role_name, p.name AS member_name "
                f"FROM [{db_name}].sys.database_role_members rm "
                f"JOIN [{db_name}].sys.database_principals r ON r.principal_id = rm.role_principal_id "
                f"JOIN [{db_name}].sys.database_principals p ON p.principal_id = rm.member_principal_id "
                f"WHERE r.is_fixed_role = 1"
            )):
                role_name = (row.get("role_name") or "").strip()
                member_name = (row.get("member_name") or "").strip()
                if not role_name:
                    continue
                out["mssql_database_roles"].append({
                    "hostname": hostname,
                    "port": port,
                    "database_name": db_name,
                    "role_name": role_name,
                    "is_fixed_role": True,
                    "domain": domain,
                    "source": "MSSQL-Auth",
                })
                if member_name:
                    out["mssql_role_members"].append({
                        "hostname": hostname,
                        "port": port,
                        "scope": "database",
                        "database_name": db_name,
                        "role_name": role_name,
                        "member_name": member_name,
                        "domain": domain,
                        "source": "MSSQL-Auth",
                    })

        # ---- linked servers -----------------------------------------
        for row in _mssql_run(ms, (
            "SELECT name, product, provider, data_source, is_linked, is_remote_login_enabled "
            "FROM master.sys.servers WHERE server_id <> 0"
        )):
            link_name = (row.get("name") or "").strip()
            if not link_name:
                continue
            out["mssql_linked_servers"].append({
                "hostname": hostname,
                "port": port,
                "linked_name": link_name,
                "product": (row.get("product") or "").strip() or None,
                "provider": (row.get("provider") or "").strip() or None,
                "data_source": (row.get("data_source") or "").strip() or None,
                "is_linked": bool(row.get("is_linked")) if row.get("is_linked") is not None else None,
                "is_remote_login_enabled": bool(row.get("is_remote_login_enabled")) if row.get("is_remote_login_enabled") is not None else None,
                "domain": domain,
                "source": "MSSQL-Auth",
            })

    finally:
        try:
            ms.disconnect()
        except Exception:
            pass

    # Dedup server roles (same role appears once per member) and database
    # roles (one row per (db, role, member)).
    def _dedup(rows: list[dict[str, Any]], keys: tuple[str, ...]) -> list[dict[str, Any]]:
        seen: set[tuple] = set()
        out_rows: list[dict[str, Any]] = []
        for r in rows:
            sig = tuple(r.get(k) for k in keys)
            if sig in seen:
                continue
            seen.add(sig)
            out_rows.append(r)
        return out_rows

    out["mssql_server_roles"] = _dedup(out["mssql_server_roles"], ("hostname", "port", "role_name"))
    out["mssql_database_roles"] = _dedup(out["mssql_database_roles"], ("hostname", "port", "database_name", "role_name"))

    return out


@app.resource(name="mssql_logins", parallelized=False, columns=MSSQLLogin)
def mssql_logins(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per server-level login on every authenticated MSSQL host."""
    for payload in ctx.mssql_introspection().values():
        for row in payload.get("mssql_logins", []):
            yield row


@app.resource(name="mssql_databases", parallelized=False, columns=MSSQLDatabase)
def mssql_databases(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per non-system database on every authenticated MSSQL host."""
    for payload in ctx.mssql_introspection().values():
        for row in payload.get("mssql_databases", []):
            yield row


@app.resource(name="mssql_database_users", parallelized=False, columns=MSSQLDatabaseUser)
def mssql_database_users(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (database, principal) on every authenticated MSSQL host."""
    for payload in ctx.mssql_introspection().values():
        for row in payload.get("mssql_database_users", []):
            yield row


@app.resource(name="mssql_server_roles", parallelized=False, columns=MSSQLServerRole)
def mssql_server_roles(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per server-level role observed on each authenticated MSSQL host."""
    for payload in ctx.mssql_introspection().values():
        for row in payload.get("mssql_server_roles", []):
            yield row


@app.resource(name="mssql_database_roles", parallelized=False, columns=MSSQLDatabaseRole)
def mssql_database_roles(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (database, role) observed on each authenticated MSSQL host."""
    for payload in ctx.mssql_introspection().values():
        for row in payload.get("mssql_database_roles", []):
            yield row


@app.resource(name="mssql_role_members", parallelized=False)
def mssql_role_members(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (scope, role, member) — server- and database-scoped."""
    for payload in ctx.mssql_introspection().values():
        for row in payload.get("mssql_role_members", []):
            yield row


@app.resource(name="mssql_linked_servers", parallelized=False)
def mssql_linked_servers(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per linked-server entry in ``sys.servers``."""
    for payload in ctx.mssql_introspection().values():
        for row in payload.get("mssql_linked_servers", []):
            yield row


# ---------------------------------------------------------------------------
# Phase 3b — AdminService REST API enumeration.
# ---------------------------------------------------------------------------
# The AdminService runs on the SMS Provider role over HTTPS / 443 and is the
# richest data source in the whole collector. The original CMBP implementation
# is `lib/collectors/adminservice_collector.py` (~1,399 LOC); we port the
# nine WMI-shaped queries faithfully but split them into separate DLT
# resources so each lands in its own JSONL.
#
# Pattern: each `adminservice_*` resource calls `ctx.adminservice_payloads()`
# which lazily fetches every reachable SMS Provider's data exactly once per
# source run, then yields the corresponding slice. Errors per host are
# swallowed with a logged INFO so a single offline provider doesn't fail the
# whole collection.
#
# CMBP reference URLs (under /AdminService/):
#   wmi/SMS_Identification               -> site code for this provider
#   wmi/SMS_Site                         -> all sites in the hierarchy
#   wmi/SMS_SCI_SiteDefinition           -> SQL/site server detail per site
#   wmi/SMS_Admin                        -> admin users / groups
#   wmi/SMS_Collection                   -> collections
#   wmi/SMS_FullCollectionMembership     -> per-collection members
#   wmi/SMS_Role                         -> security roles
#   wmi/SMS_R_System                     -> client devices / AD-mapped systems
#   wmi/SMS_CombinedDeviceResources      -> richer client device view
#   wmi/SMS_TaskSequencePackage          -> task sequence policies
#   wmi/SMS_CollectionVariable           -> per-collection variables
#   wmi/SMS_SCI_SysResUse                -> site system roles per host

def _normalize_role_member_admin(item: dict[str, Any]) -> str:
    """Extract a normalized ``DOMAIN\\sam`` admin logon from an SMS_Admin row."""
    return ((item.get("LogonName") or "").strip())


def _collect_adminservice_data(
    hostname: str,
    username: Optional[str],
    password: Optional[str],
) -> Optional[dict[str, Any]]:
    """Run the full AdminService enumeration against ``hostname`` and return
    a dict of lists keyed by resource name. Returns ``None`` if the host is
    unreachable or the initial site-code probe fails (i.e. neither
    ``SMS_Identification`` nor ``SMS_Site`` returns anything).

    Each list entry is a dict already shaped for the matching DLT resource
    schema. The shaping happens inline (one short helper would be more
    DRY but at the cost of clarity given how different the WMI rows are).
    """
    from .clients.adminservice import AdminServiceClient

    base_url = f"https://{hostname}/AdminService"
    client = AdminServiceClient(
        base_url=base_url,
        username=username,
        password=password,
        timeout=20,
    )

    if not client.host_reachable(443, timeout=3.0):
        logger.info("adminservice: %s:443 not reachable; skipping", hostname)
        return None

    # Step 1: SMS_Identification gives this provider's site code.
    site_code = None
    ident = client.get("wmi/SMS_Identification")
    if ident:
        for entry in ident.get("value", []):
            sc = entry.get("ThisSiteCode")
            if sc:
                site_code = sc
                break

    # Step 2: SMS_Site gives every site in the hierarchy. Even if SMS_Identification
    # failed we may still pull a usable site_code from here.
    sites_payload = client.get_paginated("wmi/SMS_Site") or []
    if not site_code and sites_payload:
        for entry in sites_payload:
            if entry.get("SiteCode"):
                site_code = entry["SiteCode"]
                break

    if not site_code:
        logger.info("adminservice: %s could not be probed for a site code; skipping", hostname)
        return None

    logger.info("adminservice: collecting from %s (site=%s)", hostname, site_code)

    site_definitions = client.get_paginated("wmi/SMS_SCI_SiteDefinition") or []

    admins_raw = client.get_paginated("wmi/SMS_Admin") or []
    collections_raw = client.get_paginated("wmi/SMS_Collection") or []
    collection_members_raw = client.get_paginated("wmi/SMS_FullCollectionMembership") or []
    roles_raw = client.get_paginated("wmi/SMS_Role") or []
    sms_r_system_raw = client.get_paginated("wmi/SMS_R_System") or []
    combined_devices_raw = client.get_paginated("wmi/SMS_CombinedDeviceResources") or []
    # SMS_R_User: like SMS_R_System but for AD users, with SecurityGroupName
    # giving each user's group memberships. CMBP feeds these to MemberOf
    # edges (User -> Group); see adminservice_collector._get_sms_r_user.
    sms_r_user_raw = client.get_paginated(
        "wmi/SMS_R_User",
        extra_params={
            "$select": (
                "DistinguishedName,FullDomainName,FullUserName,Name,ResourceID,"
                "SecurityGroupName,SID,UniqueUserName,UserName,UserPrincipalName"
            )
        },
    ) or []

    # The next two are best-effort - SCCM versions vary on availability.
    task_sequences_raw = client.get_paginated("wmi/SMS_TaskSequencePackage") or []
    collection_vars_raw = client.get_paginated("wmi/SMS_CollectionVariable") or []
    site_systems_raw = client.get_paginated("wmi/SMS_SCI_SysResUse") or []
    # SMS_SCI_Reserved: per-site stored accounts (NAA, push install, etc.).
    # CMBP feeds these to ``SCCM_HasStoredAccount`` edges from SCCM_Site
    # to the resolved User node.
    reserved_accounts_raw = client.get_paginated("wmi/SMS_SCI_Reserved") or []

    # ----- Normalise into per-resource row lists -----

    # adminservice_admins: one row per SMS_Admin entry
    admins: list[dict[str, Any]] = []
    role_members: list[dict[str, Any]] = []
    for item in admins_raw:
        logon = _normalize_role_member_admin(item)
        if not logon:
            continue
        roles = item.get("RoleNames") or []
        if isinstance(roles, str):
            roles = [r.strip() for r in roles.split(",") if r.strip()]
        colls = item.get("CollectionNames") or []
        if isinstance(colls, str):
            colls = [c.strip() for c in colls.split(",") if c.strip()]

        scope_names = item.get("CategoryNames") or []
        if isinstance(scope_names, str):
            scope_names = [s.strip() for s in scope_names.split(",") if s.strip()]
        is_all_instances = bool(scope_names) and (
            "All Systems" in scope_names or "All" in scope_names
        )

        admins.append({
            "logon_name": logon,
            "site_code": site_code,
            "admin_id": item.get("AdminID"),
            "admin_sid": item.get("AdminSid") or "",
            "display_name": item.get("DisplayName") or "",
            "is_group": (item.get("AccountType") == 1),
            "is_all_instances": is_all_instances,
            "source_site_code": item.get("SourceSite") or site_code,
            "role_names": roles,
            "collection_names": colls,
        })

        # adminservice_role_members: one row per (admin, role, scope-collection) tuple.
        # SMS_Admin's RoleNames + CollectionNames are parallel-ish lists; we
        # cross them so Phase 4 can join scope vs role independently. The
        # CategoryNames+RoleNames "All Systems" case represents a Full Admin
        # with global scope - emitted with scope_collection_id = "SMS00001".
        scope_collection_ids: list[str] = []
        if is_all_instances:
            scope_collection_ids = ["SMS00001"]  # All Systems
        # Match collection name -> id from the collections list when available.
        coll_name_to_id = {
            (c.get("Name") or "").strip(): (c.get("CollectionID") or "").strip()
            for c in collections_raw
        }
        for cname in colls:
            cid = coll_name_to_id.get(cname.strip())
            if cid:
                scope_collection_ids.append(cid)

        # If we couldn't resolve any specific scope, emit one role-member row
        # per role with a NULL scope so the relation is still recorded.
        if not scope_collection_ids:
            scope_collection_ids = [""]

        # Match role name -> id from the roles list.
        role_name_to_id = {
            (r.get("RoleName") or "").strip(): (r.get("RoleID") or "").strip()
            for r in roles_raw
        }
        for rname in roles:
            rid = role_name_to_id.get(rname.strip(), "")
            for cid in scope_collection_ids:
                role_members.append({
                    "admin_logon_name": logon,
                    "site_code": site_code,
                    "role_id": rid,
                    "role_name": rname,
                    "scope_collection_id": cid,
                    "scope_is_all": is_all_instances,
                })

    # adminservice_collections
    collections: list[dict[str, Any]] = []
    for item in collections_raw:
        cid = (item.get("CollectionID") or "").strip()
        if not cid:
            continue
        collections.append({
            "collection_id": cid,
            "site_code": site_code,
            "name": item.get("Name") or "",
            "collection_type": item.get("CollectionType"),
            "member_count": item.get("MemberCount"),
            "limiting_collection_id": item.get("LimitToCollectionID") or "",
        })

    # adminservice_collection_members
    collection_members: list[dict[str, Any]] = []
    for item in collection_members_raw:
        cid = (item.get("CollectionID") or "").strip()
        rid = item.get("ResourceID") if item.get("ResourceID") is not None else item.get("ResourceId")
        if not cid or rid is None:
            continue
        sms_id = (item.get("SMSID") or "").strip()
        if sms_id and sms_id.upper().startswith("GUID:"):
            guid = sms_id.split(":", 1)[1]
        else:
            guid = sms_id
        # ``raw_site_code`` preserves the raw SiteCode field exactly as it
        # arrived from the SMS_FullCollectionMembership row (could be empty
        # for user / user-group collections — CMBP groups these with a
        # bare ``<id>@`` node id). ``site_code`` falls back to the
        # AdminService host's site_code so SQL views that join on it (e.g.
        # ``has_member_edges`` / ``client_user_edges``) keep working.
        raw_site_code = item.get("SiteCode") or ""
        member_site_code = raw_site_code or site_code
        collection_members.append({
            "site_code": member_site_code,
            "raw_site_code": raw_site_code,
            "collection_id": cid,
            "resource_id": rid,
            "guid": guid,
            "machine_name": item.get("Name") or "",
        })

    # adminservice_security_roles
    security_roles: list[dict[str, Any]] = []
    for item in roles_raw:
        rid = (item.get("RoleID") or "").strip()
        if not rid:
            continue
        security_roles.append({
            "role_id": rid,
            "site_code": site_code,
            "role_name": item.get("RoleName") or "",
            "description": item.get("RoleDescription") or "",
        })

    # adminservice_client_devices: prefer SMS_CombinedDeviceResources for the
    # rich (LastLogonUser/PrimaryUser/CurrentLogonUser) view, fall back to
    # SMS_R_System for the AD-side mapping.
    client_devices: list[dict[str, Any]] = []
    seen_guids: set[str] = set()
    for item in combined_devices_raw:
        is_client = bool(item.get("IsClient"))
        is_obsolete = bool(item.get("IsObsolete"))
        if not is_client or is_obsolete:
            continue
        sms_guid = (item.get("SMSID") or "").strip()
        if sms_guid.upper().startswith("GUID:"):
            sms_guid = sms_guid.split(":", 1)[1]
        if not sms_guid:
            continue
        if sms_guid in seen_guids:
            continue
        seen_guids.add(sms_guid)
        machine_name = (item.get("Name") or "").strip()
        hostname = machine_name.lower() if machine_name else ""
        client_devices.append({
            "guid": sms_guid,
            "site_code": item.get("SiteCode") or site_code,
            "machine_name": machine_name,
            "resource_id": item.get("ResourceID") if item.get("ResourceID") is not None else item.get("ResourceId"),
            "is_client": is_client,
            "client_version": item.get("ClientVersion") or "",
            "ad_object_sid": "",  # filled in from SMS_R_System below
            "last_logon_user": item.get("LastLogonUser") or "",
            "primary_user": item.get("PrimaryUser") or "",
            "current_user": item.get("CurrentLogonUser") or "",
            "hostname": hostname,
        })

    # Walk SMS_R_System for the AD SID linkage on each device.
    rs_by_resource_id: dict[int, dict[str, Any]] = {}
    for item in sms_r_system_raw:
        rid = item.get("ResourceID") if item.get("ResourceID") is not None else item.get("ResourceId")
        if rid is None:
            continue
        rs_by_resource_id[rid] = item

    for dev in client_devices:
        rid = dev.get("resource_id")
        if rid is None:
            continue
        rs = rs_by_resource_id.get(rid)
        if not rs:
            continue
        sid = rs.get("SID") or rs.get("ObjectGUID") or ""
        if isinstance(sid, list):
            sid = sid[0] if sid else ""
        if isinstance(sid, str) and sid.startswith("S-"):
            dev["ad_object_sid"] = sid

    # adminservice_task_sequences
    task_sequences: list[dict[str, Any]] = []
    for item in task_sequences_raw:
        pkg_id = (item.get("PackageID") or "").strip()
        if not pkg_id:
            continue
        task_sequences.append({
            "package_id": pkg_id,
            "site_code": site_code,
            "name": item.get("Name") or "",
            "description": item.get("Description") or "",
        })

    # adminservice_collection_variables
    collection_variables: list[dict[str, Any]] = []
    for item in collection_vars_raw:
        cid = (item.get("CollectionID") or "").strip()
        var_name = (item.get("Name") or "").strip()
        if not cid or not var_name:
            continue
        collection_variables.append({
            "site_code": site_code,
            "collection_id": cid,
            "name": var_name,
            "value": item.get("Value") or "",
            "is_masked": bool(item.get("IsMasked")),
        })

    # adminservice_r_system_security_groups: one row per (computer_name,
    # security_group_name) pair from SMS_R_System. CMBP uses these to emit
    # Computer -> Group MemberOf edges via the AD resolver in
    # ``adminservice_collector._get_sms_r_system`` (lines 698-731). Phase 6
    # consumes this in the ``r_system_member_of_edges`` SQL view to fill
    # the MemberOf gap (33 -> 68) at convert time.
    r_system_security_groups: list[dict[str, Any]] = []
    for item in sms_r_system_raw:
        machine = (item.get("Name") or "").strip()
        groups = item.get("SecurityGroupName") or []
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(",") if g.strip()]
        if not machine or not groups:
            continue
        for grp in groups:
            grp = (grp or "").strip()
            if not grp:
                continue
            r_system_security_groups.append({
                "machine_name": machine,
                "site_code": site_code,
                "security_group_name": grp,
            })

    # adminservice_r_user_security_groups: one row per (user_sid /
    # user_name, security_group_name) pair from SMS_R_User. CMBP uses
    # these to emit User -> Group MemberOf edges; see
    # ``adminservice_collector._get_sms_r_user`` (lines 757-870).
    # Phase 6's ``r_user_member_of_edges`` SQL view consumes this.
    r_user_security_groups: list[dict[str, Any]] = []
    for item in sms_r_user_raw:
        sid_value = item.get("SID")
        if isinstance(sid_value, list):
            sid_value = sid_value[0] if sid_value else None
        if not sid_value:
            continue
        full_name = (item.get("FullUserName") or item.get("UniqueUserName") or item.get("Name") or "").strip()
        sam = (item.get("UserName") or "").strip()
        groups = item.get("SecurityGroupName") or []
        if isinstance(groups, str):
            groups = [g.strip() for g in groups.split(",") if g.strip()]
        if not groups:
            continue
        for grp in groups:
            grp = (grp or "").strip()
            if not grp:
                continue
            r_user_security_groups.append({
                "user_sid": sid_value,
                "user_name": full_name or sam,
                "user_sam_account_name": sam,
                "site_code": site_code,
                "security_group_name": grp,
            })

    # adminservice_site_systems
    site_systems: list[dict[str, Any]] = []
    for item in site_systems_raw:
        server_name = (item.get("ServerName") or "").strip()
        role_name = (item.get("RoleName") or "").strip()
        role_site = item.get("SiteCode") or site_code
        if not server_name or not role_name:
            # Fall back to NetworkOSPath which is sometimes the only field set.
            net_path = (item.get("NetworkOSPath") or "").lstrip("\\").strip()
            if net_path and not server_name:
                server_name = net_path
        if not server_name or not role_name:
            continue

        # CMBP extracts the SQL Server service account from the Props sub-list:
        # PropertyName == "SQL Server Service Logon Account", account in Value2
        # (lib/collectors/adminservice_collector.py:1267-1272). This is the
        # ONLY data source for service-account info that survives without
        # Win32_Service WMI access (lowpriv/roanalyst can't read Win32_Service).
        # We carry it on the SMS SQL Server role row so the gettgs SQL view
        # can fall back to it when wmi_sql_service_accounts is empty.
        service_account: Optional[str] = None
        props_list = item.get("Props", [])
        if isinstance(props_list, list):
            for prop in props_list:
                if not isinstance(prop, dict):
                    continue
                if prop.get("PropertyName") == "SQL Server Service Logon Account":
                    val2 = (prop.get("Value2") or "").strip()
                    if val2:
                        service_account = val2
                        break

        site_systems.append({
            "hostname": server_name.lower(),
            "role": role_name,
            "site_code": role_site,
            "computer_sid": None,  # resolved at convert time via ldap_computers
            "service_account": service_account,  # only set on SMS SQL Server rows
        })

    # adminservice_reserved_accounts: one row per SMS_SCI_Reserved entry that
    # carries an actual ``UserName`` (CMBP skips entries with no UserName).
    # Each row's ``account_username`` is a ``DOMAIN\sam`` string we resolve
    # against ``ldap_users`` at preproc time to materialise the
    # ``SCCM_HasStoredAccount`` edge.
    reserved_accounts: list[dict[str, Any]] = []
    for item in reserved_accounts_raw:
        username = (item.get("UserName") or "").strip()
        if not username:
            continue
        reserved_accounts.append({
            "account_username": username,
            "item_name": (item.get("ItemName") or "").strip(),
            "item_type": (item.get("ItemType") or "").strip(),
            "site_code": (item.get("SiteCode") or site_code).strip() or site_code,
        })

    return {
        "site_code": site_code,
        "sites": sites_payload,
        "site_definitions": site_definitions,
        "admins": admins,
        "role_members": role_members,
        "collections": collections,
        "collection_members": collection_members,
        "security_roles": security_roles,
        "client_devices": client_devices,
        "task_sequences": task_sequences,
        "collection_variables": collection_variables,
        "site_systems": site_systems,
        "r_system_security_groups": r_system_security_groups,
        "r_user_security_groups": r_user_security_groups,
        "reserved_accounts": reserved_accounts,
    }


@app.resource(name="adminservice_admins", parallelized=False, columns=SCCMAdminUser)
def adminservice_admins(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_Admin entry per reachable SMS Provider.

    Yields the dict shape consumed by ``models/sccm_admin_user.py``. Multiple
    SMS Providers in a hierarchy will produce overlapping rows (CAS sees
    every Primary's admins) — that's expected; convert-side dedup happens
    by id.
    """
    domain = ctx.domain
    for _host, payload in ctx.adminservice_payloads().items():
        for row in payload.get("admins", []):
            yield {**row, "domain": domain}


@app.resource(name="adminservice_collections", parallelized=False, columns=SCCMCollection)
def adminservice_collections(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_Collection entry per reachable SMS Provider, plus
    one phantom-suffix row per CollectionID whose first
    SMS_FullCollectionMembership member carries an empty SiteCode (CMBP
    creates a bare ``<id>@`` node for these — typically user / user-group
    collections — by grouping memberships and using
    ``members[0].SiteCode or ''``).
    """
    domain = ctx.domain
    # Track phantom collections: emit one stub row per (CollectionID) where
    # the first observed member has empty raw SiteCode and we have NOT yet
    # emitted that phantom for that ID.
    phantom_emitted: set[str] = set()

    for _host, payload in ctx.adminservice_payloads().items():
        # Real SMS_Collection entries
        for row in payload.get("collections", []):
            yield {**row, "domain": domain}

        # Phantom rows from SMS_FullCollectionMembership when the first
        # group-member's raw SiteCode is empty. CMBP groups by
        # CollectionID and uses ``members[0].SiteCode`` as the suffix —
        # if that's empty (typical for user-collection types), the node
        # is created with id ``<cid>@``.
        first_raw_by_cid: dict[str, str] = {}
        for row in payload.get("collection_members", []) or []:
            cid = (row.get("collection_id") or "").strip()
            if not cid:
                continue
            if cid in first_raw_by_cid:
                continue
            first_raw_by_cid[cid] = (row.get("raw_site_code") or "").strip()

        for cid, raw_sc in first_raw_by_cid.items():
            if raw_sc:
                # First member already has a real site code — CMBP would
                # produce <cid>@<raw_sc>, then post-processing renames it
                # to the hierarchy root. This is exactly what
                # ``SCCMCollection`` already produces from the
                # ``adminservice_collections`` SMS_Collection row, so
                # nothing more to do here.
                continue
            if cid in phantom_emitted:
                continue
            phantom_emitted.add(cid)
            yield {
                "collection_id": cid,
                "site_code": "",  # bare ``<cid>@`` node id
                "name": None,
                "collection_type": None,
                "member_count": None,
                "limiting_collection_id": None,
                "domain": domain,
                "source": "AdminService-SMS_FullCollectionMembership",
            }


@app.resource(name="adminservice_collection_members", parallelized=False)
def adminservice_collection_members(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_FullCollectionMembership entry per reachable SMS Provider.

    Lookup table only — no Pydantic asset. Phase 4 SQL views consume this for
    SCCM_HasMember edges (collection -> client device).
    """
    domain = ctx.domain
    for _host, payload in ctx.adminservice_payloads().items():
        for row in payload.get("collection_members", []):
            yield {**row, "domain": domain}


@app.resource(name="adminservice_security_roles", parallelized=False, columns=SCCMSecurityRole)
def adminservice_security_roles(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_Role entry per reachable SMS Provider."""
    domain = ctx.domain
    for _host, payload in ctx.adminservice_payloads().items():
        for row in payload.get("security_roles", []):
            yield {**row, "domain": domain}


@app.resource(name="adminservice_role_members", parallelized=False)
def adminservice_role_members(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (admin, role, scope-collection) tuple.

    Lookup table only — no Pydantic asset. Phase 4 SQL views consume this to
    materialise SCCM_FullAdministrator / SCCM_ApplicationAdministrator /
    SCCM_AssignSpecificPermissions derived edges via the
    ``role_assignment_edges`` view.
    """
    domain = ctx.domain
    for _host, payload in ctx.adminservice_payloads().items():
        for row in payload.get("role_members", []):
            yield {**row, "domain": domain}


@app.resource(name="adminservice_client_devices", parallelized=False, columns=SCCMClientDevice)
def adminservice_client_devices(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (de-duped) SCCM client device.

    Two sources combine:

    1. ``SMS_CombinedDeviceResources`` / ``SMS_R_System`` from AdminService
       (the rich, authoritative source — only available to SCCM admins).
    2. LDAP computers carrying the ``CmRcService`` SPN — that SPN is
       registered by the SCCM client agent during installation, so its
       presence on a Computer is a strong signal that the box is an SCCM
       client. CMBP emits a synthesised ``SCCM_ClientDevice`` for every
       such Computer (regardless of AdminService access) so users who
       can't reach AdminService still see the SCCM-managed estate.

    The synthesised rows are skipped when AdminService already supplied
    a row whose ``ad_object_sid`` matches the LDAP Computer SID, so the
    two sources never double-emit the same device.
    """
    domain = ctx.domain
    sid_to_admin_guid: dict[str, str] = {}
    for _host, payload in ctx.adminservice_payloads().items():
        for row in payload.get("client_devices", []):
            sid = (row.get("ad_object_sid") or "").upper()
            if sid and row.get("guid"):
                sid_to_admin_guid.setdefault(sid, row["guid"])
            yield {**row, "domain": domain}

    # Synthesise ClientDevice rows for every LDAP computer carrying the
    # CmRcService SPN. When the SID already has an AdminService device,
    # we re-use the AdminService GUID so the two rows merge at node-emit
    # time but each row still contributes its own SCCM_HasClient edge in
    # the SQL view (matching CMBP, which emits separate edges per
    # discovery path even though the underlying device is one node).
    yield from _synthesised_cmrc_client_devices(ctx, domain, sid_to_admin_guid)


def _synthesised_cmrc_client_devices(
    ctx: "SourceContext",
    domain: str,
    sid_to_admin_guid: dict[str, str],
) -> Iterable[dict[str, Any]]:
    """LDAP-only fallback: emit a SCCM_ClientDevice for every Computer
    whose ``servicePrincipalName`` includes ``CmRcService/...``.

    Matches CMBP's ``_collect_cmrc_service_spns`` behaviour: takes the
    first primary site code found via ``mSSMSSite`` (or the first site
    of any kind, falling back to ``UNKNOWN`` if none) and uses
    ``uuid.uuid5(SID, site_code)`` for a deterministic per-(sid, site)
    GUID — CMBP uses a fresh ``uuid.uuid4()`` per run; we make ours
    stable so the same ZIP is reproducible across collects.
    """
    import uuid

    site_code = _primary_site_code_from_ldap(ctx)
    if not site_code:
        # No SCCM site at all — synthesised devices wouldn't have
        # anywhere to attach to.
        return

    cmrc_namespace = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")  # URL namespace; arbitrary fixed namespace
    try:
        cmrc_results = list(
            ctx.ad.paged_search(
                search_filter="(servicePrincipalName=CmRcService/*)",
                attributes=[
                    "objectSid", "sAMAccountName", "name", "dNSHostName",
                ],
            )
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("ldap CmRcService search failed: %s", exc)
        return

    if not cmrc_results:
        return

    logger.info(
        "ldap CmRcService: found %d SCCM client computer(s) via SPN",
        len(cmrc_results),
    )
    for entry in cmrc_results:
        sid = _coerce_sid(entry.get("object_sid") or entry.get("objectSid"))
        if not sid:
            continue
        sam = (entry.get("sAMAccountName") or "").rstrip("$")
        name = entry.get("name") or sam
        machine_name = (sam or name or "").upper()
        if not machine_name:
            continue
        # Re-use the AdminService GUID for this SID if available so the
        # two rows merge at node-emit time. Otherwise synthesise a new
        # deterministic UUID.
        device_guid = sid_to_admin_guid.get(sid.upper()) or str(
            uuid.uuid5(cmrc_namespace, f"{sid}|{site_code}")
        )
        yield {
            "guid": device_guid,
            "site_code": site_code,
            "machine_name": machine_name,
            "resource_id": None,
            "is_client": True,
            "client_version": None,
            "ad_object_sid": sid,
            "last_logon_user": None,
            "primary_user": None,
            "current_user": None,
            "domain": domain,
            "source": "LDAP-CmRcService",
        }


def _primary_site_code_from_ldap(ctx: "SourceContext") -> Optional[str]:
    """First primary site code from ``mSSMSSite`` System Management container.

    Mirrors CMBP's ``_get_first_primary_site_published_to_ad``: takes the
    first site whose ``mSSMSAssignmentSiteCode`` is non-empty, falling
    back to the first one we see if no primary is flagged.
    """
    try:
        results = list(
            ctx.ad.paged_search(
                search_filter="(objectClass=mSSMSSite)",
                attributes=["mSSMSSiteCode", "mSSMSAssignmentSiteCode", "cn", "name"],
            )
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("ldap mSSMSSite search failed: %s", exc)
        return None
    primary_codes: list[str] = []
    any_codes: list[str] = []
    for entry in results:
        site_code = entry.get("mSSMSSiteCode") or entry.get("cn") or entry.get("name")
        if isinstance(site_code, list):
            site_code = site_code[0] if site_code else None
        if not site_code:
            continue
        any_codes.append(site_code)
        if entry.get("mSSMSAssignmentSiteCode"):
            primary_codes.append(site_code)
    if primary_codes:
        return primary_codes[0]
    if any_codes:
        return any_codes[0]
    return None


def _coerce_sid(sid_value: Any) -> Optional[str]:
    if sid_value is None:
        return None
    if isinstance(sid_value, list):
        sid_value = sid_value[0] if sid_value else None
        if sid_value is None:
            return None
    if isinstance(sid_value, bytes):
        try:
            from impacket.ldap.ldaptypes import LDAP_SID
            sid = LDAP_SID()
            sid.fromString(sid_value)
            return sid.formatCanonical()
        except Exception:  # noqa: BLE001
            return None
    return str(sid_value)


@app.resource(name="adminservice_task_sequences", parallelized=False)
def adminservice_task_sequences(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_TaskSequencePackage entry. Phase 4 wires these into
    SCCM_HasTaskSequence edges + SCCM_Secret nodes."""
    domain = ctx.domain
    for _host, payload in ctx.adminservice_payloads().items():
        for row in payload.get("task_sequences", []):
            yield {**row, "domain": domain}


@app.resource(name="adminservice_collection_variables", parallelized=False)
def adminservice_collection_variables(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_CollectionVariable entry. Phase 4 emits
    SCCM_HasCollectionVar edges and SCCM_Secret nodes for ``IsMasked=True``
    rows."""
    domain = ctx.domain
    for _host, payload in ctx.adminservice_payloads().items():
        for row in payload.get("collection_variables", []):
            yield {**row, "domain": domain}


@app.resource(name="adminservice_r_system_security_groups", parallelized=False)
def adminservice_r_system_security_groups(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (computer_name, security_group_name) pair from SMS_R_System.

    Lookup table only — Phase 6 SQL view ``r_system_member_of_edges``
    consumes this to emit Computer -> Group MemberOf edges that LDAP-side
    enumeration may have missed (e.g. members enumerated via WMI but not
    present in the LDAP ``member`` multi-valued attribute).
    """
    domain = ctx.domain
    for _host, payload in ctx.adminservice_payloads().items():
        for row in payload.get("r_system_security_groups", []):
            yield {**row, "domain": domain}


@app.resource(name="adminservice_r_user_security_groups", parallelized=False)
def adminservice_r_user_security_groups(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (user_sid, security_group_name) pair from SMS_R_User.

    Lookup table only — Phase 6 SQL view ``r_user_member_of_edges``
    consumes this to emit User -> Group MemberOf edges that LDAP-side
    group enumeration didn't surface (e.g. nested-group memberships via
    SCCM's user-collection sync, or foreign-domain users discovered by
    SMS_R_User but not the LDAP ``member`` walk).
    """
    domain = ctx.domain
    for _host, payload in ctx.adminservice_payloads().items():
        for row in payload.get("r_user_security_groups", []):
            yield {**row, "domain": domain}


@app.resource(name="adminservice_site_systems", parallelized=False)
def adminservice_site_systems(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per (hostname, role, site_code) tuple from SMS_SCI_SysResUse.
    Phase 4's ``LocalAdminRequired`` SQL view consumes this so that
    co-located site systems get the correct admin-required edges from the
    primary site server."""
    domain = ctx.domain
    for _host, payload in ctx.adminservice_payloads().items():
        for row in payload.get("site_systems", []):
            yield {**row, "domain": domain}


@app.resource(name="adminservice_reserved_accounts", parallelized=False)
def adminservice_reserved_accounts(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One row per SMS_SCI_Reserved entry that carries a ``UserName``.

    SMS_SCI_Reserved is the SCCM site-control-image table holding stored
    account credentials (Network Access Accounts, push install accounts,
    content access accounts, etc.). CMBP emits a ``SCCM_HasStoredAccount``
    edge from the ``SCCM_Site`` to each resolved User, plus a
    ``storedInSCCMSite`` property on the User node. We materialise
    one row per (site_code, account_username) here and the SQL view
    ``has_stored_account_edges`` joins against ``ldap_users`` to resolve
    the SID at preproc time.
    """
    domain = ctx.domain
    for _host, payload in ctx.adminservice_payloads().items():
        for row in payload.get("reserved_accounts", []):
            yield {**row, "domain": domain}


# ---------------------------------------------------------------------------
# Phase 3c — WMI / HTTP / SMB per-host enrichment.
# ---------------------------------------------------------------------------
# These resources enrich existing Computer / SCCM_ClientDevice nodes with
# additional properties (current user, PrimaryUser, SQL service account, MP
# / DP / SMS Provider role flags, SMB signing). They do NOT introduce new
# node kinds — Phase 4 SQL views consume the new tables to derive edges
# (HasSession, MSSQL_ServiceAccountFor, CoerceAndRelayToSMB, etc.).
#
# WMI uses impacket's DCOM bindings; HTTP shells out to ``curl.exe`` for the
# same Python-3.14 OPENSSL_Uplink reasons documented for AdminService (see
# Risk 8 in HANDOFF). SMB uses impacket's ``SMBConnection`` plus a bespoke
# raw SMB2 negotiate for signing detection.
#
# CMBP references:
#   - ``lib/collectors/wmi_collector.py``  (~1,549 LOC) - mostly mirrors
#     AdminService; here we only add the gap-filler queries (CCM_Client,
#     CCM_UsersSeenOnSystem, Win32_Service for the SQL service account).
#   - ``lib/collectors/http_collector.py`` (~560 LOC) - role fingerprinting.
#   - ``lib/collectors/smb_collector.py``  (~939 LOC) - share enum + SMB2
#     negotiate signing probe.
#
# CRED-2/3/5/6 attack flows are intentionally STUBBED here. Phase 4 secret
# policy edges cope with empty NAA / collection-secret tables.

# ---- WMI helper -----------------------------------------------------------

def _wmi_query(
    hostname: str,
    namespace: str,
    wql: str,
    domain: str,
    username: Optional[str],
    password: Optional[str],
) -> Optional[list[dict[str, Any]]]:
    """Run a single WQL query against ``hostname\\namespace`` and return rows.

    Returns ``None`` if the connection fails (port closed / auth denied / WMI
    namespace unavailable). Returns an empty list if the namespace responded
    but the query yielded no rows. Hosts the ``with`` boilerplate so callers
    don't have to manage DCOM lifecycle.

    Defers all impacket imports until first use - same OPENSSL_Uplink
    avoidance pattern used elsewhere.
    """
    # Fast TCP probe to skip dead hosts cheaply (DCOM uses 135).
    try:
        with socket.create_connection((hostname, 135), timeout=3):
            pass
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug("wmi: %s:135 unreachable: %s", hostname, e)
        return None

    try:
        from impacket.dcerpc.v5.dcom import wmi as impacket_wmi
        from impacket.dcerpc.v5.dcomrt import DCOMConnection
        from impacket.dcerpc.v5.dtypes import NULL
    except ImportError:
        logger.warning("wmi: impacket DCOM bindings unavailable, skipping host %s", hostname)
        return None

    auth_domain, user = _split_user_domain(username, domain)
    if not user or not password:
        logger.debug("wmi: no explicit creds for %s, skipping (Negotiate not supported by impacket-DCOM)", hostname)
        return None

    dcom = None
    try:
        dcom = DCOMConnection(hostname, username=user, password=password, domain=auth_domain)
        iInterface = dcom.CoCreateInstanceEx(
            impacket_wmi.CLSID_WbemLevel1Login,
            impacket_wmi.IID_IWbemLevel1Login,
        )
        iWbemLevel1Login = impacket_wmi.IWbemLevel1Login(iInterface)
        services = iWbemLevel1Login.NTLMLogin(namespace, NULL, NULL)
        iWbemLevel1Login.RemRelease()
    except Exception as e:  # noqa: BLE001
        logger.debug("wmi: connect to %s namespace %s failed: %s", hostname, namespace, e)
        if dcom is not None:
            try:
                dcom.disconnect()
            except Exception:
                pass
        return None

    rows: list[dict[str, Any]] = []
    try:
        enum = services.ExecQuery(wql)
    except Exception as e:  # noqa: BLE001
        logger.debug("wmi: query failed on %s [%s]: %s", hostname, wql[:80], e)
        try:
            dcom.disconnect()
        except Exception:
            pass
        return None

    try:
        while True:
            try:
                objects = enum.Next(0xFFFFFFFF, 1)
            except Exception:
                break
            if not objects:
                break
            for obj in objects:
                try:
                    props = obj.getProperties()
                    rows.append({k: v.get("value") for k, v in props.items()})
                except Exception as e:  # noqa: BLE001
                    logger.debug("wmi: property parse failed on %s: %s", hostname, e)
    finally:
        try:
            dcom.disconnect()
        except Exception:
            pass
    return rows


def _adminservice_hosts_seen(ctx: "SourceContext") -> set[str]:
    """Return the set of hostnames for which AdminService already produced data.

    WMI fallback is only run for hosts whose AdminService payload was empty.
    """
    payloads = ctx.adminservice_payloads()
    seen: set[str] = set()
    for _provider, payload in payloads.items():
        for dev in payload.get("client_devices", []):
            host = (dev.get("hostname") or "").lower()
            if host:
                seen.add(host)
        for ss in payload.get("site_systems", []):
            host = (ss.get("hostname") or "").lower()
            if host:
                seen.add(host)
    return seen


@app.resource(name="wmi_clients", parallelized=False)
def wmi_clients(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Per-host CCM_Client properties via WMI fallback.

    Yields one row per AD computer that responds to a ``SELECT * FROM
    CCM_Client`` query in the ``root\\ccm`` namespace. Skipped silently for
    hosts where AdminService already returned a client-device row, since the
    WMI data is a strict subset.

    CMBP reference: ``wmi_collector.py`` (gap-filler client enumeration).
    """
    if not ctx.method_enabled("WMI"):
        logger.info("wmi_clients: disabled via --collection-methods")
        return
    seen = _adminservice_hosts_seen(ctx)
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        if hostname in seen:
            continue
        rows = _wmi_query(
            hostname=hostname,
            namespace="root\\ccm",
            wql="SELECT ClientId, ClientVersion, AllowLocalAdminOverride FROM CCM_Client",
            domain=ctx.domain,
            username=ctx.username,
            password=ctx.password,
        )
        if not rows:
            continue
        for r in rows:
            client_id = (r.get("ClientId") or "").strip()
            if not client_id:
                continue
            yield {
                "hostname": hostname,
                "client_id": client_id,
                "client_version": (r.get("ClientVersion") or "").strip(),
                "allow_local_admin_override": bool(r.get("AllowLocalAdminOverride")),
                "computer_sid": host.get("sid"),
                "source": "WMI-CCM_Client",
                "domain": ctx.domain,
            }


@app.resource(name="wmi_users_seen", parallelized=False)
def wmi_users_seen(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per (host, user) pair from CCM_UsersSeenOnSystem.

    Drives Phase 4's ``SCCM_HasADLastLogonUser`` / ``SCCM_HasCurrentUser``
    edge generation. Only run for hosts where AdminService didn't already
    provide a primary/last-logon user.

    CMBP reference: ``wmi_collector.py::_get_combined_device_resources_via_wmi``.
    """
    if not ctx.method_enabled("WMI"):
        return
    seen = _adminservice_hosts_seen(ctx)
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        if hostname in seen:
            continue
        rows = _wmi_query(
            hostname=hostname,
            namespace="root\\ccm",
            wql="SELECT UserName, LastSeen FROM CCM_UsersSeenOnSystem",
            domain=ctx.domain,
            username=ctx.username,
            password=ctx.password,
        )
        if not rows:
            continue
        for r in rows:
            user_name = (r.get("UserName") or "").strip()
            if not user_name:
                continue
            yield {
                "hostname": hostname,
                "user_name": user_name,
                "last_seen": r.get("LastSeen"),
                "computer_sid": host.get("sid"),
                "source": "WMI-CCM_UsersSeenOnSystem",
                "domain": ctx.domain,
            }


@app.resource(name="wmi_sql_service_accounts", parallelized=False)
def wmi_sql_service_accounts(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per SQL Server service account discovered via Win32_Service.

    Phase 4 uses this to materialise ``MSSQL_ServiceAccountFor``,
    ``MSSQL_GetTGS``, and ``HasSession`` edges.

    Only queries hosts that responded to the MSSQL EPA TDS PRELOGIN probe -
    most computers don't run a SQL service so the WMI call would be wasted.
    """
    if not ctx.method_enabled("WMI"):
        return

    # Build a quick set of hosts that look like SQL servers based on the
    # Phase 3a TDS PRELOGIN probe. We can't read the DLT-collected JSONL at
    # this point in the source pipeline, so we re-probe the LDAP computers
    # directly. Cheap (TCP connect) and parallel-safe enough.
    sql_hosts: list[dict[str, Any]] = []
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        epa = _probe_mssql_epa(hostname, 1433)
        if epa is not None:
            sql_hosts.append(host)

    for host in sql_hosts:
        hostname = host["hostname"]
        rows = _wmi_query(
            hostname=hostname,
            namespace="root\\cimv2",
            wql="SELECT Name, StartName, PathName FROM Win32_Service WHERE Name='MSSQLSERVER' OR Name LIKE 'MSSQL$%'",
            domain=ctx.domain,
            username=ctx.username,
            password=ctx.password,
        )
        if not rows:
            continue
        for r in rows:
            service_name = (r.get("Name") or "").strip()
            start_name = (r.get("StartName") or "").strip()
            if not service_name or not start_name:
                continue
            yield {
                "hostname": hostname,
                "service_name": service_name,
                "service_account": start_name,
                "path_name": (r.get("PathName") or "").strip(),
                "computer_sid": host.get("sid"),
                "source": "WMI-Win32_Service",
                "domain": ctx.domain,
            }


# ---- HTTP fingerprinting (curl-based for TLS) -----------------------------

def _curl_probe(url: str, timeout: int = 5) -> Optional[dict[str, Any]]:
    """Send a HEAD-then-GET probe via ``curl.exe`` and return status + headers.

    Returns ``None`` on TCP / curl failure. Returns a dict ``{status,
    server, headers, body}`` for HTTP 200 / 401 / 403 (those imply the
    endpoint exists, even when authentication is required).

    Reuses the AdminService client's ``_resolve_curl()`` helper indirectly
    through that module's ``_CURL_PATH`` constant.
    """
    from .clients.adminservice import _CURL_PATH

    if not _CURL_PATH:
        logger.debug("http: curl.exe not available")
        return None

    args = [
        _CURL_PATH,
        "--silent", "--show-error",
        "--max-time", str(timeout),
        "--connect-timeout", "3",
        "--insecure",
        "-D", "-",  # dump headers to stdout
        "-o", "-",  # body to stdout (mixed with headers via -D -)
        "-w", "\n__HTTP_STATUS__:%{http_code}",
        url,
    ]
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout + 5,
            check=False,
        )
    except Exception as exc:  # noqa: BLE001
        logger.debug("http: curl spawn failed for %s: %s", url, exc)
        return None

    stdout = result.stdout or ""
    marker = "__HTTP_STATUS__:"
    idx = stdout.rfind("\n" + marker)
    if idx >= 0:
        body_and_headers = stdout[:idx]
        status = stdout[idx + len(marker) + 1:].strip()
    else:
        body_and_headers = stdout
        status = "0"
    try:
        status_code = int(status)
    except (TypeError, ValueError):
        status_code = 0

    if result.returncode != 0 and status_code == 0:
        return None

    # Split headers from body. curl -D - prepends headers; the first blank
    # line separates them from the body. Multiple "HTTP/x" status lines may
    # appear if redirects occurred — keep only the last header block.
    parts = re.split(r"\r?\n\r?\n", body_and_headers, maxsplit=1)
    headers_block = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    server_header: Optional[str] = None
    headers: dict[str, str] = {}
    for line in headers_block.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
            if k.strip().lower() == "server":
                server_header = v.strip()

    return {
        "status": status_code,
        "server": server_header,
        "headers": headers,
        "body": body,
    }


_HTTP_MP_PATHS = (
    ("/SMS_MP/.sms_aut?MPLOCATION", "MP_LOCATION"),
    ("/SMS_MP/.sms_aut?MPCERT", "MP_CERT"),
    ("/sms_mp/.sms_aut?mplist", "MPLIST"),
)
_HTTP_DP_PATHS = (
    ("/SMS_DP_SMSPKG$/Datalib/", "DP_DATALIB"),
    ("/SMS_DP_SMSPKG$/", "DP_PKG"),
)
_HTTP_SMS_PROVIDER_PATHS = (
    ("/AdminService/wmi/", "ADMINSERVICE_WMI"),
)


@app.resource(name="http_management_points", parallelized=False)
def http_management_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per Management Point discovered via HTTP probing.

    Probes each host's ``/SMS_MP/.sms_aut?MPLOCATION`` etc. on HTTP and
    HTTPS. A 200/401/403 response indicates the path is served (the latter
    two mean the role exists but the request needs auth).

    CMBP reference: ``http_collector.py``.
    """
    if not ctx.method_enabled("HTTP"):
        logger.info("http_management_points: disabled via --collection-methods")
        return
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        for scheme in ("https", "http"):
            port = 443 if scheme == "https" else 80
            try:
                with socket.create_connection((hostname, port), timeout=3):
                    pass
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue
            for path, desc in _HTTP_MP_PATHS:
                url = f"{scheme}://{hostname}{path}"
                resp = _curl_probe(url)
                if not resp:
                    continue
                status = resp.get("status") or 0
                if status not in (200, 401, 403):
                    continue
                yield {
                    "hostname": hostname,
                    "mp_url": url,
                    "scheme": scheme,
                    "path": path,
                    "status": status,
                    "server_header": resp.get("server"),
                    "endpoint_desc": desc,
                    "computer_sid": host.get("sid"),
                    "source": f"HTTP-{desc}",
                    "domain": ctx.domain,
                }
                # First successful path on this scheme is enough; move on
                break


@app.resource(name="http_smsproviders", parallelized=False)
def http_smsproviders(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per SMS Provider role discovered via HTTPS AdminService probe.

    Hits ``https://<host>/AdminService/wmi/``. A 200/401/403 indicates the
    role is present even if creds aren't sufficient. Complements
    ``adminservice_admins`` which only fires when creds *are* sufficient.
    """
    if not ctx.method_enabled("HTTP"):
        return
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        try:
            with socket.create_connection((hostname, 443), timeout=3):
                pass
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
        for path, desc in _HTTP_SMS_PROVIDER_PATHS:
            url = f"https://{hostname}{path}"
            resp = _curl_probe(url)
            if not resp:
                continue
            status = resp.get("status") or 0
            if status not in (200, 401, 403):
                continue
            yield {
                "hostname": hostname,
                "provider_url": url,
                "status": status,
                "server_header": resp.get("server"),
                "endpoint_desc": desc,
                "computer_sid": host.get("sid"),
                "source": f"HTTP-{desc}",
                "domain": ctx.domain,
            }


@app.resource(name="http_distribution_points", parallelized=False)
def http_distribution_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per Distribution Point discovered via HTTP probing.

    Hits ``/SMS_DP_SMSPKG$/Datalib/`` and ``/SMS_DP_SMSPKG$/`` over both
    schemes.
    """
    if not ctx.method_enabled("HTTP"):
        return
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        for scheme in ("https", "http"):
            port = 443 if scheme == "https" else 80
            try:
                with socket.create_connection((hostname, port), timeout=3):
                    pass
            except (socket.timeout, ConnectionRefusedError, OSError):
                continue
            for path, desc in _HTTP_DP_PATHS:
                url = f"{scheme}://{hostname}{path}"
                resp = _curl_probe(url)
                if not resp:
                    continue
                status = resp.get("status") or 0
                if status not in (200, 401, 403):
                    continue
                yield {
                    "hostname": hostname,
                    "dp_url": url,
                    "scheme": scheme,
                    "path": path,
                    "status": status,
                    "server_header": resp.get("server"),
                    "endpoint_desc": desc,
                    "computer_sid": host.get("sid"),
                    "source": f"HTTP-{desc}",
                    "domain": ctx.domain,
                }
                break


@app.resource(name="http_naa_secrets", parallelized=False)
def http_naa_secrets(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """STUB: CRED-3 NAA secret extraction via authenticated MP HTTP API.

    Real flow requires the SCCMPolicyClient client-registration handshake
    (see ``clients/sccm.py``). Phase 4 secret-policy edges cope with the
    empty table; this resource is wired so the table appears when collected
    with secret extraction enabled in a future iteration.
    """
    return
    yield  # type: ignore[unreachable]


@app.resource(name="http_collection_secrets", parallelized=False)
def http_collection_secrets(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """STUB: CRED-5 collection-variable secret extraction.

    Same pattern as ``http_naa_secrets`` — needs an authenticated client
    registration. Empty rows here; Phase 4 SQL views will produce zero
    secret-policy edges, which matches the lab baseline.
    """
    return
    yield  # type: ignore[unreachable]


# ---- SMB enumeration ------------------------------------------------------


def _smb_check_signing(hostname: str, port: int = 445, timeout: float = 5.0) -> Optional[bool]:
    """Detect SMB signing-required via impacket SMB negotiate handshake.

    Returns ``True`` if signing is required, ``False`` if not, ``None`` if
    the probe failed. Uses impacket's ``SMBConnection`` to perform a full
    negotiate (handles SMB1->SMB3 upgrade automatically) — modern Windows
    boxes negotiate SMB 3.x and the raw SMB2 negotiate path in CMBP can
    miss the signing flag for them.
    """
    try:
        sock = socket.create_connection((hostname, port), timeout=timeout)
        sock.close()
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        logger.debug("smb_signing: %s:%d unreachable: %s", hostname, port, e)
        return None

    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        logger.warning("smb_signing: impacket unavailable, skipping %s", hostname)
        return None

    try:
        conn = SMBConnection(hostname, hostname, timeout=int(timeout))
        try:
            # impacket exposes signing-required as ``isSigningRequired()``.
            signing_required = bool(conn.isSigningRequired())
            return signing_required
        finally:
            try:
                conn.close()
            except Exception:
                pass
    except Exception as e:  # noqa: BLE001
        logger.debug("smb_signing: probe failed for %s: %s", hostname, e)
        return None


def _smb_list_shares(
    hostname: str,
    domain: str,
    username: Optional[str],
    password: Optional[str],
    timeout: int = 5,
) -> Optional[list[dict[str, str]]]:
    """List SMB shares on ``hostname``. Returns None on connect/auth failure.

    Direct port of ``smb_collector._enumerate_shares`` minus the GraphStore
    side-effects.
    """
    try:
        from impacket.smbconnection import SMBConnection
    except ImportError:
        logger.warning("smb: impacket unavailable, skipping share enumeration on %s", hostname)
        return None

    auth_domain, user = _split_user_domain(username, domain)

    try:
        conn = SMBConnection(hostname, hostname, timeout=timeout)
        if user and password:
            conn.login(user, password, auth_domain)
        else:
            try:
                conn.login("", "", auth_domain)
            except Exception:
                return None
    except Exception as e:  # noqa: BLE001
        logger.debug("smb: login to %s failed: %s", hostname, e)
        return None

    rows: list[dict[str, str]] = []
    try:
        shares = conn.listShares()
        for share in shares:
            try:
                name = share["shi1_netname"][:-1]
            except Exception:
                name = str(getattr(share, "shi1_netname", "")).rstrip("\x00")
            try:
                comment = share["shi1_remark"][:-1]
            except Exception:
                comment = str(getattr(share, "shi1_remark", "")).rstrip("\x00")
            if isinstance(comment, bytes):
                comment = comment.decode("utf-8", errors="ignore")
            rows.append({"name": str(name), "comment": str(comment)})
    except Exception as e:  # noqa: BLE001
        logger.debug("smb: listShares on %s failed: %s", hostname, e)
        rows = []
    finally:
        try:
            conn.logoff()
        except Exception:
            pass
    return rows


_SMB_SITE_SHARES = {"SMS_SITE", "SMS_DP$", "SCCMContentLib$", "REMINST"}


@app.resource(name="smb_site_servers", parallelized=False)
def smb_site_servers(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per (hostname, role, site_code) discovered via SMB share enum.

    A site server presents an ``SMS_SITE`` or ``SMS_<sitecode>`` share with a
    ``"SMS Site <code>"`` comment. The site_code is parsed out of the
    comment when present.
    """
    if not ctx.method_enabled("SMB"):
        logger.info("smb_site_servers: disabled via --collection-methods")
        return
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        shares = ctx.smb_shares(hostname)
        if shares is None:
            continue
        is_site_server = False
        site_code: Optional[str] = None
        for s in shares:
            name = s["name"] or ""
            comment = s["comment"] or ""
            m = re.match(r"^SMS_(\w{3})$", name)
            if name == "SMS_SITE" or m:
                is_site_server = True
                cm = re.search(r"SMS Site (\w{3})", comment)
                if cm:
                    site_code = cm.group(1)
                elif m:
                    site_code = m.group(1)
        if not is_site_server:
            continue
        yield {
            "hostname": hostname,
            "role": "SMS Site Server",
            "site_code": site_code or "",
            "computer_sid": host.get("sid"),
            "source": "SMB-SMS_SITE",
            "domain": ctx.domain,
        }


@app.resource(name="smb_distribution_points", parallelized=False)
def smb_distribution_points(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per Distribution Point discovered via SMB share enum.

    DP indicators: ``SMS_DP$``, ``SCCMContentLib$``, ``REMINST`` (PXE).
    """
    if not ctx.method_enabled("SMB"):
        return
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        shares = ctx.smb_shares(hostname)
        if shares is None:
            continue
        share_names = {s.get("name", "") for s in shares}
        is_dp = bool(share_names & {"SMS_DP$", "SCCMContentLib$"})
        is_pxe = "REMINST" in share_names
        if not (is_dp or is_pxe):
            continue
        site_code = ""
        for s in shares:
            cm = re.search(r"SMS Site (\w{3})", s.get("comment") or "")
            if cm:
                site_code = cm.group(1)
                break
        yield {
            "hostname": hostname,
            "dp_role": "Distribution Point",
            "is_pxe_enabled": is_pxe,
            "hosts_content_library": "SCCMContentLib$" in share_names or "SMS_DP$" in share_names,
            "site_code": site_code,
            "computer_sid": host.get("sid"),
            "source": "SMB-DP",
            "domain": ctx.domain,
        }


@app.resource(name="smb_signing_status", parallelized=False)
def smb_signing_status(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per host indicating whether SMB signing is required.

    Critical for Phase 4's ``CoerceAndRelayToSMB`` derived-edge generation.
    A host with ``signing_required=False`` and which is *not* the relay
    initiator is a candidate for the relay attack.

    Two probes per host, in order:

      1. SMB negotiate handshake against TCP/445 (impacket
         ``SMBConnection.isSigningRequired``). Fast and always usable.
      2. Remote registry read of
         ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters
         ::RequireSecuritySignature`` REG_DWORD. CMBP collects this value
         in ``registry_collector._read_smb_signing`` and uses it whenever
         the SMB-negotiate path would have failed (e.g. for passive
         failover hosts where 445 is firewalled but RPC over 135/445 still
         works for registry). Without this fallback OH misses
         CoerceAndRelayToSMB candidates like ``ps1-psv`` (the PS1 passive
         site server).
    """
    if not ctx.method_enabled("SMB"):
        return
    for host in ctx.ldap_computer_hosts():
        hostname = host["hostname"]
        signing = _smb_check_signing(hostname)
        source = "SMB-Negotiate"
        if signing is None:
            # Registry fallback (CMBP parity)
            with _RegistryProbe(hostname, ctx.domain, ctx.username, ctx.password) as probe:
                if probe is not None:
                    val = probe.read_dword(
                        r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters",
                        "RequireSecuritySignature",
                    )
                    if val is not None:
                        signing = val == 1
                        source = "RemoteRegistry-SMBSigning"
        if signing is None:
            continue
        yield {
            "hostname": hostname,
            "signing_required": signing,
            "computer_sid": host.get("sid"),
            "source": source,
            "domain": ctx.domain,
        }


# ---------------------------------------------------------------------------
# Phase 4 — derived-edges trigger.
# ---------------------------------------------------------------------------
#
# The 11 derived edge SQL views materialised in ``transforms.py`` are read at
# convert time by ``models/derived/aggregator.py::DerivedEdges``. That model
# only fires when its bound DLT resource yields at least one row, so we add a
# tiny trigger resource that emits a single sentinel row at collect time. The
# row's value doesn't matter — the model opens its own DuckDB connection via
# ``self._lookup.client``.
#
# Yielding a single row also keeps ``Converter.run``'s
# ``source_object.resources.values()`` discovery happy: it binds DerivedEdges
# to the ``derived_edges`` table by matching ``columns=DerivedEdges``.

@app.resource(name="derived_edges", parallelized=False, columns=DerivedEdges)
def derived_edges(_ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """One sentinel row to trigger the DerivedEdges aggregator at convert time."""
    yield {"trigger": "derived_edges"}


# ---------------------------------------------------------------------------
# Phase 6 — derived MSSQL principal nodes (synthesised at collect time).
# ---------------------------------------------------------------------------
#
# The Phase 4 ``mssql_sysadmin_edges`` SQL view emits edge endpoints for
# MSSQL_Login / MSSQL_DatabaseUser / MSSQL_DatabaseRole / MSSQL_ServerRole /
# MSSQL_Database principals that don't have their own collected tables. Until
# this resource existed those nodes were stub-on-first-reference inside
# BloodHound — graphically valid but property-poor.
#
# We replicate the same fan-out logic in Python here, using the cached
# ``ctx.adminservice_payloads()`` (site_systems) plus ``ctx.ldap_computer_hosts()``
# (computer SID/SAM) — the same inputs the SQL view consumes. Each yielded row
# carries one synthesised node and is bound to the ``DerivedNode`` model.

_SECONDARY_ROLES = {"sms site server", "sms provider", "sms sql server", "sms management point", "sms distribution point"}


def _classify_site_type(roles: set[str]) -> str:
    """Match the ``sccm.site_types`` view heuristic.

    CAS         = SiteServer + Provider + no MP
    Primary     = SiteServer + Provider + MP
    Secondary   = SiteServer + MP + no Provider
    Other       = anything else
    """
    has_ss = "sms site server" in roles
    has_mp = "sms management point" in roles
    has_prov = "sms provider" in roles
    if has_ss and has_prov and not has_mp:
        return "CAS"
    if has_ss and has_prov and has_mp:
        return "Primary"
    if has_ss and has_mp and not has_prov:
        return "Secondary"
    return "Other"


@app.resource(name="derived_nodes", parallelized=False, columns=DerivedNode)
def derived_nodes(ctx: "SourceContext") -> Iterable[dict[str, Any]]:
    """Yield one row per synthesised MSSQL principal node.

    Mirrors the SQL view ``sccm.mssql_sysadmin_edges`` but in Python so the
    rows can be written to JSONL at collect time and consumed by the
    ``DerivedNode`` model at convert time.

    The fan-out for each (sysadmin Computer, site DB Computer) tuple at the
    same site emits five node kinds:

      * MSSQL_Login        ``<DOMAIN>\\<sam>@<dbhost>:1433``
      * MSSQL_DatabaseUser ``<DOMAIN>\\<sam>@<dbhost>:1433\\CM_<site>``
      * MSSQL_Database     ``<dbhost>:1433\\CM_<site>``
      * MSSQL_ServerRole   ``sysadmin@<dbhost>:1433`` (one per server)
      * MSSQL_DatabaseRole ``db_owner@<dbhost>:1433\\CM_<site>`` (one per db)

    Per-server / per-database role nodes are deduped so we emit one
    ``sysadmin@server`` and one ``db_owner@server\\db`` regardless of how
    many sysadmin computers are present.
    """
    payloads = ctx.adminservice_payloads()
    if not payloads:
        return

    # Build site -> set(role) mapping for the site_types classification.
    site_roles: dict[str, set[str]] = {}
    site_systems_rows: list[dict[str, Any]] = []
    for payload in payloads.values():
        for ss in payload.get("site_systems", []):
            site = (ss.get("site_code") or "").strip()
            role = (ss.get("role") or "").strip().lower()
            host = (ss.get("hostname") or "").strip().lower()
            if not site or not role or not host:
                continue
            site_roles.setdefault(site, set()).add(role)
            site_systems_rows.append({"site": site, "role": role, "hostname": host})

    site_types = {site: _classify_site_type(roles) for site, roles in site_roles.items()}

    # Index ldap_computer_hosts by hostname / sam for fast lookup.
    ldap_by_host: dict[str, dict[str, Any]] = {}
    ldap_by_sam: dict[str, dict[str, Any]] = {}
    for h in ctx.ldap_computer_hosts():
        host = (h.get("hostname") or "").lower()
        sam = (h.get("sam") or "").rstrip("$").lower()
        if host:
            ldap_by_host[host] = h
        if sam:
            ldap_by_sam[sam] = h

    def _resolve_computer(hostname: str) -> Optional[dict[str, Any]]:
        """Mirror the SQL JOIN on dns_host_name / sam / name."""
        h = (hostname or "").lower()
        if not h:
            return None
        if h in ldap_by_host:
            return ldap_by_host[h]
        short = h.split(".", 1)[0]
        if short in ldap_by_sam:
            return ldap_by_sam[short]
        return None

    # Site DBs (one per site, role = SMS SQL Server)
    site_dbs: dict[str, str] = {}
    for ss in site_systems_rows:
        if ss["role"] == "sms sql server":
            site_dbs.setdefault(ss["site"], ss["hostname"])

    # Sysadmins (Site Server + SMS Provider on non-Secondary sites)
    sysadmins: list[tuple[str, str, dict[str, Any]]] = []  # (site, hostname, ldap_row)
    for ss in site_systems_rows:
        site = ss["site"]
        if site_types.get(site) == "Secondary":
            continue
        if ss["role"] not in ("sms site server", "sms provider"):
            continue
        ldap_row = _resolve_computer(ss["hostname"])
        if not ldap_row or not ldap_row.get("sid"):
            continue
        sysadmins.append((site, ss["hostname"], ldap_row))

    # Track emitted server/db roles + databases to avoid duplicate yields.
    emitted_logins: set[str] = set()
    emitted_db_users: set[str] = set()
    emitted_databases: set[str] = set()
    emitted_server_roles: set[str] = set()
    emitted_db_roles: set[str] = set()

    domain_short = (ctx.domain or "").split(".")[0].lower()

    # ---- Per-(server,site) structural fan-out -----------------------------
    # For every site that has an 'SMS SQL Server' role row, emit the
    # MSSQL_Database / MSSQL_ServerRole sysadmin / MSSQL_DatabaseRole db_owner
    # nodes that anchor the per-server structural edges built by
    # ``transforms._build_mssql_server_hierarchy_edges``. This fires for ALL
    # sites with a SQL server, including Secondary sites — CMBP's check at
    # ``mssql_collector.py:373`` is a string compare against "Secondary Site"
    # that never matches the integer siteType=1 form, so CMBP emits the full
    # hierarchy for Secondary sites too. The sysadmin-fan-out below (logins
    # and db users) still excludes Secondary because there's no separate
    # sysadmin Computer to fan out from.
    for site, db_host in site_dbs.items():
        if not db_host:
            continue
        server_id = f"{db_host}:1433"
        database_id = f"{server_id}\\CM_{site}"
        sysadmin_role_id = f"sysadmin@{server_id}"
        db_owner_role_id = f"db_owner@{database_id}"

        if database_id not in emitted_databases:
            emitted_databases.add(database_id)
            yield {
                "kind": "MSSQL_Database",
                "node_id": database_id,
                "name": f"CM_{site}",
                "displayname": f"CM_{site}",
                "server": db_host,
                "database": f"CM_{site}",
                "site_code": site,
                "domain": ctx.domain,
                "sccm_infra": True,
            }

        if sysadmin_role_id not in emitted_server_roles:
            emitted_server_roles.add(sysadmin_role_id)
            yield {
                "kind": "MSSQL_ServerRole",
                "node_id": sysadmin_role_id,
                "name": "sysadmin",
                "displayname": "sysadmin",
                "server": db_host,
                "site_code": site,
                "domain": ctx.domain,
                "is_fixed_role": True,
                "sccm_infra": True,
            }

        if db_owner_role_id not in emitted_db_roles:
            emitted_db_roles.add(db_owner_role_id)
            yield {
                "kind": "MSSQL_DatabaseRole",
                "node_id": db_owner_role_id,
                "name": "db_owner",
                "displayname": "db_owner",
                "server": db_host,
                "database": f"CM_{site}",
                "site_code": site,
                "domain": ctx.domain,
                "is_fixed_role": True,
                "sccm_infra": True,
            }

    for site, _sa_host, sa in sysadmins:
        db_host = site_dbs.get(site)
        if not db_host or db_host == _sa_host:
            continue
        sam = (sa.get("sam") or "").rstrip("$").lower()
        if not sam:
            continue
        login_str = f"{domain_short}\\{sam}"
        server_id = f"{db_host}:1433"
        database_id = f"{server_id}\\CM_{site}"
        login_id = f"{login_str}@{server_id}"
        db_user_id = f"{login_str}@{database_id}"
        sysadmin_role_id = f"sysadmin@{server_id}"
        db_owner_role_id = f"db_owner@{database_id}"

        # MSSQL_Login
        if login_id not in emitted_logins:
            emitted_logins.add(login_id)
            yield {
                "kind": "MSSQL_Login",
                "node_id": login_id,
                "name": login_id,
                "displayname": login_str,
                "server": db_host,
                "login": login_str,
                "site_code": site,
                "domain": ctx.domain,
                "sccm_infra": True,
                "member_of_roles": ["sysadmin"],
            }

        # MSSQL_DatabaseUser
        if db_user_id not in emitted_db_users:
            emitted_db_users.add(db_user_id)
            yield {
                "kind": "MSSQL_DatabaseUser",
                "node_id": db_user_id,
                "name": db_user_id,
                "displayname": login_str,
                "server": db_host,
                "database": f"CM_{site}",
                "login": login_str,
                "site_code": site,
                "domain": ctx.domain,
                "sccm_infra": True,
                "member_of_roles": ["db_owner"],
            }

        # MSSQL_Database (one per (server, db))
        if database_id not in emitted_databases:
            emitted_databases.add(database_id)
            yield {
                "kind": "MSSQL_Database",
                "node_id": database_id,
                "name": f"CM_{site}",
                "displayname": f"CM_{site}",
                "server": db_host,
                "database": f"CM_{site}",
                "site_code": site,
                "domain": ctx.domain,
                "sccm_infra": True,
            }

        # MSSQL_ServerRole sysadmin (one per server)
        if sysadmin_role_id not in emitted_server_roles:
            emitted_server_roles.add(sysadmin_role_id)
            yield {
                "kind": "MSSQL_ServerRole",
                "node_id": sysadmin_role_id,
                "name": "sysadmin",
                "displayname": "sysadmin",
                "server": db_host,
                "site_code": site,
                "domain": ctx.domain,
                "is_fixed_role": True,
                "sccm_infra": True,
            }

        # MSSQL_DatabaseRole db_owner (one per database)
        if db_owner_role_id not in emitted_db_roles:
            emitted_db_roles.add(db_owner_role_id)
            yield {
                "kind": "MSSQL_DatabaseRole",
                "node_id": db_owner_role_id,
                "name": "db_owner",
                "displayname": "db_owner",
                "server": db_host,
                "database": f"CM_{site}",
                "site_code": site,
                "domain": ctx.domain,
                "is_fixed_role": True,
                "sccm_infra": True,
            }


# ---------------------------------------------------------------------------
# Source assembly
# ---------------------------------------------------------------------------

@app.source(name="sccm", max_table_nesting=0)
def source(
    # ---- Connection (CMBP -d/-dc/-u/-p) — dlt-bound from SOURCES__SCCM__* env vars ----
    domain: str = dlt.config.value,
    domain_controller: str | None = dlt.config.value,
    username: str | None = dlt.secrets.value,
    password: str | None = dlt.secrets.value,
):
    """Build the LDAP-driven SCCM data source.

    The four parameters above bind via dlt's config/secrets system (so the
    `SOURCES__SCCM__{DOMAIN,DOMAIN_CONTROLLER,USERNAME,PASSWORD}` env vars
    are read automatically). Every other CMBP-equivalent flag is read from
    ``os.environ`` inside the body via the ``_env*`` helpers — declaring
    them as dlt-bound parameters causes dlt to eagerly coerce them from
    config providers in ways that produce confusing runtime errors (e.g.
    a missing or unset env value tripping bool/int coercion). Keeping the
    dlt-bound surface to the four credentials matches the pre-CLI-port
    factory shape and lets the CMBP-style flags on
    ``openhound collect|preprocess|convert sccm`` drive everything else
    via the env vars they set in ``main.py``.
    """

    # Defaults for every CMBP-equivalent flag the source factory honours.
    # ``_env*`` helpers below override these from the matching env var.
    # Note: ``use_ssl`` / ``start_tls`` / ``ldap_signing`` / ``ldap_channel_binding``
    # are intentionally absent — the LDAP transport + hardening combo is
    # auto-detected by ``ADClient.bind()`` in a lockout-safe way (see
    # ``clients/ad.py``). ``LDAP_PORT`` survives only as an explicit pin
    # for the rare case where 636/389 isn't appropriate.
    ldap_port: int | None = None
    collection_methods: str = "All"
    computers: str | None = None
    computer_file: str | None = None
    sms_provider: str | None = None
    site_codes: str | None = None
    disable_possible_edges: bool = False
    enable_bad_opsec: bool = False
    threads: int = 1
    show_cleartext_passwords: bool = False
    mssql_introspect: bool = False
    machine_name: str | None = None
    machine_pass: str | None = None
    client_name: str | None = None
    create_machine_account: str | None = None
    use_altauth: bool = False
    registration_sleep: int = 10
    socks_proxy: str | None = None

    def _env(name: str, fallback):
        v = os.environ.get(name)
        return v if v not in (None, "") else fallback

    def _env_bool(name: str, fallback: bool) -> bool:
        v = os.environ.get(name)
        if v is None or v == "":
            return fallback
        return v.lower() in ("1", "true", "yes", "on")

    def _env_int(name: str, fallback: int) -> int:
        v = os.environ.get(name)
        if v is None or v == "":
            return fallback
        try:
            return int(v)
        except ValueError:
            return fallback

    # Preserve None when no env var is set so ADClient auto-detects the
    # transport (LDAPS 636 → StartTLS 389 → LDAP 389 with NTLM sign/seal).
    _ldap_port_env = os.environ.get("SOURCES__SCCM__LDAP_PORT")
    if _ldap_port_env not in (None, ""):
        try:
            ldap_port = int(_ldap_port_env)
        except ValueError:
            pass
    collection_methods = _env("SOURCES__SCCM__COLLECTION_METHODS", collection_methods) or "All"
    computers = _env("SOURCES__SCCM__COMPUTERS", computers)
    computer_file = _env("SOURCES__SCCM__COMPUTER_FILE", computer_file)
    sms_provider = _env("SOURCES__SCCM__SMS_PROVIDER", sms_provider)
    site_codes = _env("SOURCES__SCCM__SITE_CODES", site_codes)
    disable_possible_edges = _env_bool("SOURCES__SCCM__DISABLE_POSSIBLE_EDGES", disable_possible_edges)
    enable_bad_opsec = _env_bool("SOURCES__SCCM__ENABLE_BAD_OPSEC", enable_bad_opsec)
    threads = _env_int("SOURCES__SCCM__THREADS", threads)
    show_cleartext_passwords = _env_bool("SOURCES__SCCM__SHOW_CLEARTEXT_PASSWORDS", show_cleartext_passwords)
    mssql_introspect = _env_bool("SOURCES__SCCM__MSSQL_INTROSPECT", mssql_introspect)
    machine_name = _env("SOURCES__SCCM__MACHINE_NAME", machine_name)
    machine_pass = _env("SOURCES__SCCM__MACHINE_PASS", machine_pass)
    client_name = _env("SOURCES__SCCM__CLIENT_NAME", client_name)
    create_machine_account = _env("SOURCES__SCCM__CREATE_MACHINE_ACCOUNT", create_machine_account)
    use_altauth = _env_bool("SOURCES__SCCM__USE_ALTAUTH", use_altauth)
    registration_sleep = _env_int("SOURCES__SCCM__REGISTRATION_SLEEP", registration_sleep)
    socks_proxy = _env("SOURCES__SCCM__SOCKS_PROXY", socks_proxy)

    creds = ADCredentials(
        domain=domain,
        domain_controller=domain_controller,
        username=username,
        password=password,
        port=ldap_port,
    )
    ctx = SourceContext(
        ad=ADClient(creds),
        domain=domain,
        username=username,
        password=password,
        collection_methods=collection_methods or "All",
        computers=computers,
        computer_file=computer_file,
        sms_provider=sms_provider,
        site_codes=site_codes,
        disable_possible_edges=bool(disable_possible_edges),
        enable_bad_opsec=bool(enable_bad_opsec),
        threads=int(threads) if threads else 1,
        show_cleartext_passwords=bool(show_cleartext_passwords),
        mssql_introspect=bool(mssql_introspect),
        machine_name=machine_name,
        machine_pass=machine_pass,
        client_name=client_name,
        create_machine_account=create_machine_account,
        use_altauth=bool(use_altauth),
        registration_sleep=int(registration_sleep) if registration_sleep else 10,
        socks_proxy=socks_proxy,
    )

    return (
        # Phase 1 — LDAP once-phases
        ldap_sites(ctx),
        ldap_mp_site_classifications(ctx),
        ldap_computers(ctx),
        ldap_users(ctx),
        ldap_groups(ctx),
        ldap_group_memberships(ctx),
        ldap_sms_providers(ctx),
        # Phase 2 — Local / DNS / DHCP once-phases. Each runs locally on the
        # collector machine (no per-host fan-out) and contributes provenance
        # rows to ``sccm.targets`` via the SQL union in ``transforms.py``.
        local_management_points(ctx),
        local_distribution_points(ctx),
        dns_management_points(ctx),
        dhcp_pxe_dps(ctx),
        # Phase 3a — Per-host RemoteRegistry + MSSQL probes. Each iterates the
        # cached ``ctx.ldap_computer_hosts()`` list. Hosts that don't permit
        # remote registry / aren't listening on TCP 1433 are silently skipped.
        registry_sccm_components(ctx),
        registry_sccm_databases(ctx),
        registry_current_users(ctx),
        mssql_epa_flags(ctx),
        mssql_logins(ctx),
        mssql_databases(ctx),
        mssql_database_users(ctx),
        mssql_server_roles(ctx),
        mssql_database_roles(ctx),
        mssql_role_members(ctx),
        mssql_linked_servers(ctx),
        # Phase 3b — AdminService REST API. Each resource shares a per-host
        # cache built lazily by ``ctx.adminservice_payloads()``.
        adminservice_admins(ctx),
        adminservice_collections(ctx),
        adminservice_collection_members(ctx),
        adminservice_security_roles(ctx),
        adminservice_role_members(ctx),
        adminservice_client_devices(ctx),
        adminservice_task_sequences(ctx),
        adminservice_collection_variables(ctx),
        adminservice_site_systems(ctx),
        adminservice_r_system_security_groups(ctx),
        adminservice_r_user_security_groups(ctx),
        adminservice_reserved_accounts(ctx),
        # Phase 3c — WMI / HTTP / SMB per-host enrichment. WMI is a fallback
        # for hosts where AdminService didn't return a row; HTTP / SMB tag
        # role + signing flags consumed by Phase 4 SQL views.
        wmi_clients(ctx),
        wmi_users_seen(ctx),
        wmi_sql_service_accounts(ctx),
        http_management_points(ctx),
        http_smsproviders(ctx),
        http_distribution_points(ctx),
        http_naa_secrets(ctx),
        http_collection_secrets(ctx),
        smb_site_servers(ctx),
        smb_distribution_points(ctx),
        smb_signing_status(ctx),
        # Phase 4 — derived-edges trigger. One sentinel row that fires the
        # DerivedEdges aggregator model in convert.
        derived_edges(ctx),
        # Phase 6 — synthesised MSSQL principal nodes (Login / DatabaseUser /
        # DatabaseRole / ServerRole / Database) referenced by the
        # ``mssql_sysadmin_edges`` fan-out. Mirrors the SQL view in Python so
        # the rows can be persisted to JSONL at collect time.
        derived_nodes(ctx),
    )
