"""Per-server SQL collection in the exact ``.ps1`` order (design spec §8).

:func:`collect_server` drives one authenticated :class:`MssqlConnection` through
the MSSQLHound collection steps (spec §8 steps 5-23) and yields
``(table_name, row_dict)`` pairs. The DLT source layer (Stage 3.3) writes each
pair to the matching raw-JSONL table; preproc/convert derive nodes and edges from
those raw rows later. We yield rows verbatim (raw server column names) and do NOT
derive anything here — that all moves to preproc/convert (spec §8 closing note).

Order is load-bearing: it mirrors ``CollectServerInfo`` in
``MSSQLHound/internal/mssql/client.go`` and the ``.ps1``. The yielded order is:

  servers (1 row, EPA + auth-mode + service-account merged) → service_accounts
  → credentials → proxy_accounts/proxy_subsystems/proxy_logins → server_principals
  → server_principal_credentials → server_role_members → server_permissions →
  local_group_members → per database (databases → database_principals →
  database_principal_logins → database_role_members → database_permissions →
  database_scoped_credentials) → linked_servers.

Each query block logs at an appropriate level and degrades gracefully: a
version-gated or permission-denied query yields nothing and logs a warning rather
than aborting the whole server (matching the Go "return nil on error" behavior).
"""
from __future__ import annotations

import logging
import re
import socket
from dataclasses import dataclass, field
from typing import Iterator, Optional

from openhound_collector_common.clients.mssql import MssqlConnection, parse_target
from openhound_collector_common.clients.wmi import WmiClient
from openhound_collector_common.logging import log_context  # noqa: F401  (registers logger.verbose)

from ..auth import CollectionConfig, detect_epa
from . import ad_resolve, queries

logger = logging.getLogger(__name__)

# Pseudo-authorities that name a local/built-in account, not an AD principal.
_LOCAL_AUTHORITIES = {"NT AUTHORITY", "NT SERVICE", "BUILTIN"}

# Matches a local Windows group server-principal name:  BUILTIN\Administrators
# or  PS1-DB\SQLAdmins  (the host's NetBIOS short name + "\" + group).
_BUILTIN_GROUP = re.compile(r"^BUILTIN\\(.+)$", re.IGNORECASE)


@dataclass
class ServerContext:
    """Inputs to :func:`collect_server` for one target.

    * ``target`` — the connection target string (``host`` / ``host:port`` / ...).
    * ``cfg``    — the run-wide :class:`CollectionConfig` (auth, toggles, ...).
    * ``wmi``    — a shared :class:`WmiClient` for the host (local-group members /
      service-account fallback). Optional: ``None`` disables WMI-backed steps.
    * ``epa``    — a pre-computed EPA verdict; when ``None``, :func:`collect_server`
      runs :func:`detect_epa` itself (spec §8 step 3, before DB queries).
    * ``spns``   — the ``MSSQLSvc/...`` SPN strings discovered for this target (from
      LDAP SPN enumeration). The first ``MSSQLSvc/<fqdn>`` SPN is the most
      authoritative source of the server's canonical FQDN (spec §8 step 1/2).
    * ``computer_sid`` — the host's resolved *computer* SID, if discovery already
      resolved it (AD-enumerated targets carry it on the :class:`Target`). When
      ``None`` (e.g. an explicit ``-t`` target), :func:`collect_server` resolves it
      itself via LDAP (spec §8 step 1) so the server ObjectIdentifier is keyed by
      SID rather than the hostname fallback.
    * ``ad`` — a shared :class:`AdClient` (or ``None``) for SID/principal resolution
      at collect time (computer SID, service-account SIDs, credential identities,
      domain-login enrichment). Optional: ``None`` disables every LDAP-backed step
      and the OIDs fall back to the hostname (matching Go when no domain is set).
    * ``discovered_links`` — a shared, mutable set the linked-server step adds each
      discovered remote ``DataSource`` to when ``--collect-from-linked`` is set, so
      the run can queue those servers as new collection targets. ``None`` disables
      the recording (the default; the recursion still runs, just nothing is queued).
    """

    target: str
    cfg: CollectionConfig
    wmi: Optional[WmiClient] = None
    epa: Optional[dict] = field(default=None)
    spns: list[str] = field(default_factory=list)
    computer_sid: Optional[str] = None
    ad: Optional["object"] = None
    discovered_links: Optional[set] = None


def collect_server(conn: MssqlConnection, ctx: ServerContext) -> Iterator[tuple[str, dict]]:
    """Run the per-server queries in ``.ps1`` order, yielding ``(table, row)``.

    *conn* must already be connected (see :func:`openhound_mssql.auth.connect`).
    """
    target = ctx.target
    host = parse_target(target).host
    short_host = host.split(".", 1)[0]

    # ---- step 5/6/7: server properties + @@VERSION + InstanceName ----------
    server_row = _query_one(conn, queries.SERVER_PROPERTIES, "servers")
    if server_row is None:
        # Without server properties we have no server node; nothing else is useful.
        logger.error("No server properties returned for %s; aborting this server", target)
        return
    logger.info("Collected server properties for %s (version %s)",
                target, _short_version(server_row.get("ProductVersion")))

    # ---- step 5: FQDN suffix via DEFAULT_DOMAIN (PS1) ----------------------
    default_domain_row = _query_one(conn, queries.DEFAULT_DOMAIN, "default_domain")
    if default_domain_row and default_domain_row.get("DefaultDomain"):
        server_row["DefaultDomain"] = default_domain_row["DefaultDomain"]
        logger.verbose("Server %s default domain: %s", target, default_domain_row["DefaultDomain"])
    else:
        # DEFAULT_DOMAIN() can be NULL on a workgroup / non-domain host.
        logger.verbose("Server %s returned no DEFAULT_DOMAIN()", target)

    # ---- step 8: authentication mode (mixed vs Windows-only) ---------------
    auth_row = _query_one(conn, queries.AUTH_MODE, "auth_mode")
    if auth_row is not None:
        server_row["isMixedModeAuthEnabled"] = bool(auth_row.get("IsMixedModeAuthEnabled"))
        logger.verbose("Server %s mixed-mode auth: %s", target, server_row["isMixedModeAuthEnabled"])
    else:
        logger.warning("Could not determine auth mode for %s", target)

    # ---- step 3 (computed before DB queries) / step 10: EPA ----------------
    _merge_epa(conn, ctx, server_row)

    # ---- step 11: service account (DMV primary; WMI fallback) --------------
    service_rows = _collect_service_accounts(conn, ctx, short_host)
    # Merge the SQL-engine service account onto the server row for convenience.
    engine_account = _engine_service_account(service_rows)
    if engine_account:
        server_row["serviceAccount"] = engine_account
        logger.verbose("Server %s service account: %s", target, engine_account)

    # Resolve the canonical FQDN once, at collect time, so convert never has to
    # guess from the tool host's domain. Stamp fqdn + sql_server_name (FQDN:Port,
    # Go's SQLServerName format) onto the server row; convert reads them verbatim.
    fqdn = _resolve_fqdn(ctx, server_row, short_host)
    server_row["fqdn"] = fqdn
    port = parse_target(target).port
    server_row["sql_server_name_display"] = f"{fqdn}:{port}"
    logger.info("Server %s canonical FQDN: %s (display name %s)",
                target, fqdn, server_row["sql_server_name_display"])

    # ---- step 1: resolve the host *computer* SID (Go resolveComputerSID) ----
    # The server ObjectIdentifier is keyed by this SID (<computerSID>:<port>) so
    # the graph ids match Go and the validator S-1-5-21-* edge patterns. AD-
    # enumerated targets carry it on the Target (ctx.computer_sid); for an explicit
    # target we resolve it now via LDAP. Falls back to None -> the OID uses the
    # lowercased hostname (matching Go with no domain). Stamped onto the servers
    # row so preproc/convert derive the SID-based OID without re-querying.
    computer_sid = ctx.computer_sid or ad_resolve.resolve_computer_sid(ctx.ad, fqdn or host)
    if computer_sid:
        server_row["computer_sid"] = computer_sid
        logger.info("Server %s computer SID: %s", target, computer_sid)
    else:
        logger.warning("No computer SID for %s; server OID will fall back to the hostname", target)

    # The server row is now fully populated — emit it first (the root node).
    yield ("servers", server_row)
    for sa in service_rows:
        yield ("service_accounts", sa)

    # ---- step 21: server-level credentials ---------------------------------
    # Buffer the credential / proxy rows (and reuse service_rows / principals
    # below) so the collect-time AD resolution pass (Go resolveCredentialSIDs /
    # resolveServiceAccountSIDs / createADNodes enrichment) can resolve every
    # referenced identity once collection is complete. The raw rows are still
    # yielded verbatim; the resolution result is yielded as a separate
    # `ad_resolved` table at the end of this generator.
    credentials = _query_all(conn, queries.CREDENTIALS, "credentials", optional=True)
    for row in credentials:
        yield ("credentials", row)

    # ---- step 22: SQL Agent proxy accounts (+ subsystems, logins) ----------
    proxy_accounts: list[dict] = []
    for table_name, row in _collect_proxies(conn):
        if table_name == "proxy_accounts":
            proxy_accounts.append(row)
        yield (table_name, row)

    # ---- step 12: server principals ----------------------------------------
    principals = _query_all(conn, queries.SERVER_PRINCIPALS, "server_principals")
    logger.info("Collected %d server principal(s) for %s", len(principals), target)
    for row in principals:
        yield ("server_principals", row)

    # ---- step 13: login -> credential mappings (2012+) ---------------------
    for row in _query_all(conn, queries.SERVER_PRINCIPAL_CREDENTIALS,
                          "server_principal_credentials", optional=True):
        yield ("server_principal_credentials", row)

    # ---- step 14: server role memberships ----------------------------------
    for row in _query_all(conn, queries.SERVER_ROLE_MEMBERS, "server_role_members"):
        yield ("server_role_members", row)

    # ---- step 15: server permissions ---------------------------------------
    for row in _query_all(conn, queries.SERVER_PERMISSIONS, "server_permissions"):
        yield ("server_permissions", row)

    # ---- step 18: local Windows group members (WMI) ------------------------
    yield from _collect_local_group_members(ctx, principals, short_host)

    # ---- step 19: databases (+ per-db principals/perms/roles/creds) --------
    # Accumulate DB-scoped credential rows for the collect-time AD resolution pass.
    db_scoped_credentials: list[dict] = []
    databases = _query_all(conn, queries.DATABASES, "databases")
    logger.info("Collected %d database(s) for %s", len(databases), target)
    for db in databases:
        db_name = db.get("name")
        if not db_name:
            # A database row with no name is unusable for the [{db}].sys.* queries.
            logger.warning("Database row without a name on %s; skipping", target)
            continue
        # PS1/Go only keep a database if its principals were readable. Collect
        # them first; on failure, skip the database entirely (matches the Go
        # "continue" in collectDatabases).
        db_principals = _query_all(
            conn, queries.DATABASE_PRINCIPALS.format(db=db_name),
            f"database_principals[{db_name}]", optional=True, missing_ok=True,
        )
        if db_principals is None:
            logger.warning("Could not read principals for database %s on %s; skipping database",
                           db_name, target)
            continue
        logger.verbose("Processing database %s on %s (%d principal(s))",
                       db_name, target, len(db_principals))

        # Every per-database row is tagged with its database name so preproc and
        # convert can scope it correctly (the [{db}].sys.* queries don't return a
        # database column, and the same principal_id — e.g. 1=dbo — recurs in every
        # database). transforms.py and the node assets read this `database` column.
        yield ("databases", db)
        for row in db_principals:
            row["database"] = db_name
            yield ("database_principals", row)

        # db user -> server login mapping (SID join).
        for row in _query_all(conn, queries.DATABASE_PRINCIPAL_LOGINS.format(db=db_name),
                              f"database_principal_logins[{db_name}]", optional=True):
            row["database"] = db_name
            yield ("database_principal_logins", row)

        # database role memberships.
        for row in _query_all(conn, queries.DATABASE_ROLE_MEMBERS.format(db=db_name),
                              f"database_role_members[{db_name}]", optional=True):
            row["database"] = db_name
            yield ("database_role_members", row)

        # database permissions (class 0 = database, class 4 = DB principal).
        for row in _query_all(conn, queries.DATABASE_PERMISSIONS.format(db=db_name),
                              f"database_permissions[{db_name}]", optional=True):
            row["database"] = db_name
            yield ("database_permissions", row)

        # database-scoped credentials (2016+).
        for row in _query_all(conn, queries.DATABASE_SCOPED_CREDENTIALS.format(db=db_name),
                              f"database_scoped_credentials[{db_name}]", optional=True):
            row["database"] = db_name
            db_scoped_credentials.append(row)
            yield ("database_scoped_credentials", row)

    # ---- step 20: linked servers (recursive probe, level<=10) --------------
    if ctx.cfg.skip_linked_servers:
        # --skip-linked-servers disables the whole step.
        logger.verbose("Skipping linked-server enumeration on %s (--skip-linked-servers)", target)
    else:
        # Run the full Go `collectLinkedServers` server-side recursive batch: it
        # discovers chained links to level<=10 (cycle-safe) AND probes each linked
        # server's remote privileges via OPENQUERY (remote sysadmin/securityadmin/
        # control-server/impersonate-any-login/mixed-mode/current-login), returning
        # the populated flags on every row. One row per linked-login mapping (the
        # distinct LocalLogin/RemoteLogin per row is what keeps the LinkedTo edge
        # count from collapsing under downstream JSON dedup). We yield each row
        # verbatim; preproc's linked_server_flags reads the now-populated flags and
        # convert derives the LinkedTo / LinkedAsAdmin edges.
        linked = _query_all(conn, queries.LINKED_SERVERS_RECURSIVE, "linked_servers", optional=True)
        logger.info("Collected %d linked-server mapping(s) for %s (recursive)", len(linked), target)
        # Resolve each link's TARGET (data_source) and SOURCE (source_server) to a
        # SID-based <computerSID>:<port> node id (Go processLinkedServers +
        # resolveLinkedServerSourceID), so convert can attach LinkedTo/LinkedAsAdmin
        # edges to real SQL Server nodes and emit the foreign-target stub node. The
        # source's DNS domain feeds the AD lookup (Go derives it from the host FQDN).
        link_domain = fqdn.split(".", 1)[1] if "." in fqdn else (ctx.cfg.domain or "")
        for row in linked:
            data_source = row.get("DataSource") or row.get("data_source") or row.get("LinkedServer") or ""
            if data_source:
                # Target id: foreign -> <foreignSID>:1433; loopback resolves to its
                # own SID (collapsed to server_oid in preproc); fallback host:port.
                row["resolved_object_identifier"] = ad_resolve.resolve_data_source_to_sid(
                    ctx.ad, str(data_source), link_domain)
            source_server = row.get("SourceServer") or row.get("source_server") or ""
            if source_server and not _same_host(str(source_server), fqdn, short_host):
                # Chained link from a DIFFERENT host: resolve its source id too.
                row["resolved_source"] = ad_resolve.resolve_linked_server_source_id(
                    ctx.ad, str(source_server), link_domain)
            yield ("linked_servers", row)
            # --collect-from-linked: record each discovered remote server's data
            # source so the run can queue it as a new collection target. The
            # discovered_links sink (set by collection/run.py) is cycle-/dedupe-safe.
            if ctx.cfg.collect_from_linked and ctx.discovered_links is not None:
                data_source = row.get("DataSource") or row.get("data_source")
                if data_source:
                    ctx.discovered_links.add(str(data_source))

    # ---- Stage 7a: collect-time AD SID/object resolution -------------------
    # Now that every referenced identity has been collected, resolve them against
    # AD once (Go's post-collection resolveComputerSID/resolveServiceAccountSIDs/
    # resolveCredentialSIDs + createADNodes enrichment). Each resolved object is
    # yielded as an `ad_resolved` row (deduped by SID), which preproc joins back to
    # build the AD nodes — so preproc/convert never re-query LDAP. No-op when no AD
    # client (no domain / --skip-ad-nodes).
    resolved_count = 0
    for row in ad_resolve.resolve_referenced_objects(
        ctx.ad,
        computer_sid=computer_sid,
        fqdn=fqdn,
        server_principals=principals,
        service_accounts=service_rows,
        credentials=credentials,
        proxy_accounts=proxy_accounts,
        db_scoped_credentials=db_scoped_credentials,
    ):
        resolved_count += 1
        yield ("ad_resolved", row)
    logger.info("Resolved %d referenced AD object(s) for %s", resolved_count, target)


# ---------------------------------------------------------------------------
# Canonical FQDN resolution (collect-time, never from the tool host's domain)
# ---------------------------------------------------------------------------
def _resolve_fqdn(ctx: ServerContext, server_row: dict, short_host: str) -> str:
    """Resolve the server's canonical FQDN at collect time (spec §8 step 1/2).

    Resolution order, most authoritative first:

    1. The ``MSSQLSvc/<fqdn>`` SPN already discovered for this target — the SPN
       host part is the canonical name the service registered in AD.
    2. DNS of the connected target host: forward-resolve the host to an IP, then
       reverse-resolve that IP to its PTR name (the host's canonical FQDN). A bare
       forward ``getfqdn`` is the fallback when the PTR lookup yields nothing.
    3. ``<short-hostname>.<DEFAULT_DOMAIN()>`` — the PS1 form, using the domain the
       *server* reported (``DEFAULT_DOMAIN()``), never the tool host's domain.

    Always returns a non-empty string (worst case the bare connection host), so the
    server node always has an FQDN.
    """
    # 1) MSSQLSvc SPN host part.
    spn_fqdn = _fqdn_from_spns(ctx.spns)
    if spn_fqdn:
        logger.verbose("FQDN for %s from SPN: %s", ctx.target, spn_fqdn)
        return spn_fqdn

    # 2) DNS forward + reverse on the connected host.
    connect_host = parse_target(ctx.target).host
    dns_fqdn = _fqdn_from_dns(connect_host)
    if dns_fqdn:
        logger.verbose("FQDN for %s from DNS: %s", ctx.target, dns_fqdn)
        return dns_fqdn

    # 3) PS1 form: short host + the server-reported DEFAULT_DOMAIN().
    default_domain = server_row.get("DefaultDomain")
    if default_domain and "." not in short_host:
        composed = f"{short_host}.{default_domain}"
        logger.verbose("FQDN for %s from DEFAULT_DOMAIN(): %s", ctx.target, composed)
        return composed

    # Last resort: the connection host as-is (may already be an FQDN, or bare).
    logger.warning("Could not resolve a canonical FQDN for %s; using connect host %r",
                   ctx.target, connect_host)
    return connect_host


def _fqdn_from_spns(spns: list[str]) -> str:
    """Pull the host part of the first ``MSSQLSvc/<host>[:port]`` SPN, or ""."""
    for spn in spns or ():
        if spn.upper().startswith("MSSQLSVC/"):
            host_port = spn.split("/", 1)[1]
            host = host_port.split(":", 1)[0].strip()
            # An SPN host with a dot is already an FQDN; a bare NetBIOS SPN host is
            # not canonical enough to prefer over DNS, so require a dotted name.
            if host and "." in host:
                return host.lower()
    return ""


def _fqdn_from_dns(host: str) -> str:
    """Forward+reverse DNS the connected host to its canonical FQDN, or "".

    Forward-resolves *host* to an IP, then reverse-resolves that IP to its PTR
    name. Falls back to ``socket.getfqdn`` when the PTR lookup yields nothing.
    Any DNS error returns "" (the caller falls through to the DEFAULT_DOMAIN form).
    """
    try:
        ip = socket.gethostbyname(host)
    except OSError as ex:
        logger.debug("Forward DNS for %r failed: %s", host, ex)
        ip = None
    if ip:
        try:
            ptr, _aliases, _addrs = socket.gethostbyaddr(ip)
        except OSError as ex:
            logger.debug("Reverse DNS for %r failed: %s", ip, ex)
            ptr = ""
        if ptr and "." in ptr:
            return ptr.lower().rstrip(".")
    # Fallback: getfqdn (forward canonicalization). Only trust a dotted result.
    fqdn = socket.getfqdn(host)
    if fqdn and "." in fqdn and fqdn.lower() != host.lower():
        return fqdn.lower().rstrip(".")
    return ""


# ---------------------------------------------------------------------------
# EPA
# ---------------------------------------------------------------------------
def _merge_epa(conn: MssqlConnection, ctx: ServerContext, server_row: dict) -> None:
    """Merge an EPA verdict into *server_row* (spec §8 step 3, then step 10).

    Uses a pre-computed verdict when present; otherwise runs :func:`detect_epa`.
    If EPA can't be probed (no domain creds / probe error), falls back to the
    registry read (step 10). The "Allowed/Required" ambiguity from SSPI is
    preserved verbatim (the shared client sets it; we don't collapse it).
    """
    verdict = ctx.epa
    if verdict is None:
        try:
            verdict = detect_epa(ctx.target, ctx.cfg)
        except Exception as ex:  # noqa: BLE001 - EPA probe is best-effort
            logger.warning("EPA probe failed for %s (%s); falling back to registry read",
                           ctx.target, ex)
            verdict = None

    if verdict is not None:
        server_row["forceEncryption"] = "Yes" if verdict.get("forceEncryption") else "No"
        server_row["strictEncryption"] = "Yes" if verdict.get("strictEncryption") else "No"
        server_row["extendedProtection"] = verdict.get("extendedProtection", "Unknown")
        logger.info("EPA for %s: forceEncryption=%s extendedProtection=%s strictEncryption=%s",
                    ctx.target, server_row["forceEncryption"],
                    server_row["extendedProtection"], server_row["strictEncryption"])
        return

    # Fallback: registry-based detection (step 10).
    reg = _query_one(conn, queries.ENCRYPTION_SETTINGS_REGISTRY, "encryption_registry", optional=True)
    if reg is None:
        logger.warning("Could not read encryption settings from registry for %s", ctx.target)
        return
    force = reg.get("ForceEncryption")
    ext = reg.get("ExtendedProtection")
    server_row["forceEncryption"] = "Yes" if force == 1 else "No"
    server_row["extendedProtection"] = {0: "Off", 1: "Allowed", 2: "Required"}.get(ext, "Unknown")
    logger.info("EPA (registry) for %s: forceEncryption=%s extendedProtection=%s",
                ctx.target, server_row["forceEncryption"], server_row["extendedProtection"])


# ---------------------------------------------------------------------------
# Service accounts (step 11)
# ---------------------------------------------------------------------------
def _collect_service_accounts(conn: MssqlConnection, ctx: ServerContext, short_host: str) -> list[dict]:
    """Collect service accounts: DMV primary, registry then WMI fallback."""
    rows = _query_all(conn, queries.SERVICE_ACCOUNTS_DMV, "service_accounts", optional=True)
    rows = [_shape_service_row(r) for r in rows if r.get("service_account")]
    if rows:
        logger.verbose("Service accounts from sys.dm_server_services on %s: %d",
                       ctx.target, len(rows))
        return rows

    # Registry fallback (default instance, then named instance).
    logger.verbose("sys.dm_server_services empty/unavailable on %s; trying registry", ctx.target)
    reg = _query_one(conn, queries.SERVICE_ACCOUNT_REGISTRY_DEFAULT, "service_account_reg", optional=True)
    if reg is None or not reg.get("ServiceAccount"):
        reg = _query_one(conn, queries.SERVICE_ACCOUNT_REGISTRY_NAMED, "service_account_reg", optional=True)
    if reg and reg.get("ServiceAccount"):
        logger.verbose("Service account from registry on %s: %s", ctx.target, reg["ServiceAccount"])
        return [{"service_account": reg["ServiceAccount"], "servicename": "SQL Server",
                 "ServiceType": "SQLServer"}]

    # WMI fallback (Win32_Service.StartName).
    if ctx.wmi is not None:
        try:
            account = ctx.wmi.service_account()
        except Exception as ex:  # noqa: BLE001 - WMI is a best-effort fallback
            logger.warning("WMI service-account lookup failed on %s: %s", ctx.target, ex)
            account = None
        if account:
            logger.verbose("Service account from WMI on %s: %s", ctx.target, account)
            return [{"service_account": account, "servicename": "SQL Server", "ServiceType": "SQLServer"}]

    logger.warning("Could not determine a service account for %s", ctx.target)
    return []


def _shape_service_row(row: dict) -> dict:
    """Tag a DMV service row with the Go-derived ServiceType (Agent vs engine)."""
    name = row.get("servicename") or ""
    row["ServiceType"] = "SQLServerAgent" if "Agent" in name else "SQLServer"
    return row


def _engine_service_account(rows: list[dict]) -> Optional[str]:
    """Return the SQL-engine service account from a list of service rows."""
    for row in rows:
        if row.get("ServiceType") == "SQLServer" and row.get("service_account"):
            return row["service_account"]
    # No engine row tagged: fall back to the first populated account.
    for row in rows:
        if row.get("service_account"):
            return row["service_account"]
    return None


# ---------------------------------------------------------------------------
# Proxies (step 22)
# ---------------------------------------------------------------------------
def _collect_proxies(conn: MssqlConnection) -> Iterator[tuple[str, dict]]:
    """Yield proxy_accounts + proxy_subsystems + proxy_logins rows (msdb access)."""
    proxies = _query_all(conn, queries.PROXY_ACCOUNTS, "proxy_accounts", optional=True)
    if not proxies:
        # No msdb access or no proxies — skip the subsystem/login queries too.
        logger.verbose("No SQL Agent proxy accounts (or no msdb access)")
        return
    logger.verbose("Collected %d SQL Agent proxy account(s)", len(proxies))
    for row in proxies:
        yield ("proxy_accounts", row)
    for row in _query_all(conn, queries.PROXY_SUBSYSTEMS, "proxy_subsystems", optional=True):
        yield ("proxy_subsystems", row)
    for row in _query_all(conn, queries.PROXY_LOGINS, "proxy_logins", optional=True):
        yield ("proxy_logins", row)


# ---------------------------------------------------------------------------
# Local Windows group members (step 18)
# ---------------------------------------------------------------------------
def _collect_local_group_members(ctx: ServerContext, principals: list[dict],
                                 short_host: str) -> Iterator[tuple[str, dict]]:
    """Yield local_group_members rows for local groups that hold SQL logins.

    Matches the PS1: for each ``WINDOWS_GROUP`` server principal that names a
    local group (``BUILTIN\\<g>`` or ``<host>\\<g>``), enumerate its members via
    ``Win32_GroupUser`` and yield the AD (non-local) members. If WMI is
    unavailable or DCOM is unreachable, yield nothing and log.
    """
    local_groups = _local_groups_with_logins(principals, short_host)
    if not local_groups:
        # No local-group logins on this server — nothing to enumerate.
        logger.verbose("No local-group server logins on %s; skipping WMI group enumeration", ctx.target)
        return
    if ctx.wmi is None:
        # WMI disabled (e.g. no creds / non-Windows) — can't enumerate members.
        logger.warning("Local-group logins present on %s but no WMI client; skipping members of %s",
                       ctx.target, sorted(local_groups.values()))
        return

    for principal_oid, group_name in local_groups.items():
        try:
            members = ctx.wmi.local_group_members(group=group_name)
        except Exception as ex:  # noqa: BLE001 - DCOM unreachable / access denied
            logger.warning("WMI local-group enumeration failed for %s\\%s on %s: %s",
                           short_host, group_name, ctx.target, ex)
            continue
        logger.verbose("Local group %s on %s has %d domain member(s)",
                       group_name, ctx.target, len(members))
        for member in members:
            yield ("local_group_members", {
                "groupPrincipalObjectIdentifier": principal_oid,
                "groupName": group_name,
                "memberDomain": member.get("domain"),
                "memberName": member.get("name"),
            })


def _local_groups_with_logins(principals: list[dict], short_host: str) -> dict[str, str]:
    """Map ``WINDOWS_GROUP`` local-group principal name -> bare group name.

    The principal "name" is the raw ``BUILTIN\\X`` / ``HOST\\X`` form; we key the
    yielded rows by that name (the convert stage builds the OID from it). Only
    BUILTIN groups and groups on this host's short name are local.
    """
    result: dict[str, str] = {}
    host_prefix = re.compile(rf"^{re.escape(short_host)}\\(.+)$", re.IGNORECASE)
    for p in principals:
        if p.get("type_desc") != "WINDOWS_GROUP":
            continue
        name = p.get("name") or ""
        builtin = _BUILTIN_GROUP.match(name)
        if builtin:
            result[name] = builtin.group(1)
            continue
        host_match = host_prefix.match(name)
        if host_match:
            result[name] = host_match.group(1)
    return result


# ---------------------------------------------------------------------------
# Query helpers (graceful per-query degradation + logging)
# ---------------------------------------------------------------------------
def _query_all(conn: MssqlConnection, sql: str, label: str, *,
               optional: bool = False, missing_ok: bool = False):
    """Run *sql* and return all rows.

    ``optional`` (version-gated / permission-gated): a query error logs a warning
    and returns ``[]``. ``missing_ok`` additionally returns ``None`` on error so
    the caller can distinguish "no rows" from "couldn't run" (used to skip a whole
    database whose principals are unreadable, matching the Go behavior).
    """
    try:
        rows = conn.query(sql)
    except Exception as ex:  # noqa: BLE001 - one query failing must not abort the server
        if missing_ok:
            logger.debug("Query %s failed (treating as missing): %s", label, ex)
            return None
        if optional:
            logger.warning("Optional query %s failed (yielding no rows): %s", label, ex)
            return []
        # A required query failed — log loudly but still return empty so the rest
        # of the server can be collected (the framework keeps partial output).
        logger.error("Query %s failed: %s", label, ex)
        return []
    logger.debug("Query %s returned %d row(s)", label, len(rows))
    return rows


def _query_one(conn: MssqlConnection, sql: str, label: str, *, optional: bool = False) -> Optional[dict]:
    """Run *sql* and return the single (first) row, or ``None``."""
    rows = _query_all(conn, sql, label, optional=optional)
    if not rows:
        return None
    return rows[0]


def _same_host(source_server: str, fqdn: str, short_host: str) -> bool:
    """Whether a link's ``source_server`` names THIS collected server.

    Go compares ``linked.SourceServer`` to ``serverInfo.Hostname`` (the FQDN) with
    a case-insensitive equality (``strings.EqualFold``) to decide whether a link is
    self-sourced (no chained-source resolution) or comes from a different host. We
    accept either the FQDN or the bare short host (the recursive query reports the
    level-0 source as ``@@SERVERNAME``, the short name) so the self-row is not
    treated as a chained link — its resolved source would equal the server's own
    OID anyway, so collapsing it avoids a redundant LDAP lookup.
    """
    src = (source_server or "").strip().lower()
    src_short = src.split(".", 1)[0]
    return src in {fqdn.lower(), short_host.lower()} or src_short == short_host.lower()


def _short_version(product_version: Optional[str]) -> str:
    """Best-effort major-version label for logging (e.g. ``15`` from 15.0.x)."""
    if not product_version:
        return "unknown"
    return str(product_version).split(".", 1)[0]


__all__ = ["ServerContext", "collect_server"]
