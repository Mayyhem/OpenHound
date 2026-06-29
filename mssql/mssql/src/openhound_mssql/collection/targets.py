"""Target discovery + classification for the MSSQL collector.

Reproduces MSSQLHound's target-resolution semantics 1:1 from the Go reference
(``MSSQLHound/cmd/mssqlhound/main.go`` ``classifyTarget`` /
``extractAndApplyCredentials`` / ``extractTargetCredentials`` / ``parsePortList``,
and ``MSSQLHound/internal/collector/collector.go`` ``parseServerString`` /
``parseSPN`` / ``buildServerList`` / ``enumerateServersFromAD`` /
``addServerToProcess`` / ``deduplicateByIP``). The verbatim parsing rules are
covered by ``tests/unit/test_targets.py`` (ported from ``main_test.go``).

A :class:`Target` is a single SQL Server instance to enumerate. Sources, in the
exact order the Go collector applies them:

  1. Explicit ``-t/--targets`` — a single instance, a comma-separated list, or a
     file path. Inline ``user:pass@host`` credentials are stripped and applied to
     ``cfg.user`` / ``cfg.password`` (first match wins, only when ``user`` unset).
  2. If no explicit targets — enumerate domain ``MSSQLSvc/*`` SPNs via LDAP.
  3. If ``--scan-all-computers`` — additionally enumerate every domain computer
     across ``--scan-all-computer-ports``.

``--dc`` is auto-resolved from ``--domain`` (SRV ``_ldap._tcp`` then A record)
when unset, via the shared :mod:`discovery.dns`. Targets that resolve to the same
IP are deduplicated (FQDN preferred over NetBIOS) unless ``--skip-ip-dedupe``.

The LDAP/AD work (auth ladder, lockout safety, SSPI Windows gate) lives in the
shared :class:`openhound_collector_common.clients.ad.AdClient`; this module only
orchestrates target resolution and never modifies that client.
"""

from __future__ import annotations

import logging
import os
import socket

from dataclasses import dataclass, field
from typing import Any, Optional

from .. import ids

# Importing the shared logging module registers the VERBOSE level and the
# ``Logger.verbose`` method used below. Imported for that side effect; the
# fallback keeps this module importable even if the shared lib isn't installed.
try:
    from openhound_collector_common.logging import log_context  # noqa: F401
except ImportError:  # pragma: no cover - shared lib not yet on the path
    pass

logger = logging.getLogger(__name__)

# ``logger.verbose`` exists once log_context is imported; fall back to debug if
# it isn't, so the VERBOSE-level calls below never raise AttributeError.
if not hasattr(logger, "verbose"):
    logger.verbose = logger.debug  # type: ignore[attr-defined]

# Default SQL Server TCP port and the default (unnamed) instance. A named
# instance keys the ObjectIdentifier by instance name; the default keys by port
# (mirrors collector.go addServerToProcess / ids.server_oid).
DEFAULT_PORT = 1433
DEFAULT_INSTANCE = ids.DEFAULT_INSTANCE  # "MSSQLSERVER"

# SPN prefix, matched case-insensitively (Go uppercases before comparing).
_SPN_PREFIX = "MSSQLSVC/"


# ---------------------------------------------------------------------------
# Target descriptor
# ---------------------------------------------------------------------------
@dataclass
class Target:
    """A single SQL Server instance to enumerate.

    Attributes:
        host: Hostname / FQDN / IP to connect to.
        port: TCP port (default 1433).
        instance: SQL named-instance, or "" / "MSSQLSERVER" for the default.
        connection_string: The string handed to the SQL client (host, host:port,
            or host\\instance), mirroring Go ``ServerToProcess.ConnectionString``.
        object_sid: Resolved *computer* SID, if known, used to build the stable
            ObjectIdentifier; ``None`` falls back to the lowercased hostname. This
            is the machine SID (from ``(objectClass=computer)`` resolution), NOT
            the SPN service-account SID — keeping them distinct is what prevents
            every SPN of a single service account collapsing to one OID.
        account_name: SPN service-account name, if discovered (tracked alongside
            the target like Go's ``serverSPNData``; never used for the OID).
        account_sid: SPN service-account SID, if discovered (same note).
        spns: Full ``MSSQLSvc/...`` SPN strings associated with this target.
        skip_if_unresolved: True for ``--scan-all-computers`` targets, which are
            dropped (not kept) when DNS resolution fails.
        object_identifier: Stable graph ID (built by :meth:`finalize`).
    """

    host: str
    port: int = DEFAULT_PORT
    instance: str = ""
    connection_string: str = ""
    object_sid: Optional[str] = None
    account_name: Optional[str] = None
    account_sid: Optional[str] = None
    spns: list[str] = field(default_factory=list)
    skip_if_unresolved: bool = False
    object_identifier: str = ""

    def finalize(self) -> "Target":
        """Compute and store :attr:`object_identifier` from the current fields.

        Mirrors collector.go ``addServerToProcess``: prefer the resolved SID,
        else the lowercased hostname; key by instance name for a named instance,
        otherwise by port. Returns self for chaining.
        """
        self.object_identifier = ids.server_oid(
            self.object_sid, self.host, self.instance, self.port
        )
        return self


# ---------------------------------------------------------------------------
# Pure parsing helpers (1:1 with Go cmd/mssqlhound/main.go)
# ---------------------------------------------------------------------------
def classify_target(value: str) -> tuple[str, str]:
    """Classify a ``-t/--targets`` value (Go ``classifyTarget``).

    Returns ``(kind, payload)`` where *kind* is one of:

      * ``"file"`` — *value* is an existing (non-directory) file path; *payload*
        is the path.
      * ``"list"`` — *value* contains a comma; *payload* is the raw list string.
      * ``"instance"`` — anything else (host, host:port, host\\instance, SPN, or
        a non-existent path treated as a hostname); *payload* is *value*.

    An empty *value* classifies as ``("instance", "")`` (the Go zero return).
    """
    if value == "":
        # Empty input — Go returns all-empty; treat as an empty single instance.
        logger.debug("classify_target: empty value")
        return ("instance", "")
    # An existing file (not a directory) is a server-list file.
    try:
        if os.path.isfile(value):
            logger.debug("classify_target: %r is an existing file -> file", value)
            return ("file", value)
    except (OSError, ValueError) as exc:
        # os.path.isfile can raise ValueError on embedded NULs / OSError on odd
        # paths; treat an un-stat-able value as a plain instance string.
        logger.debug("classify_target: stat of %r failed (%s); treating as instance", value, exc)
    # A comma means a comma-separated list of targets.
    if "," in value:
        logger.debug("classify_target: %r contains a comma -> list", value)
        return ("list", value)
    # Otherwise it's a single server instance.
    logger.debug("classify_target: %r -> single instance", value)
    return ("instance", value)


def extract_target_credentials(value: str) -> tuple[str, str, str, bool]:
    """Parse ``user:password@target`` from a target string (Go ``extractTargetCredentials``).

    Splits on the **last** ``@`` (so UPN usernames like ``user@domain`` survive)
    and the **first** ``:`` in the credentials portion (so passwords containing
    ``:`` survive). Both user and the clean target must be non-empty.

    Returns ``(user, password, clean_target, ok)``. When parsing fails, returns
    ``("", "", value, False)`` — the original value is handed back unchanged so
    the caller treats it as a plain target.
    """
    at_idx = value.rfind("@")
    if at_idx < 0:
        # No "@" — cannot carry credentials.
        return ("", "", value, False)

    credentials = value[:at_idx]
    clean_target = value[at_idx + 1:]

    colon_idx = credentials.find(":")
    if colon_idx < 0:
        # No ":" in the credentials portion — not "user:pass" form.
        return ("", "", value, False)

    user = credentials[:colon_idx]
    password = credentials[colon_idx + 1:]

    # Sanity: both the user and the clean target must be non-empty.
    if user == "" or clean_target == "":
        return ("", "", value, False)

    return (user, password, clean_target, True)


def extract_and_apply_credentials(targets: str, cfg: Any) -> str:
    """Strip inline creds from a comma-list and apply them to *cfg* (Go ``extractAndApplyCredentials``).

    For each comma-separated entry, removes any ``user:pass@`` prefix and records
    the first set of credentials found onto ``cfg.user`` / ``cfg.password`` — but
    only when ``cfg.user`` is not already set (the caller mirrors Go's
    "only when -u not explicitly provided" guard). File paths are returned
    untouched so :func:`classify_target` can still detect them.

    Returns the cleaned target string (a single value, or a comma-joined list).
    """
    # Leave file paths alone — classify_target detects them downstream.
    try:
        if os.path.isfile(targets):
            logger.debug("extract_and_apply_credentials: %r is a file; leaving untouched", targets)
            return targets
    except (OSError, ValueError) as exc:
        logger.debug("extract_and_apply_credentials: stat of %r failed (%s)", targets, exc)

    cleaned: list[str] = []
    cred_user = ""
    cred_pass = ""
    cred_set = False

    for part in targets.split(","):
        part = part.strip()
        if part == "":
            # Skip blank entries (trailing commas, etc.).
            continue
        user, password, clean_target, ok = extract_target_credentials(part)
        if ok:
            if not cred_set:
                # First entry with credentials wins.
                cred_user = user
                cred_pass = password
                cred_set = True
            cleaned.append(clean_target)
        else:
            cleaned.append(part)

    if cred_set:
        # Apply only when the SQL user wasn't already supplied (Go applies
        # unconditionally here, but its caller only calls this when -u is unset;
        # we replicate that guard locally so the function is safe standalone).
        existing_user = getattr(cfg, "user", None)
        if not existing_user:
            cfg.user = cred_user
            cfg.password = cred_pass
            logger.info("Parsed inline credentials from target (user=%s)", cred_user)
        else:
            logger.debug("Inline target credentials ignored; --user already set")

    if len(cleaned) == 1:
        return cleaned[0]
    return ",".join(cleaned)


def parse_port_list(value: str) -> list[int]:
    """Parse a comma-separated port list (Go ``parsePortList``).

    Trims whitespace, deduplicates (preserving first-seen order), and validates
    each is an integer in 1-65535. Raises :class:`ValueError` on an empty list,
    an empty item (e.g. ``"1433,,1444"``), a non-numeric item, or an
    out-of-range port.
    """
    ports: list[int] = []
    seen: set[int] = set()
    for part in value.split(","):
        part = part.strip()
        if part == "":
            # Empty input or an empty item (consecutive/trailing commas).
            raise ValueError("empty port")
        try:
            port = int(part)
        except ValueError as exc:
            raise ValueError(f"{part!r} is not a number") from exc
        if port < 1 or port > 65535:
            raise ValueError(f"{port} is outside 1-65535")
        if port in seen:
            # Duplicate — keep the first occurrence only.
            continue
        seen.add(port)
        ports.append(port)
    if not ports:
        # Reachable only for an all-empty split (handled above per item), kept
        # for parity with Go's final guard.
        raise ValueError("at least one port is required")
    return ports


# ---------------------------------------------------------------------------
# Server-string / SPN parsing (1:1 with collector.go parseServerString/parseSPN)
# ---------------------------------------------------------------------------
def _is_int(text: str) -> bool:
    """True if *text* is a base-10 integer (matches Go's strconv.Atoi success)."""
    try:
        int(text)
        return True
    except ValueError:
        return False


def parse_server_string(server_str: str) -> Target:
    """Parse a server string into a :class:`Target` (Go ``parseServerString``).

    Accepts ``host``, ``host:port``, ``host\\instance``, ``host,port``, and the
    ``MSSQLSvc/host:portOrInstance`` SPN form. Does not resolve SIDs. The
    ObjectIdentifier is left unset (call :meth:`Target.finalize` after any SID
    resolution).
    """
    target = Target(host="", port=DEFAULT_PORT)

    # Strip an "MSSQLSvc/" prefix (case-insensitive), like the SPN form.
    if server_str.upper().startswith(_SPN_PREFIX):
        server_str = server_str[len(_SPN_PREFIX):]

    if "\\" in server_str:
        # host\instance
        host, _, instance = server_str.partition("\\")
        target.host = host
        target.instance = instance
        target.connection_string = server_str
    elif ":" in server_str:
        # host:port or host:instance
        host, _, port_or_instance = server_str.partition(":")
        target.host = host
        if _is_int(port_or_instance):
            target.port = int(port_or_instance)
        else:
            target.instance = port_or_instance
        target.connection_string = server_str
    elif "," in server_str:
        # host,port (an alternative port separator the Go code accepts)
        host, _, port = server_str.partition(",")
        target.host = host
        if _is_int(port):
            target.port = int(port)
        target.connection_string = server_str
    else:
        # Bare hostname.
        target.host = server_str
        target.connection_string = server_str

    return target


def _parse_spn(spn_str: str) -> Optional[tuple[str, str, str]]:
    """Parse an ``MSSQLSvc/host:portOrInstance`` SPN (Go ``parseSPN``).

    Returns ``(hostname, port, instance)`` (port/instance possibly empty) or
    ``None`` when *spn_str* lacks the ``MSSQLSvc/`` prefix.
    """
    if not spn_str.upper().startswith(_SPN_PREFIX):
        # Not an MSSQL SPN — caller skips it.
        return None
    remainder = spn_str[len(_SPN_PREFIX):]
    hostname, sep, port_or_instance = remainder.partition(":")
    port = ""
    instance = ""
    if sep:
        if _is_int(port_or_instance):
            port = port_or_instance
        else:
            instance = port_or_instance
    return (hostname, port, instance)


def _target_from_spn_entry(entry: dict[str, Any]) -> list[Target]:
    """Turn one AD SPN account entry into its MSSQL :class:`Target`(s).

    ``entry`` is a dict from :meth:`AdClient.enumerate_spns` with keys
    ``servicePrincipalName`` (list), ``objectSid``, ``sAMAccountName``. One
    account may publish several ``MSSQLSvc`` SPNs (multiple hosts/instances); we
    build a target per SPN, mirroring the Go per-SPN loop.
    """
    account_sid = entry.get("objectSid")
    account_name = entry.get("sAMAccountName")
    raw_spns = entry.get("servicePrincipalName") or []
    if isinstance(raw_spns, str):
        raw_spns = [raw_spns]

    targets: list[Target] = []
    for spn_str in raw_spns:
        parsed = _parse_spn(spn_str)
        if parsed is None:
            # Non-MSSQL SPN slipped through the filter — skip it.
            logger.debug("_target_from_spn_entry: skipping non-MSSQL SPN %r", spn_str)
            continue
        hostname, port, instance = parsed
        # account_name/account_sid are the SPN service account (tracked, not used
        # for the OID); the computer SID is resolved separately by hostname.
        target = Target(
            host=hostname, port=DEFAULT_PORT,
            account_name=account_name, account_sid=account_sid,
        )
        # Rebuild the canonical full SPN + connection string exactly as Go does.
        if port:
            target.port = int(port)
            target.connection_string = f"{hostname}:{port}"
            full_spn = f"MSSQLSvc/{hostname}:{port}"
        elif instance:
            target.instance = instance
            target.connection_string = f"{hostname}\\{instance}"
            full_spn = f"MSSQLSvc/{hostname}:{instance}"
        else:
            target.connection_string = hostname
            full_spn = f"MSSQLSvc/{hostname}"
        target.spns = [full_spn]
        targets.append(target)
    return targets


def _scan_all_computer_servers(entry: dict[str, Any], ports: list[int]) -> list[Target]:
    """Build :class:`Target`(s) for one domain computer (Go ``scanAllComputerServers``).

    One target per scan port. When the only port is the default 1433 the
    connection string is the bare hostname; otherwise it carries an explicit
    ``host:port``. These targets are marked :attr:`skip_if_unresolved` so an
    unresolvable computer is dropped rather than kept.
    """
    hostname = entry.get("dnsHostName") or entry.get("name")
    object_sid = entry.get("objectSid")
    if not hostname:
        # No usable hostname for this computer object — nothing to scan.
        logger.debug("_scan_all_computer_servers: computer %r has no hostname", entry.get("distinguishedName"))
        return []

    use_bare = len(ports) == 1 and ports[0] == DEFAULT_PORT
    out: list[Target] = []
    for port in ports:
        connection_string = hostname if use_bare else f"{hostname}:{port}"
        target = parse_server_string(connection_string)
        target.port = port
        target.object_sid = object_sid
        target.skip_if_unresolved = True
        out.append(target)
    return out


# ---------------------------------------------------------------------------
# Deduplication (1:1 intent with collector.go deduplicateByIP / addServerToProcess)
# ---------------------------------------------------------------------------
def _resolve_ip(hostname: str) -> Optional[str]:
    """Resolve *hostname* to a single IP string, or None on failure.

    Uses the stdlib resolver (which honours an installed dnspython override only
    indirectly); a miss returns None so the caller can decide whether to keep or
    drop the target.
    """
    try:
        return socket.gethostbyname(hostname)
    except (socket.gaierror, OSError) as exc:
        logger.debug("_resolve_ip: DNS lookup for %s failed: %s", hostname, exc)
        return None


def _dedupe_by_object_identifier(targets: list[Target]) -> list[Target]:
    """Collapse targets sharing an ObjectIdentifier (Go ``addServerToProcess`` dedup).

    Applied as targets are gathered (before IP dedupe). When two targets share an
    OID, the FQDN-hostname variant is preferred over a NetBIOS one.
    """
    by_oid: dict[str, Target] = {}
    order: list[str] = []
    for target in targets:
        oid = target.finalize().object_identifier
        existing = by_oid.get(oid)
        if existing is None:
            by_oid[oid] = target
            order.append(oid)
            continue
        # Duplicate OID — prefer the FQDN hostname over a NetBIOS short name.
        if "." not in existing.host and "." in target.host:
            logger.debug("dedupe(OID): preferring FQDN %s over %s", target.host, existing.host)
            existing.host = target.host
        else:
            logger.debug("dedupe(OID): dropping duplicate %s (kept %s)", target.host, existing.host)
    return [by_oid[oid] for oid in order]


def _deduplicate_by_ip(targets: list[Target]) -> list[Target]:
    """Remove targets resolving to the same (IP, port, instance) (Go ``deduplicateByIP``).

    Prefers FQDN over NetBIOS for the kept entry. A target whose hostname does
    not resolve is kept as-is unless it is a scan-all-computers target
    (:attr:`skip_if_unresolved`), which is dropped.
    """
    if not targets:
        return targets

    # Resolve each unique hostname once.
    ip_by_host: dict[str, Optional[str]] = {}
    for target in targets:
        host = target.host.strip()
        if not host:
            continue
        key = host.lower()
        if key not in ip_by_host:
            ip_by_host[key] = _resolve_ip(host)

    kept: list[Target] = []
    seen: dict[tuple[str, int, str], int] = {}  # (ip, port, INSTANCE) -> index in kept
    dropped_unresolved = 0

    for target in targets:
        ip = ip_by_host.get(target.host.strip().lower())
        if not ip:
            if target.skip_if_unresolved:
                # scan-all-computers target that doesn't resolve — drop it.
                logger.verbose("Dedup by IP: dropping unresolved scan-all-computers target %s", target.host)
                dropped_unresolved += 1
                continue
            # Explicit/SPN target that doesn't resolve — keep it so the SQL
            # client can still try (and surface a concrete connect error).
            logger.debug("Dedup by IP: DNS lookup failed, keeping %s as-is", target.host)
            kept.append(target)
            continue

        key = (ip, target.port, target.instance.upper())
        if key in seen:
            existing = kept[seen[key]]
            is_fqdn = "." in target.host
            existing_is_fqdn = "." in existing.host
            if is_fqdn and not existing_is_fqdn:
                logger.debug("Dedup by IP: replacing %s with %s (ip=%s)", existing.host, target.host, ip)
                kept[seen[key]] = target
            else:
                logger.debug("Dedup by IP: skipping duplicate %s (kept %s, ip=%s)", target.host, existing.host, ip)
            continue
        seen[key] = len(kept)
        kept.append(target)

    removed = len(targets) - len(kept)
    if removed > 0:
        logger.info("Deduplicated %d target(s) by resolved IP", removed)
    if dropped_unresolved > 0:
        logger.info("Dropped %d unresolved scan-all-computers target(s)", dropped_unresolved)
    return kept


def _filter_unresolved_scan_all(targets: list[Target]) -> list[Target]:
    """When IP dedupe is skipped, still drop unresolved scan-all-computers targets.

    Mirrors collector.go ``filterUnresolvedScanAllComputers``: explicit/SPN
    targets are always kept, but a scan-all-computers target that doesn't resolve
    is dropped (it would only waste a connection attempt against a non-existent
    host).
    """
    has_scan_all = any(t.skip_if_unresolved for t in targets)
    if not has_scan_all:
        # Nothing to filter — avoid the DNS round-trips entirely.
        return targets

    resolvable: dict[str, bool] = {}
    kept: list[Target] = []
    dropped = 0
    for target in targets:
        if not target.skip_if_unresolved:
            kept.append(target)
            continue
        key = target.host.strip().lower()
        if key not in resolvable:
            resolvable[key] = _resolve_ip(target.host) is not None
        if resolvable[key]:
            kept.append(target)
        else:
            logger.debug("Dropping unresolved scan-all-computers target %s", target.host)
            dropped += 1
    if dropped > 0:
        logger.info("Dropped %d unresolved scan-all-computers target(s)", dropped)
    return kept


# ---------------------------------------------------------------------------
# AD client construction
# ---------------------------------------------------------------------------
def _build_ldap_auth(cfg: Any, ldap_auth: Any = None) -> Any:
    """Build the :class:`LdapAuth` for SPN/computer enumeration.

    If *ldap_auth* is supplied it is used verbatim (the caller already chose the
    LDAP credential). Otherwise an ``LdapAuth`` is assembled from cfg's LDAP
    fields, falling back to the SQL credentials when they look domain-shaped
    (mirrors Go's effective-LDAP-cred fallback in ``run``).
    """
    if ldap_auth is not None:
        return ldap_auth

    from openhound_collector_common.clients.ad import LdapAuth

    ldap_user = getattr(cfg, "ldap_user", None) or ""
    ldap_password = getattr(cfg, "ldap_password", None) or ""
    ldap_nt_hash = getattr(cfg, "ldap_nt_hash", None) or ""
    ldap_ticket = getattr(cfg, "ldap_ticket", None) or ""
    sql_user = getattr(cfg, "user", None) or ""
    sql_password = getattr(cfg, "password", None) or ""
    sql_nt_hash = getattr(cfg, "nt_hash", None) or ""
    domain = getattr(cfg, "domain", None) or ""

    # Fall back to the SQL creds for LDAP when no LDAP creds were given and the
    # SQL user looks like a domain credential (Go effectiveLDAPUser logic).
    if not (ldap_user or ldap_password or ldap_nt_hash or ldap_ticket) and sql_user:
        if "\\" in sql_user or "@" in sql_user:
            ldap_user = sql_user
            ldap_password = sql_password
            ldap_nt_hash = sql_nt_hash
            logger.debug("LDAP creds: falling back to qualified SQL user %s", sql_user)
        elif domain:
            # Bare username — derive a UPN from --domain.
            ldap_user = f"{sql_user}@{domain}"
            ldap_password = sql_password
            ldap_nt_hash = sql_nt_hash
            logger.debug("LDAP creds: derived UPN %s from bare SQL user + domain", ldap_user)

    return LdapAuth(
        username=ldap_user or None,
        password=ldap_password or None,
        nt_hash=ldap_nt_hash or None,
        kerberos_ticket=ldap_ticket or None,
    )


def _short_hostname(hostname: str) -> str:
    """Return the NetBIOS short name for a host (the label before the first dot)."""
    return hostname.split(".", 1)[0]


def _resolve_computer_sid(client: Any, hostname: str) -> Optional[str]:
    """Resolve a host's *computer* SID via LDAP (Go ``ResolveComputerSID``).

    Searches the computer object by ``sAMAccountName=<shorthost>$`` (computer
    accounts always end in ``$``). Returns the SID or None on miss/error. This is
    the machine SID used to key the server ObjectIdentifier — distinct from the
    SPN service-account SID.
    """
    if not hostname:
        return None
    sam = _short_hostname(hostname)
    if not sam.endswith("$"):
        sam = f"{sam}$"
    try:
        principal = client.resolve_principal(sam)
    except Exception as exc:  # pragma: no cover - LDAP error surfaced, then skip
        logger.debug("resolve_computer_sid: lookup for %s failed: %s", sam, exc)
        return None
    if principal and principal.get("sid"):
        logger.debug("resolve_computer_sid: %s -> %s", sam, principal["sid"])
        return principal["sid"]
    logger.debug("resolve_computer_sid: no computer object for %s", sam)
    return None


# ---------------------------------------------------------------------------
# Top-level resolution
# ---------------------------------------------------------------------------
def resolve_targets(cfg: Any, ldap_auth: Any = None) -> list[Target]:
    """Resolve the full target list for a collection run.

    Args:
        cfg: A config object exposing (all optional, duck-typed): ``targets``,
            ``user``, ``password``, ``nt_hash``, ``ldap_user``, ``ldap_password``,
            ``ldap_nt_hash``, ``ldap_ticket``, ``domain``, ``dc``,
            ``dns_resolver``, ``scan_all_computers``, ``scan_all_computer_ports``,
            ``skip_ip_dedupe``.
        ldap_auth: An optional pre-built ``LdapAuth`` to use for AD enumeration;
            when omitted it is derived from *cfg* (with the SQL-cred fallback).

    Returns:
        The deduplicated list of :class:`Target` instances to enumerate, each
        with its :attr:`object_identifier` populated.
    """
    targets_value = getattr(cfg, "targets", None) or ""
    explicit_user = getattr(cfg, "user", None)

    # 1) Strip inline credentials from explicit targets (only when -u unset),
    #    mirroring run()'s guard, then classify.
    if targets_value and not explicit_user:
        targets_value = extract_and_apply_credentials(targets_value, cfg)

    kind, payload = classify_target(targets_value)
    gathered: list[Target] = []

    if kind == "instance" and payload:
        # Single explicit instance.
        logger.info("Target source: single instance %r", payload)
        gathered.append(parse_server_string(payload))
    elif kind == "list":
        # Comma-separated list.
        count = 0
        for entry in payload.split(","):
            entry = entry.strip()
            if entry:
                gathered.append(parse_server_string(entry))
                count += 1
        logger.info("Target source: %d server(s) from comma-separated list", count)
    elif kind == "file":
        # Server-list file: one target per non-comment line; inline creds per
        # line apply to cfg (first match wins), matching extractLineCredentials.
        gathered.extend(_targets_from_file(payload, cfg))

    # 2) No explicit targets → enumerate MSSQL SPNs from AD. 3) Optionally also
    #    scan all domain computers. Both need a domain (and a resolved DC).
    if not gathered:
        gathered.extend(_resolve_from_ad(cfg, ldap_auth))
    elif getattr(cfg, "scan_all_computers", False):
        # --scan-all-computers augments an explicit/SPN list too (Go runs the
        # computer enum inside enumerateServersFromAD only when no servers were
        # given; explicit + scan-all is unusual, but we honour the flag).
        logger.info("scan-all-computers requested alongside explicit targets")
        gathered.extend(_resolve_from_ad(cfg, ldap_auth, spn_enum=False))

    # Collapse exact ObjectIdentifier duplicates (FQDN preferred).
    gathered = _dedupe_by_object_identifier(gathered)

    # 4) IP-based dedupe unless disabled.
    if getattr(cfg, "skip_ip_dedupe", False):
        logger.info("Skipping IP-based deduplication (--skip-ip-dedupe)")
        gathered = _filter_unresolved_scan_all(gathered)
    else:
        gathered = _deduplicate_by_ip(gathered)

    # Ensure every kept target has a finalized ObjectIdentifier.
    for target in gathered:
        target.finalize()

    logger.info("Resolved %d unique target(s) to process", len(gathered))
    return gathered


def _targets_from_file(path: str, cfg: Any) -> list[Target]:
    """Read targets from a server-list file (Go ``buildServerList`` file branch).

    One target per line; blank lines and ``#`` comments are skipped. Inline
    ``user:pass@host`` credentials on a line are stripped and applied to cfg
    (first match wins, only when ``cfg.user`` is unset).
    """
    out: list[Target] = []
    try:
        with open(path, "r", encoding="utf-8") as handle:
            lines = handle.read().splitlines()
    except OSError as exc:
        # Unreadable file — log and return nothing (the run yields no targets).
        logger.error("Failed to read server list file %s: %s", path, exc)
        return out

    count = 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            # Skip blanks and comments.
            continue
        # Per-line inline credential extraction (single-entry form).
        user, password, clean_target, ok = extract_target_credentials(line)
        if ok:
            if not getattr(cfg, "user", None):
                cfg.user = user
                cfg.password = password
                logger.info("Parsed inline credentials from target file (user=%s)", user)
            else:
                logger.debug("Inline file credentials ignored; --user already set")
            line = clean_target
        out.append(parse_server_string(line))
        count += 1
    logger.info("Target source: %d server(s) from file %s", count, path)
    return out


def _resolve_from_ad(cfg: Any, ldap_auth: Any, *, spn_enum: bool = True) -> list[Target]:
    """Discover targets from Active Directory (SPN enum + optional scan-all).

    Auto-resolves the DC from the domain when ``cfg.dc`` is unset, builds the
    shared :class:`AdClient`, enumerates ``MSSQLSvc/*`` SPNs (when *spn_enum*),
    and — when ``cfg.scan_all_computers`` is set — every domain computer across
    the configured ports. Returns the gathered (not-yet-deduped) targets.
    """
    domain = getattr(cfg, "domain", None) or ""
    if not domain:
        # Without a domain there is nothing to enumerate from AD.
        logger.error(
            "No targets specified and no --domain provided; cannot enumerate SPNs. "
            "Specify --targets, or --domain (+ optional --dc)."
        )
        return []

    # Auto-resolve the DC from the domain (SRV then A) when not pinned.
    dc = getattr(cfg, "dc", None) or ""
    dns_resolver = getattr(cfg, "dns_resolver", None) or ""
    if not dc:
        from openhound_collector_common.discovery import dns as dns_discovery

        resolver = dns_discovery.make_resolver(dns_resolver or None) if dns_resolver else None
        dc = dns_discovery.resolve_dc(domain, None, resolver=resolver)
        logger.info("Auto-resolved domain controller %s for domain %s", dc, domain)
        # Surface the resolved DC back onto cfg so downstream auth reuses it.
        try:
            cfg.dc = dc
        except (AttributeError, TypeError):
            # cfg may be read-only / a simple namespace without the attr; ignore.
            logger.debug("Could not write resolved DC back onto cfg")

    from openhound_collector_common.clients.ad import AdClient

    auth = _build_ldap_auth(cfg, ldap_auth)
    client = AdClient(domain=domain, dc=dc or None, auth=auth)

    gathered: list[Target] = []
    try:
        if spn_enum:
            logger.info("No servers specified; enumerating MSSQL SPNs from Active Directory")
            spn_entries = client.enumerate_spns("MSSQLSvc/*")
            # Cache computer-SID resolution per short hostname so the many SPNs
            # of one host hit LDAP only once.
            sid_by_host: dict[str, Optional[str]] = {}
            for entry in spn_entries:
                for target in _target_from_spn_entry(entry):
                    host_key = _short_hostname(target.host).lower()
                    if host_key not in sid_by_host:
                        sid_by_host[host_key] = _resolve_computer_sid(client, target.host)
                    target.object_sid = sid_by_host[host_key]
                    gathered.append(target)
                    logger.info(
                        "Found SPN target %s (computerSID=%s, serviceAccount=%s)",
                        target.connection_string, target.object_sid, target.account_name,
                    )

        if getattr(cfg, "scan_all_computers", False):
            ports = _scan_all_ports(cfg)
            logger.info("scan-all-computers enabled; enumerating domain computers on ports %s", ports)
            computers = client.enumerate_computers()
            added = 0
            for entry in computers:
                for target in _scan_all_computer_servers(entry, ports):
                    gathered.append(target)
                    added += 1
            logger.info("Added %d scan-all-computers target(s)", added)
    finally:
        # Always release the LDAP connection.
        try:
            client.close()
        except Exception as exc:  # pragma: no cover - defensive cleanup
            logger.debug("Error closing AD client: %s", exc)

    return gathered


def _scan_all_ports(cfg: Any) -> list[int]:
    """Return the scan-all-computers port list, defaulting to [1433].

    ``cfg.scan_all_computer_ports`` may be a parsed ``list[int]`` (the CLI layer
    already ran :func:`parse_port_list`) or a raw comma string; both are handled.
    """
    raw = getattr(cfg, "scan_all_computer_ports", None)
    if raw is None or raw == "":
        return [DEFAULT_PORT]
    if isinstance(raw, (list, tuple)):
        return list(raw) if raw else [DEFAULT_PORT]
    # Raw string form — parse it (raises ValueError on malformed input).
    return parse_port_list(str(raw))


__all__ = [
    "Target",
    "classify_target",
    "extract_target_credentials",
    "extract_and_apply_credentials",
    "parse_port_list",
    "parse_server_string",
    "resolve_targets",
]
