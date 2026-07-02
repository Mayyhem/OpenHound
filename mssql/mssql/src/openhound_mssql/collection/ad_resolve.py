"""Collect-time Active Directory SID/object resolution (Stage 7a).

MSSQLHound resolves a handful of AD objects during collection so the graph can
key the server node on the host's *computer* SID, and so the AD nodes (and the
Stage-7b edges that attach to them) have real SIDs + LDAP attributes instead of
bare names. Go does this as a post-collection pass over the in-memory
``ServerInfo`` (``resolveComputerSID`` / ``resolveServiceAccountSIDsViaLDAP`` /
``resolveCredentialSIDsViaLDAP`` and the ``createADNodes`` enrichment loop). We
do the same here, at collect time, and emit the results as a single
``ad_resolved`` raw table that preproc reads to build the AD nodes — so neither
preproc nor convert ever has to re-query LDAP.

Two kinds of output:

* The **host computer SID** (``resolve_computer_sid``) is returned so
  ``collect_server`` can stamp it onto the ``servers`` row → the server
  ObjectIdentifier becomes ``<computerSID>:<port>`` (matching Go). Built by
  searching ``sAMAccountName=<shorthost>$``.
* The **referenced AD objects** (``resolve_referenced_objects``) are emitted as
  ``ad_resolved`` rows, one per resolved object, deduped by SID. Each carries the
  resolve_*-dict shape the AdClient returns (sid, name, type, samAccountName,
  enabled, dn, dnsHostName, upn) plus a ``domain`` column. Preproc joins these
  back to logins / service accounts / credentials by SID or identity name.

Every LDAP failure is best-effort: it logs and yields nothing for that object
rather than aborting collection (matching Go's "log and continue" on a miss).
The whole module is a no-op when no :class:`AdClient` is supplied (no domain /
``--skip-ad-nodes``), so collection still runs and the OIDs fall back to the
hostname, exactly like Go with no domain.
"""
from __future__ import annotations

import logging
from typing import Iterator, Optional

logger = logging.getLogger(__name__)

# SID prefix that identifies a domain principal (vs a local / built-in account).
# Mirrors Go's `strings.HasPrefix(sid, "S-1-5-21-")` gates.
_DOMAIN_SID_PREFIX = "S-1-5-21-"

# Service-account names that are local/virtual and are NOT resolved against AD
# (Go `resolveServiceAccountSIDsViaLDAP` skips these prefixes verbatim).
_NON_AD_SA_PREFIXES = ("NT SERVICE\\", "NT AUTHORITY\\")


def resolve_computer_sid(ad, hostname: str) -> Optional[str]:
    """Resolve the host's *computer* SID via LDAP (Go ``ResolveComputerSID``).

    Searches the computer object by ``sAMAccountName=<shorthost>$`` (computer
    accounts always end in ``$``). Returns the SID, or ``None`` on miss/error/no
    client. This is the machine SID used to key the server ObjectIdentifier —
    distinct from any SPN service-account SID.

    Args:
        ad: A shared :class:`~openhound_collector_common.clients.ad.AdClient`, or
            ``None`` to skip (returns ``None``).
        hostname: The connected host name (FQDN or short); only the short name is
            used to build the ``$`` sAMAccountName.
    """
    if ad is None:
        # No AD client (no domain / skip-ad-nodes) — cannot resolve; caller falls
        # back to the hostname-based OID.
        logger.verbose("No AD client; skipping computer-SID resolution for %s", hostname)
        return None
    short = hostname.split(".", 1)[0]
    sam = short if short.endswith("$") else f"{short}$"
    try:
        principal = ad.resolve_principal(sam)
    except Exception as exc:  # noqa: BLE001 - LDAP miss/error is non-fatal
        logger.warning("Computer-SID resolution for %s failed: %s", sam, exc)
        return None
    sid = (principal or {}).get("sid")
    if sid:
        logger.info("Resolved computer SID for %s: %s", hostname, sid)
        return sid
    logger.warning("No computer object found in AD for %s", sam)
    return None


# Cloud-SQL hostname suffixes Go never resolves to a computer SID — the host is
# the node id directly (Go resolveDataSourceToSID cloud short-circuit).
_CLOUD_SUFFIXES = (".database.windows.net", ".rds.amazonaws.com", ".database.azure.com")


def parse_data_source(data_source: str) -> tuple[str, str, str]:
    """Split a SQL Server data source into ``(hostname, port, instance_name)``.

    Faithful port of Go ``collector.parseDataSource`` (handles ``host``,
    ``host:port``, ``host,port``, ``host\\instance``, ``host\\instance,port``).
    The default port is ``"1433"``; ``instance_name`` is empty unless a backslash
    instance is present.
    """
    port = "1433"
    hostname = data_source
    instance_name = ""

    # Instance name (backslash) wins; a port may follow it after , or :.
    idx = data_source.find("\\")
    if idx != -1:
        hostname = data_source[:idx]
        remaining = data_source[idx + 1:]
        comma = remaining.find(",")
        colon = remaining.find(":")
        if comma != -1:
            instance_name = remaining[:comma]
            port = remaining[comma + 1:]
        elif colon != -1:
            instance_name = remaining[:colon]
            port = remaining[colon + 1:]
        else:
            instance_name = remaining
        return hostname, port, instance_name

    # Port via comma (host,port).
    comma = data_source.find(",")
    if comma != -1:
        return data_source[:comma], data_source[comma + 1:], ""

    # Port via colon (host:port) — but guard against a drive letter (C:\...).
    colon = data_source.rfind(":")
    if colon > 1:
        return data_source[:colon], data_source[colon + 1:], ""

    return hostname, port, instance_name


def resolve_data_source_to_sid(ad, data_source: str, domain: str) -> str:
    """Resolve a linked server's data source to its ``<computerSID>:<port>`` id.

    Faithful port of Go ``collector.resolveDataSourceToSID`` (the target/source
    endpoint id of a LinkedTo/LinkedAsAdmin edge, and the id of the foreign
    linked-server *stub* server node):

    * Cloud SQL (Azure / AWS RDS) is never SID-resolved — the host:port (or
      host:instance) string is the id.
    * Otherwise the bare machine name (everything before the first dot) is
      resolved to its AD *computer* SID via ``sAMAccountName=<machine>$``. On
      success the id is ``<SID>:<instance>`` when an instance name is present,
      else ``<SID>:<port>``.
    * On any miss (no AD client, computer not found, error) the id falls back to
      ``<hostname>:<instance|port>`` — the bare hostname string (Go fallback).

    ``domain`` is the SOURCE server's DNS domain (Go derives it from the source
    server hostname); it is currently informational here because the single shared
    :class:`AdClient` is already bound to that domain.
    """
    hostname, port, instance_name = parse_data_source(data_source)
    suffix = instance_name or port

    # Cloud SQL short-circuit (Go: never resolve a SID for these).
    low = hostname.lower()
    if any(s in low for s in _CLOUD_SUFFIXES):
        logger.verbose("Linked target %s is cloud SQL; using host:port id", data_source)
        return f"{hostname}:{suffix}"

    machine = hostname.split(".", 1)[0] if "." in hostname else hostname
    if ad is not None and machine:
        sam = machine if machine.endswith("$") else f"{machine}$"
        try:
            principal = ad.resolve_principal(sam)
        except Exception as exc:  # noqa: BLE001 - LDAP miss/error is non-fatal
            logger.warning("Linked-target SID resolution for %s failed: %s", sam, exc)
            principal = None
        sid = (principal or {}).get("sid")
        if sid:
            logger.info("Resolved linked target %s -> %s:%s", data_source, sid, suffix)
            return f"{sid}:{suffix}"
        logger.verbose("No computer object in AD for linked target %s ($%s); using hostname id",
                       data_source, machine)
    else:
        logger.verbose("No AD client/machine for linked target %s; using hostname id", data_source)

    # Fallback: bare hostname id (Go returns hostname:port / hostname:instance).
    return f"{hostname}:{suffix}"


def resolve_referenced_objects(
    ad,
    *,
    computer_sid: Optional[str],
    fqdn: str,
    server_principals: list[dict],
    service_accounts: list[dict],
    credentials: list[dict],
    proxy_accounts: list[dict],
    db_scoped_credentials: list[dict],
) -> Iterator[dict]:
    """Resolve every AD object the AD nodes reference, yielding ``ad_resolved`` rows.

    Mirrors the four Go resolution passes that run after per-server collection:

    * **Domain logins/groups** — for each AD server principal with a
      ``S-1-5-21-*`` SID, enrich it via ``resolve_sid`` (Go ``createADNodes``
      enrichment loop). The SID already exists on the principal (hex→S-1 in
      preproc); we resolve it to attach SAMAccountName / enabled / dn / dnsHostName
      / upn for the node props.
    * **Service accounts** — built-in accounts (LocalSystem / NT AUTHORITY\\*) map
      to the host computer account (``HOST$`` + the computer SID); ``NT SERVICE\\``
      virtual accounts are skipped; a real domain account is resolved by name
      (Go ``resolveServiceAccountSIDsViaLDAP`` + ``preprocessServiceAccounts``).
    * **Credentials / proxy credentials / DB-scoped credentials** — resolve the
      credential *identity* name to a domain object (Go
      ``resolveCredentialSIDsViaLDAP``); only domain (``S-1-5-21-*``) results are
      surfaced as AD nodes.

    Each resolved object is yielded **once** (deduped by SID across all sources).
    The host computer account is yielded here too (so the service-account /
    HasSession edge has a node), keyed by *computer_sid*. Yields nothing when
    *ad* is ``None``.

    Args:
        ad: shared AdClient (or None to skip).
        computer_sid: the host's resolved computer SID (or None).
        fqdn: the host FQDN (used as the computer account display name).
        server_principals: raw ``server_principals`` rows (carry ``sid`` hex +
            ``name`` + ``type_desc``).
        service_accounts: raw ``service_accounts`` rows (carry ``service_account``).
        credentials / proxy_accounts / db_scoped_credentials: raw rows carrying a
            ``credential_identity`` column.
    """
    if ad is None:
        logger.verbose("No AD client; skipping referenced-object SID resolution")
        return

    seen: set[str] = set()

    def _emit(principal: dict, *, source: str) -> Iterator[dict]:
        """Yield one ad_resolved row for *principal* (dict from resolve_*), deduped."""
        sid = (principal or {}).get("sid")
        if not sid or sid in seen:
            return
        seen.add(sid)
        logger.verbose("Resolved AD object (%s): %s -> %s", source, principal.get("name"), sid)
        yield {
            "sid": sid,
            "name": principal.get("name"),
            "type": principal.get("type"),
            "samAccountName": principal.get("samAccountName"),
            "enabled": principal.get("enabled"),
            "dn": principal.get("dn"),
            "dnsHostName": principal.get("dnsHostName"),
            "upn": principal.get("upn"),
            "source": source,
        }

    # 1) Domain logins/groups: enrich each AD server principal by its SID. The SID
    #    is the hex column on the raw row; convert it the same way preproc does.
    #    short_host enables the local-machine AD exclusion (Go !isLocalMachine) so a
    #    machine-local group (e.g. ps1-db\X) isn't resolved as a domain object.
    short_host = (fqdn or "").split(".", 1)[0]
    for row in server_principals:
        name = row.get("name") or ""
        type_desc = row.get("type_desc") or row.get("type_description") or ""
        if not _looks_ad(name, type_desc, short_host):
            continue
        sid = _sid_to_string(row.get("sid"))
        if not sid.startswith(_DOMAIN_SID_PREFIX):
            continue
        principal = _resolve_sid(ad, sid)
        if principal:
            yield from _emit(principal, source="server_principal")

    # 2) Service accounts. Built-in accounts use the host computer account; real
    #    domain accounts are resolved by name. The host computer node itself is
    #    always emitted when we have its SID (HasSession edge target).
    if computer_sid:
        # Host computer account: synthesize a resolved object from the computer SID
        # + FQDN (Go createADNodes builds the host Computer node from ServerInfo).
        yield from _emit(
            {
                "sid": computer_sid,
                "name": fqdn,
                "type": "computer",
                "samAccountName": None,
                "enabled": True,
                "dn": None,
                "dnsHostName": fqdn,
                "upn": None,
            },
            source="host_computer",
        )

    for row in service_accounts:
        account = (row.get("service_account") or "").strip()
        if not account:
            continue
        upper = account.upper()
        if any(upper.startswith(prefix) for prefix in _NON_AD_SA_PREFIXES):
            # NT SERVICE\* / NT AUTHORITY\* — built-ins map to the computer account
            # (already emitted above via computer_sid); virtual accounts are skipped.
            logger.verbose("Service account %s is local/virtual; not resolved as AD object", account)
            continue
        principal = _resolve_name(ad, account)
        if principal and (principal.get("sid") or "").startswith(_DOMAIN_SID_PREFIX):
            yield from _emit(principal, source="service_account")

    # 3) Server-level / proxy / DB-scoped credential identities (resolved by name).
    for source, rows in (
        ("credential", credentials),
        ("proxy_credential", proxy_accounts),
        ("db_scoped_credential", db_scoped_credentials),
    ):
        for row in rows:
            identity = (row.get("credential_identity") or "").strip()
            if not identity:
                continue
            principal = _resolve_name(ad, identity)
            if principal and (principal.get("sid") or "").startswith(_DOMAIN_SID_PREFIX):
                yield from _emit(principal, source=source)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _resolve_sid(ad, sid: str) -> Optional[dict]:
    """Best-effort ``ad.resolve_sid`` (logs + returns None on error)."""
    try:
        return ad.resolve_sid(sid)
    except Exception as exc:  # noqa: BLE001 - LDAP miss/error is non-fatal
        logger.warning("resolve_sid(%s) failed: %s", sid, exc)
        return None


def _resolve_name(ad, name: str) -> Optional[dict]:
    """Best-effort ``ad.resolve_principal`` (logs + returns None on error)."""
    try:
        return ad.resolve_principal(name)
    except Exception as exc:  # noqa: BLE001 - LDAP miss/error is non-fatal
        logger.warning("resolve_principal(%s) failed: %s", name, exc)
        return None


# Pseudo-authorities that prefix a local/built-in account name (never AD). Same
# set transforms._NON_AD_PREFIXES uses.
_NON_AD_PREFIXES = ("NT SERVICE\\", "NT AUTHORITY\\", "BUILTIN\\")


def _looks_ad(name: str, type_desc: str, short_host: str = "") -> bool:
    """Reproduce client.go ``IsActiveDirectoryPrincipal`` (same as transforms).

    Excludes NT SERVICE / NT AUTHORITY / BUILTIN AND local-machine
    (``<MACHINENAME>\\...``) accounts (Go ``!isLocalMachine``).
    """
    if type_desc not in ("WINDOWS_LOGIN", "WINDOWS_GROUP"):
        return False
    if "\\" not in name:
        return False
    upper = name.upper()
    if any(upper.startswith(prefix) for prefix in _NON_AD_PREFIXES):
        return False
    if short_host and upper.startswith(short_host.upper() + "\\"):
        return False
    return True


def _sid_to_string(hex_sid) -> str:
    """Convert a ``0x...`` hex SID to ``S-1-...`` form (shared with transforms).

    Duplicated from ``transforms._sid_to_string`` so collection has no dependency
    on the preproc module; both are faithful ports of client.go
    ``convertHexSIDToString``.
    """
    if not hex_sid:
        return ""
    text = str(hex_sid)
    if text in ("0x", "0x01"):
        return ""
    if text.lower().startswith("0x"):
        text = text[2:]
    try:
        raw = bytes.fromhex(text)
    except ValueError:
        return text if text.startswith("S-1-") else ""
    if len(raw) < 8 or raw[0] != 1:
        return ""
    sub_auth_count = raw[1]
    if len(raw) < 8 + sub_auth_count * 4:
        return ""
    authority = int.from_bytes(raw[2:8], "big")
    parts = [f"S-{raw[0]}-{authority}"]
    for i in range(sub_auth_count):
        offset = 8 + i * 4
        parts.append(str(int.from_bytes(raw[offset:offset + 4], "little")))
    return "-".join(parts)


def resolve_linked_server_source_id(ad, source_server: str, domain: str) -> str:
    """Resolve a chained link's SOURCE server id (Go ``resolveLinkedServerSourceID``).

    Used when a discovered linked-server row's ``source_server`` is a DIFFERENT
    host than the server being collected (a chained link, e.g. ``CAS-DB`` ->
    ``ps1-db`` discovered while probing ps1-db's link to CAS-DB). Resolves the
    source to ``<SID>:<port>``; if the SID can't be resolved (the result is not an
    ``S-1-5-`` SID), falls back to ``LinkedServer:<source_server>`` — exactly the
    Go fallback (distinct from the target fallback, which is ``hostname:port``).
    """
    resolved = resolve_data_source_to_sid(ad, source_server, domain)
    if resolved.startswith("S-1-5-"):
        return resolved
    return f"LinkedServer:{source_server}"


__all__ = [
    "resolve_computer_sid",
    "resolve_referenced_objects",
    "parse_data_source",
    "resolve_data_source_to_sid",
    "resolve_linked_server_source_id",
]
