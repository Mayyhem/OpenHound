"""Preproc-derived ``ad_nodes`` table (Stage 7a) — the Active Directory nodes the
MSSQL graph attaches edges to.

``build_ad_nodes(con, schema)`` reproduces Go ``createADNodes``
(``MSSQLHound/internal/collector/collector.go``): it scans the raw server
principals, the ``servers`` row, the collect-time ``ad_resolved`` resolutions, and
the EPA setting, and writes one deduped row per AD principal that needs a node.
The convert AD asset (``models/ad_node.py``) then emits each row as an OpenGraph
node — kinds ``[Computer|User|Group, "Base"]``, **no icon**, ids that are SIDs
(or ``<host>-<SID>`` for local groups, ``<domain>-S-1-5-11`` for Authenticated
Users), and the LDAP-enriched property bag.

Node kinds + gating, verbatim from Go ``createADNodes``:

1. **Host Computer** — id = the host computer SID; props name=FQDN, DNSHostName,
   domain, SID, SAMAccountName=``HOST$``, isDomainPrincipal=true. Always when the
   computer SID was resolved.
2. **Authenticated Users Group** — id ``<domain>-S-1-5-11`` (or ``S-1-5-11`` with
   no domain); only when ExtendedProtection is ``Off`` AND there is an enabled AD
   *computer-account* login (name ends ``$``, ``S-1-5-21-*`` SID) — the
   MSSQL_CoerceAndRelayToMSSQL precondition. Props: name only.
3. **Domain principals with logins** — User/Group/Computer per the login name; id =
   SID; gated on AD principal + SID under the domain SID + not disabled + has
   CONNECT SQL (direct grant or sysadmin/securityadmin membership). NetBIOS-
   stripped ``name@DOMAIN`` display name; enriched from ``ad_resolved``.
4. **Local groups** — Group; id ``<host>-<SID>``; BUILTIN (``S-1-5-32-*``) or a
   machine-local ``WINDOWS_GROUP`` (``S-1-5-21-*`` not under the domain SID); not
   disabled + has CONNECT SQL. Props: name + isActiveDirectoryPrincipal only.
5. **Service accounts** — User/Computer; id = SID (must be ``S-1-5-21-*``); built-
   in accounts already covered by the host Computer node. Enriched from
   ``ad_resolved``.
6. **Credential / proxy / DB-scoped-credential identities** — User/Group/Computer
   per the resolved object class; id = SID (``S-1-5-21-*``). From ``ad_resolved``.

Dedupe is by node id (first writer wins), exactly like Go's ``createdNodes`` map.
The whole table is empty when ``--skip-ad-nodes`` is set (the builder is simply
not called) — convert then emits no AD nodes.
"""
from __future__ import annotations

import logging
from typing import Optional

import duckdb

from . import ids
from .kinds import nodes as nk

logger = logging.getLogger(__name__)

# Well-known SID prefixes (Go uses these literal HasPrefix checks).
_DOMAIN_SID_PREFIX = "S-1-5-21-"
_BUILTIN_SID_PREFIX = "S-1-5-32-"
# Authenticated Users well-known SID (Go prefixes it with the domain).
_AUTHENTICATED_USERS_SID = "S-1-5-11"

# The fixed roles that grant implicit CONNECT SQL (Go createADNodes hasConnectSQL).
_IMPLICIT_CONNECT_ROLES = ("sysadmin", "securityadmin")

# Permission state that counts as a grant (DENY never grants CONNECT SQL).
_GRANT_STATES = ("GRANT", "GRANT_WITH_GRANT_OPTION")

# Pseudo-authorities that prefix a local/built-in account name (never AD).
_NON_AD_PREFIXES = ("NT SERVICE\\", "NT AUTHORITY\\", "BUILTIN\\")


# ---------------------------------------------------------------------------
# Pure node-shape helpers (covered directly by tests/unit/test_ad_nodes.py)
# ---------------------------------------------------------------------------
def kinds_for(name: str, object_class: Optional[str], type_desc: str) -> list[str]:
    """Pick the AD node kinds for a principal (Go ``createADNodes`` kind switch).

    The Go code decides the kind in two ways depending on the source:

    * For logins / service accounts it keys off the *name* (``$`` suffix ->
      Computer) then the *type_desc* (``GROUP`` -> Group), else User.
    * For resolved credential identities it keys off the LDAP *objectClass*
      (computer/group/user).

    *object_class* (when known) wins; otherwise the name/type_desc heuristic is
    used. Every AD node carries the secondary ``Base`` kind and no icon.
    """
    if object_class:
        oc = object_class.lower()
        if oc == "computer":
            return [nk.COMPUTER, nk.BASE]
        if oc == "group":
            return [nk.GROUP, nk.BASE]
        if oc == "user":
            return [nk.USER, nk.BASE]
    # Name/type heuristic (Go: `$` suffix -> Computer; "GROUP" in type -> Group).
    if name.endswith("$"):
        return [nk.COMPUTER, nk.BASE]
    if "GROUP" in (type_desc or "").upper():
        return [nk.GROUP, nk.BASE]
    return [nk.USER, nk.BASE]


def display_name(raw_name: str, domain: str) -> str:
    """NetBIOS-strip a login name and append ``@DOMAIN`` (Go ``createADNodes``).

    ``CONTOSO\\jdoe`` -> ``jdoe@CONTOSO.COM``; an already-``@``-qualified name is
    left as-is. A name with no domain qualifier and no domain configured is
    returned unchanged.
    """
    name = raw_name
    idx = name.find("\\")
    if idx != -1:
        name = name[idx + 1:]
    if domain and "@" not in name:
        name = f"{name}@{domain}"
    return name


def authenticated_users_id(domain: str) -> str:
    """The Authenticated Users node id (``<domain>-S-1-5-11`` or ``S-1-5-11``)."""
    return f"{domain}-{_AUTHENTICATED_USERS_SID}" if domain else _AUTHENTICATED_USERS_SID


def local_group_id(hostname: str, sid: str) -> str:
    """The local-group node id (``<host>-<SID>``, Go ``serverFQDN-SID``)."""
    return f"{hostname}-{sid}"


def has_connect_sql(direct_permissions: set[str], member_roles: set[str]) -> bool:
    """Whether a principal effectively has CONNECT SQL (Go ``hasConnectSQL``).

    True when CONNECT SQL is directly granted, OR the principal is a member of
    sysadmin / securityadmin (which carry implicit CONNECT SQL). *direct_permissions*
    is the set of GRANT/GRANT_WITH_GRANT_OPTION permission names; *member_roles* is
    the set of role names the principal is a direct member of.
    """
    if "CONNECT SQL" in direct_permissions:
        return True
    return any(role in member_roles for role in _IMPLICIT_CONNECT_ROLES)


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------
def build_ad_nodes(con: duckdb.DuckDBPyConnection, schema: str, server_oid: Optional[str]) -> None:
    """Build the ``ad_nodes`` derived table (Go ``createADNodes``).

    Reads the raw ``servers`` / ``server_principals`` / ``server_permissions`` /
    ``server_role_members`` / ``ad_resolved`` tables and writes one deduped
    ``ad_nodes`` row per AD principal that needs a node. Always (re)creates the
    table — empty when there is nothing to emit — so the convert asset's read
    always binds.
    """
    rows: list[tuple] = []
    seen: set[str] = set()

    def add(node_id: str, kinds: list[str], props: dict) -> None:
        """Append one node row, deduped by id (first writer wins, like Go)."""
        if not node_id or node_id in seen:
            return
        seen.add(node_id)
        rows.append((
            node_id,
            kinds,
            props.get("name"),
            props.get("SID"),
            props.get("domain"),
            props.get("isDomainPrincipal"),
            props.get("SAMAccountName"),
            props.get("isActiveDirectoryPrincipal"),
            props.get("isEnabled"),
            props.get("distinguishedName"),
            props.get("userPrincipalName"),
            props.get("DNSHostName"),
        ))

    server_row = _fetch_one(con, f"SELECT * FROM {schema}.servers LIMIT 1", "servers")
    domain = ""
    fqdn = ""
    hostname = ""
    short_host = ""
    computer_sid = None
    extended_protection = ""
    if server_row is not None:
        fqdn = str(_get(server_row, "fqdn") or "")
        machine = _get(server_row, "machine_name", "MachineName") or _get(server_row, "server_name", "ServerName") or ""
        # Local-group node ids key off Go's serverInfo.Hostname, which is the
        # connection host (the FQDN we resolved at collect), falling back to the
        # bare MachineName. The short host is used for the HOST$ SAMAccountName.
        hostname = fqdn or str(machine).split("\\", 1)[0]
        short_host = hostname.split(".", 1)[0]
        computer_sid = _get(server_row, "computer_sid", "computersid") or None
        extended_protection = str(_get(server_row, "extended_protection", "extendedProtection") or "")
        # The collection domain isn't stamped on the row; derive it from the FQDN
        # suffix. Go uppercases the domain everywhere it builds AD nodes
        # (main.go `Domain: strings.ToUpper(domain)`), so the Authenticated Users
        # id is `MAYYHEM.COM-S-1-5-11` and AD display names are `name@MAYYHEM.COM`.
        # The server FQDN itself stays lowercase (it is a DNS name); only the
        # AD-node domain suffix is uppercased here, matching Go.
        domain = _domain_from_fqdn(fqdn).upper()

    # ad_resolved: SID -> resolved object dict. dlt snake_cases the collected
    # camelCase keys when it loads the JSONL (samAccountName -> sam_account_name,
    # dnsHostName -> dns_host_name), so normalize each row back to the camelCase
    # shape _enrich expects (accepting both forms defensively).
    resolved_by_sid = {}
    for r in _fetch_all(con, f"SELECT * FROM {schema}.ad_resolved", "ad_resolved"):
        sid = r.get("sid")
        if not sid:
            continue
        resolved_by_sid[sid] = {
            "sid": sid,
            "name": _get(r, "name"),
            "type": _get(r, "type"),
            "samAccountName": _get(r, "sam_account_name", "samAccountName"),
            "enabled": _get(r, "enabled"),
            "dn": _get(r, "dn"),
            "dnsHostName": _get(r, "dns_host_name", "dnsHostName"),
            "upn": _get(r, "upn"),
        }

    # Load principals with the fields the gating needs. short_host enables the
    # local-machine AD exclusion (Go IsActiveDirectoryPrincipal !isLocalMachine).
    principals = _load_principals(con, schema, short_host)
    domain_sid = _domain_sid(principals)

    # 1) Host Computer node (Go: ServerInfo.ComputerSID present).
    if computer_sid:
        sam = f"{short_host.upper()}$" if short_host else None
        add(str(computer_sid), [nk.COMPUTER, nk.BASE], {
            "name": fqdn or hostname,
            "DNSHostName": fqdn or None,
            "domain": domain or None,
            "isDomainPrincipal": True,
            "SID": str(computer_sid),
            "SAMAccountName": sam,
        })

    # 2) Authenticated Users (Go: EPA Off + an enabled AD computer-account login).
    if extended_protection == "Off" and _needs_auth_users(principals, domain_sid):
        add(authenticated_users_id(domain), [nk.GROUP, nk.BASE], {
            "name": f"AUTHENTICATED USERS@{domain}",
        })

    # 3) Domain principals with logins (Go: AD + under domain SID + enabled + connect).
    for p in principals:
        if not p.is_ad or not p.sid.startswith(_DOMAIN_SID_PREFIX):
            continue
        if not domain_sid or not p.sid.startswith(domain_sid + "-"):
            continue
        if p.is_disabled or not has_connect_sql(p.perms, set(p.member_of)):
            continue
        resolved = resolved_by_sid.get(p.sid)
        props = {
            "name": display_name(p.name, domain),
            "isDomainPrincipal": True,
            "SID": p.sid,
        }
        _enrich(props, resolved)
        add(p.sid, kinds_for(p.name, (resolved or {}).get("type"), p.type_desc), props)

    # 4) Local groups (Go: BUILTIN or machine-local WINDOWS_GROUP + enabled + connect).
    for p in principals:
        if not p.sid:
            continue
        is_local_group = p.sid.startswith(_BUILTIN_SID_PREFIX) or (
            p.type_desc == "WINDOWS_GROUP"
            and p.sid.startswith(_DOMAIN_SID_PREFIX)
            and (not domain_sid or not p.sid.startswith(domain_sid + "-"))
        )
        if not is_local_group:
            continue
        if p.is_disabled or not has_connect_sql(p.perms, set(p.member_of)):
            continue
        add(local_group_id(hostname, p.sid), [nk.GROUP, nk.BASE], {
            "name": p.name,
            "isActiveDirectoryPrincipal": p.is_ad,
        })

    # 5) + 6) Service accounts + credential identities (resolved at collect; domain
    # SID only). The host computer account is among these but is deduped by #1.
    #
    # `ad_resolved` also contains the resolved DOMAIN LOGINS (resolved at collect to
    # enrich the section-3 nodes). A login is NOT a standalone AD node in Go — it is
    # handled by section 3 with the enabled + CONNECT-SQL gate, so a disabled /
    # no-CONNECT login must NOT get a node here. Only genuine service-account /
    # credential / proxy identities (which are not server principals) belong in 5/6.
    principal_sids = {p.sid for p in principals if p.sid}
    for sid, resolved in resolved_by_sid.items():
        if not sid.startswith(_DOMAIN_SID_PREFIX):
            continue
        if sid in principal_sids:
            continue
        name = resolved.get("name") or ""
        props = {
            "name": display_name(name, domain),
            "isDomainPrincipal": True,
            "SID": sid,
        }
        _enrich(props, resolved)
        add(sid, kinds_for(name, resolved.get("type"), ""), props)

    _create_ad_nodes_table(con, schema, rows)
    logger.info("transforms: ad_nodes built (%d node(s)) for server_oid=%s", len(rows), server_oid)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
class _ADPrincipal:
    """A server principal with the fields the AD-node gating needs."""

    __slots__ = ("principal_id", "name", "type_desc", "is_disabled", "is_ad", "sid",
                 "member_of", "perms")

    def __init__(self, principal_id, name, type_desc, is_disabled, is_ad, sid):
        self.principal_id = principal_id
        self.name = name
        self.type_desc = type_desc
        self.is_disabled = is_disabled
        self.is_ad = is_ad
        self.sid = sid
        self.member_of: list[str] = []
        self.perms: set[str] = set()


def _load_principals(con: duckdb.DuckDBPyConnection, schema: str, short_host: str = "") -> list[_ADPrincipal]:
    """Load server principals + their direct GRANT permissions + role memberships.

    Unlike transforms._load_server_principals this keeps the raw ``is_disabled``
    flag and does NOT add implicit ``public`` membership — the connect-SQL check
    only honours explicit sysadmin/securityadmin membership (Go ``createADNodes``).
    *short_host* enables the local-machine AD exclusion.
    """
    principals: list[_ADPrincipal] = []
    by_id: dict[int, _ADPrincipal] = {}
    for r in _fetch_all(con, f"SELECT * FROM {schema}.server_principals", "server_principals"):
        pid = _as_int(_get(r, "principal_id"))
        if pid is None:
            continue
        name = _get(r, "name") or ""
        type_desc = _get(r, "type_desc", "type_description") or ""
        is_disabled = _as_bool(_get(r, "is_disabled"))
        sid = _sid_to_string(_get(r, "sid"))
        is_ad = _is_ad_principal(name, type_desc, short_host)
        p = _ADPrincipal(pid, name, type_desc, is_disabled, is_ad, sid)
        principals.append(p)
        by_id[pid] = p

    for rm in _fetch_all(con, f"SELECT * FROM {schema}.server_role_members", "server_role_members"):
        member_id = _as_int(_get(rm, "member_principal_id"))
        role_name = _get(rm, "role_name") or ""
        member = by_id.get(member_id) if member_id is not None else None
        if member is not None and role_name:
            member.member_of.append(role_name)

    for perm in _fetch_all(con, f"SELECT * FROM {schema}.server_permissions", "server_permissions"):
        grantee = _as_int(_get(perm, "grantee_principal_id"))
        state = (_get(perm, "state_desc") or "").upper()
        name = _get(perm, "permission_name") or ""
        owner = by_id.get(grantee) if grantee is not None else None
        if owner is not None and name and state in _GRANT_STATES:
            owner.perms.add(name)

    return principals


def _needs_auth_users(principals: list[_ADPrincipal], domain_sid: str) -> bool:
    """Whether the Authenticated Users node is needed (Go createADNodes condition).

    True when there is an enabled AD computer-account login (name ends ``$``,
    ``S-1-5-21-*`` SID) — the MSSQL_CoerceAndRelayToMSSQL precondition. (The EPA-Off
    check is applied by the caller.)
    """
    for p in principals:
        if (p.is_ad and p.sid.startswith(_DOMAIN_SID_PREFIX)
                and p.name.endswith("$") and not p.is_disabled):
            return True
    return False


def _enrich(props: dict, resolved: Optional[dict]) -> None:
    """Copy LDAP attributes from a resolved object onto *props* (Go enrichment).

    Sets SAMAccountName / domain / isEnabled always when resolved, and the
    distinguishedName / DNSHostName / userPrincipalName only when non-empty
    (matching Go's conditional ``if resolved.X != ""``).
    """
    if not resolved:
        return
    props["SAMAccountName"] = resolved.get("samAccountName")
    props["isEnabled"] = resolved.get("enabled")
    # Keep the SID-prefix-derived domain unless the resolved object carries one.
    if resolved.get("domain"):
        props["domain"] = resolved.get("domain")
    if resolved.get("dn"):
        props["distinguishedName"] = resolved.get("dn")
    if resolved.get("dnsHostName"):
        props["DNSHostName"] = resolved.get("dnsHostName")
    if resolved.get("upn"):
        props["userPrincipalName"] = resolved.get("upn")


def _domain_from_fqdn(fqdn: str) -> str:
    """Return the DNS domain suffix of *fqdn* (everything after the first dot)."""
    if not fqdn or "." not in fqdn:
        return ""
    return fqdn.split(".", 1)[1]


# The explicit ad_nodes column schema (id + kinds array + each ADProperties field).
_AD_NODE_COLUMNS = [
    ("id", "VARCHAR"), ("kinds", "VARCHAR[]"), ("name", "VARCHAR"),
    ("SID", "VARCHAR"), ("domain", "VARCHAR"), ("isDomainPrincipal", "BOOLEAN"),
    ("SAMAccountName", "VARCHAR"), ("isActiveDirectoryPrincipal", "BOOLEAN"),
    ("isEnabled", "BOOLEAN"), ("distinguishedName", "VARCHAR"),
    ("userPrincipalName", "VARCHAR"), ("DNSHostName", "VARCHAR"),
]


def _create_ad_nodes_table(con: duckdb.DuckDBPyConnection, schema: str, rows: list[tuple]) -> None:
    """(Re)create ``schema.ad_nodes`` with the explicit typed schema + rows."""
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    coldefs = ", ".join(f'"{name}" {sqltype}' for name, sqltype in _AD_NODE_COLUMNS)
    con.execute(f"CREATE OR REPLACE TABLE {schema}.ad_nodes ({coldefs})")
    if not rows:
        return
    placeholders = ", ".join(["?"] * len(_AD_NODE_COLUMNS))
    con.executemany(f"INSERT INTO {schema}.ad_nodes VALUES ({placeholders})", rows)


# ---------------------------------------------------------------------------
# Row / SID helpers (duplicated from transforms to keep this module standalone)
# ---------------------------------------------------------------------------
def _fetch_all(con: duckdb.DuckDBPyConnection, sql: str, label: str) -> list[dict]:
    try:
        cur = con.execute(sql)
    except duckdb.CatalogException as err:
        logger.warning("ad_nodes: source table for %r missing: %s", label, err)
        return []
    except duckdb.Error as err:
        logger.error("ad_nodes: query for %r failed: %s", label, err)
        return []
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def _fetch_one(con: duckdb.DuckDBPyConnection, sql: str, label: str) -> Optional[dict]:
    rows = _fetch_all(con, sql, label)
    return rows[0] if rows else None


def _get(row: dict, *names: str):
    for name in names:
        if name in row and row[name] is not None:
            return row[name]
    return None


def _as_int(value) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "t", "yes", "y")
    return False


def _is_ad_principal(name: str, type_desc: str, short_host: str = "") -> bool:
    """client.go ``IsActiveDirectoryPrincipal`` (same as transforms._is_ad_principal).

    Excludes NT SERVICE / NT AUTHORITY / BUILTIN AND local-machine
    (``<MACHINENAME>\\...``) accounts (Go ``!isLocalMachine``), so a machine-local
    group is treated as a local group (``<host>-<SID>`` HasLogin) rather than a
    domain principal.
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


def _domain_sid(principals: list[_ADPrincipal]) -> str:
    """Derive the domain SID from the first AD principal's SID (client.go parity)."""
    for p in principals:
        if p.is_ad and p.sid.startswith(_DOMAIN_SID_PREFIX):
            idx = p.sid.rfind("-")
            if idx > 0:
                return p.sid[:idx]
    return ""


def _sid_to_string(hex_sid) -> str:
    """``0x...`` hex SID -> ``S-1-...`` (port of client.go convertHexSIDToString)."""
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


__all__ = [
    "build_ad_nodes",
    "kinds_for",
    "display_name",
    "authenticated_users_id",
    "local_group_id",
    "has_connect_sql",
]
