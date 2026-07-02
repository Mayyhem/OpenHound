"""DuckDB derived/lookup tables for the MSSQL collector's preproc phase.

``transforms(con)`` reads the raw JSONL tables that ``preproc`` loaded into the
``mssql`` schema and builds the *derived* tables that ``convert`` needs to emit
nodes and edges. Everything here is **collector-agnostic**: it operates only on
the raw rows in DuckDB, never on a live SQL Server.

The derived tables reproduce MSSQLHound's in-memory derivation (Go
``internal/collector/collector.go`` + the ``.ps1`` ``Get-NestedRoleMembership`` /
``Get-EffectivePermissions`` / ``$fixed*RolePermissions`` tables):

* ``server_principal_map``  — (server_oid, principal_id) -> object_identifier,
  name, type_description, is_fixed_role, resolved SID, is_ad_principal.
* ``database_principal_map`` — (server_oid, database, principal_id) -> oid/name/
  type/is_fixed_role/sid.
* ``server_role_closure``    — transitive (nested) server-role membership
  (member_oid -> role_oid), including the implicit ``public`` role.
* ``database_role_closure``  — transitive (nested) database-role membership,
  scoped per database, including the implicit ``public`` role.
* ``effective_high_priv``    — per server: which principals (and which *domain*
  principals) effectively have sysadmin / CONTROL SERVER / securityadmin /
  IMPERSONATE ANY LOGIN (direct grant OR via nested role OR via fixed-role
  implication), plus ``is_any_domain_principal_sysadmin``. Feeds the server
  node's ``domainPrincipalsWith*`` props and the GetAdminTGS / GetTGS edges.
* ``server_fixed_role_permissions`` / ``database_fixed_role_permissions`` — the
  implicit permissions a fixed role confers (sysadmin -> CONTROL SERVER;
  db_owner -> CONTROL on DB; db_securityadmin -> GrantAnyDBPermission /
  AlterAnyRole / AlterAnyApplicationRole; securityadmin -> ALTER ANY LOGIN; ...).
* ``linked_server_flags``    — per linked server: resolved target + the remote
  sysadmin/securityadmin/controlserver/impersonateanylogin/mixedmode flags and
  the ``LinkedAsAdmin`` precondition.

Why the graph walks are done in Python (not recursive SQL): the algorithm is a
faithful port of the Go BFS/DFS, and reading the few thousand principal/role rows
into memory, walking them, then writing the closures back is far more readable
than a DuckDB ``WITH RECURSIVE`` (project rule: readability over efficiency). The
row counts are bounded by one server's catalog, so memory is not a concern.

**Server scope (decision, surfaced 2026-06-25):** the raw rows from ``collect``
are NOT stamped with a per-server identifier — the push->pull bridge yields bare
rows (``collection/run.py``). So Stage 4 derives a *single* ``server_oid`` from
the one ``servers`` row and stamps it onto every derived table. This is correct
for the single-target lab/verify runs (and any single-target collection). A
multi-server bucket would need ``collect`` to tag each raw row with its server
(a Stage 3 follow-up); until then the derived tables collapse all servers'
principals under one server_oid. The ``server_oid`` column is present on every
derived table so a future per-row tag drops in without reshaping ``convert``.
"""
from __future__ import annotations

import logging
from collections import deque
from typing import Iterable, Optional

import duckdb

from openhound_collector_common.dlt.duckdb_safe import ensure_columns, safe_execute
from openhound_collector_common.logging import log_context  # noqa: F401  (registers logger.verbose)

from . import ids

logger = logging.getLogger(__name__)

# Default SQL Server port. The raw ``servers`` row carries no port (collect never
# queries it), so a default instance falls back to this when keyed by port.
_DEFAULT_PORT = 1433

# Fixed *server* role -> implied permission(s) it confers, matching the Go
# ``fixedServerRolePermissions`` table (collector.go) / PS1 $fixedServerRolePermissions.
# sysadmin implicitly holds every permission; CONTROL SERVER is the effective grant.
FIXED_SERVER_ROLE_PERMISSIONS: dict[str, list[str]] = {
    "sysadmin": ["CONTROL SERVER"],
    "securityadmin": ["ALTER ANY LOGIN"],
    # SQL Server 2022+ fixed roles (createFixedRoleEdges special-cases these too).
    "##MS_LoginManager##": ["ALTER ANY LOGIN"],
    "##MS_DatabaseConnector##": ["CONNECT ANY DATABASE"],
}

# Fixed *database* role -> implied permission(s), matching createFixedRoleEdges'
# db switch (collector.go). db_owner has CONTROL on the database;
# db_securityadmin can grant any DB permission and alter roles/app-roles.
FIXED_DATABASE_ROLE_PERMISSIONS: dict[str, list[str]] = {
    "db_owner": ["CONTROL"],
    "db_securityadmin": [
        "GRANT ANY DATABASE PERMISSION",
        "ALTER ANY APPLICATION ROLE",
        "ALTER ANY ROLE",
    ],
}

# The four effective-high-privilege checks the server node + Kerberoasting edges
# need. sysadmin / securityadmin are *role-membership* checks (nested); CONTROL
# SERVER / IMPERSONATE ANY LOGIN are *effective-permission* checks (direct grant,
# inherited via role, or implied by a fixed role). Mirrors collector.go's two
# domainPrincipalsWith* passes.
_ROLE_HIGH_PRIV = ("sysadmin", "securityadmin")
_PERM_HIGH_PRIV = ("CONTROL SERVER", "IMPERSONATE ANY LOGIN")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def transforms(con: duckdb.DuckDBPyConnection, schema: str = "mssql") -> None:
    """Build every derived table ``convert`` reads.

    Each builder is defensive: a missing or empty raw table logs and produces an
    empty (but correctly-shaped) derived table so ``convert`` never crashes on a
    not-yet-collected source. Builders run in dependency order — the principal
    maps and role closures first, then effective-high-priv (which reads them).

    Args:
        con: DuckDB connection holding the loaded raw tables.
        schema: Schema name the raw tables live in (``mssql``).
    """
    server_oid = _derive_server_oid(con, schema)
    if server_oid is None:
        # No servers row -> nothing to derive. Still create empty derived tables
        # so convert's SELECTs bind (build_* short-circuit to an empty table).
        logger.warning("transforms: no rows in %s.servers; building empty derived tables", schema)

    logger.info("transforms: deriving tables for server_oid=%s", server_oid)

    short_host = _server_short_host(con, schema)
    server_principals = _load_server_principals(con, schema, server_oid, short_host)
    database_principals = _load_database_principals(con, schema, server_oid)

    _build_server_principal_map(con, schema, server_principals)
    _build_database_principal_map(con, schema, database_principals)

    server_closure = _build_server_role_closure(con, schema, server_principals)
    _build_database_role_closure(con, schema, database_principals)

    _build_server_fixed_role_permissions(con, schema, server_principals)
    _build_database_fixed_role_permissions(con, schema, database_principals)

    _build_effective_high_priv(con, schema, server_oid, server_principals, server_closure)

    _build_linked_server_flags(con, schema, server_oid)

    # Stage 7b: foreign linked-server stub nodes (a distinct MSSQL_Server node per
    # remote host a linked server points at, e.g. CAS-DB) + the primary node's
    # self-reference flag for loopback links. Reads linked_server_flags (whose
    # resolved_target/resolved_source were resolved to <computerSID>:<port> at
    # collect time). Imported leaf-locally to keep transforms' top clean.
    from .linked_server_nodes import build_linked_server_targets

    build_linked_server_targets(con, schema, server_oid)

    # Stage 7a: build the AD node table (host Computer, Authenticated Users, domain
    # principals with logins, local groups, service accounts, credential
    # identities) from the raw principals + the collect-time ad_resolved table.
    # Gated by --skip-ad-nodes (SOURCES__MSSQL__SKIP_AD_NODES): when set, the
    # ad_nodes table is created empty so the convert read still binds but emits
    # nothing. Imported here (not at module top) to keep the dependency leaf-local.
    from .ad_nodes import build_ad_nodes
    from .auth import _env_bool

    if _env_bool("SKIP_AD_NODES"):
        logger.info("transforms: --skip-ad-nodes set; building empty ad_nodes table")
        build_ad_nodes_empty(con, schema)
    else:
        build_ad_nodes(con, schema, server_oid)

    # Stage 6: derive every server/database/structural/fixed-role edge into the
    # graph_edges table convert reads back via the shared GraphEdge model. Runs
    # LAST so it can read the principal maps / role closures / effective-high-priv
    # tables built above (the CVE ChangePassword gate + ExecuteAsOwner owner check
    # need the effective_high_priv flags). Imported here (not at module top) to
    # avoid a cycle: edge_rules -> edges.derive -> models -> ids/kinds, all of
    # which are leaf modules, but the import is cheap and keeps transforms' top
    # clean.
    from .edge_rules import build_graph_edges

    build_graph_edges(con, schema)

    logger.info("transforms: derived-table build complete for server_oid=%s", server_oid)


def build_ad_nodes_empty(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Create an empty ``ad_nodes`` table (used when --skip-ad-nodes is set)."""
    from .ad_nodes import _create_ad_nodes_table

    _create_ad_nodes_table(con, schema, [])


# ---------------------------------------------------------------------------
# server_oid derivation (single-server scope — see module docstring)
# ---------------------------------------------------------------------------
def _derive_server_oid(con: duckdb.DuckDBPyConnection, schema: str) -> Optional[str]:
    """Compute the one server_oid from the ``servers`` raw row.

    Mirrors ``ids.server_oid`` / collector.go ``addServerToProcess``: prefer the
    resolved computer SID (Stage 7a stamps the ``computer_sid`` column at collect
    time), else the lowercased hostname; a named instance keys by instance name,
    otherwise by port. The raw ``servers`` row carries ``ServerName`` /
    ``MachineName`` / ``InstanceName`` / (Stage 7a) ``computer_sid`` but no port,
    so we fall back to the default port. Returns ``None`` if there is no servers
    row.
    """
    row = _fetch_one(
        con,
        f"SELECT * FROM {schema}.servers LIMIT 1",
        "servers",
    )
    if row is None:
        return None

    # dlt snake_cases the collected camelCase keys (MachineName -> machine_name).
    # Accept the snake_case form first, then the originals defensively.
    machine = (
        _get(row, "machine_name", "MachineName", "machinename")
        or _get(row, "server_name", "ServerName", "servername")
        or ""
    )
    instance = _get(row, "instance_name", "InstanceName", "instancename") or ""
    # Stage 7a: the resolved computer SID keys the OID (<computerSID>:<port>),
    # matching Go; absent on a non-domain host -> fall back to the hostname.
    computer_sid = _get(row, "computer_sid", "computersid") or None
    # MachineName can be HOST or HOST\INSTANCE; take the bare host for the key base.
    hostname = str(machine).split("\\", 1)[0] if machine else ""
    if not hostname:
        logger.warning("transforms: servers row has no MachineName/ServerName; server_oid will be blank")
    server_oid = ids.server_oid(
        str(computer_sid) if computer_sid else None,
        hostname, str(instance) if instance else None, _DEFAULT_PORT,
    )
    logger.verbose("transforms: derived server_oid=%s (host=%s instance=%s computerSID=%s)",
                   server_oid, hostname, instance, computer_sid)
    return server_oid


# ---------------------------------------------------------------------------
# Raw-row loaders (read once, walk in Python)
# ---------------------------------------------------------------------------
class _Principal:
    """A server- or database-level principal with its role memberships + perms.

    Reproduces the fields of the Go ``ServerPrincipal`` / ``DatabasePrincipal``
    that the derivation walks: identity, type, fixed-role flag, AD-ness, SID, the
    set of role *names* it is a direct member of (``member_of``), and its direct
    *granted* permission names (``perms``, DENY excluded — DENY never confers an
    effective grant in the Go BFS).
    """

    __slots__ = (
        "principal_id", "name", "type_desc", "is_fixed_role", "is_ad", "sid",
        "object_identifier", "member_of", "perms", "database",
    )

    def __init__(self, principal_id: int, name: str, type_desc: str,
                 is_fixed_role: bool, is_ad: bool, sid: str, object_identifier: str,
                 database: Optional[str] = None) -> None:
        self.principal_id = principal_id
        self.name = name
        self.type_desc = type_desc
        self.is_fixed_role = is_fixed_role
        self.is_ad = is_ad
        self.sid = sid
        self.object_identifier = object_identifier
        self.database = database
        self.member_of: list[str] = []   # role names this principal is a direct member of
        self.perms: set[str] = set()      # directly-granted permission names (no DENY)


def _server_short_host(con: duckdb.DuckDBPyConnection, schema: str) -> str:
    """Return the collected server's short (NetBIOS) host name, or "".

    Used for the local-machine exclusion in :func:`_is_ad_principal`. Prefers the
    fqdn's first label, then machine_name / server_name. Empty when no servers row.
    """
    if not _table_exists(con, schema, "servers"):
        return ""
    row = _fetch_one(con, f"SELECT * FROM {schema}.servers LIMIT 1", "servers")
    if not row:
        return ""
    host = (
        _get(row, "fqdn")
        or _get(row, "machine_name", "MachineName")
        or _get(row, "server_name", "ServerName")
        or ""
    )
    return str(host).split("\\", 1)[0].split(".", 1)[0].strip()


def _load_server_principals(
    con: duckdb.DuckDBPyConnection, schema: str, server_oid: Optional[str], short_host: str = ""
) -> list[_Principal]:
    """Load server principals + attach role memberships + granted permissions.

    Implicit ``public`` membership is added for every non-role principal (matches
    client.go ``collectServerRoleMemberships``). Returns ``[]`` if the principals
    table is missing/empty. *short_host* enables the local-machine AD exclusion.
    """
    rows = _fetch_all(con, f"SELECT * FROM {schema}.server_principals", "server_principals")
    if not rows:
        logger.warning("transforms: no server_principals; server-level derivation will be empty")
        return []

    principals: list[_Principal] = []
    by_id: dict[int, _Principal] = {}
    for r in rows:
        pid = _as_int(_get(r, "principal_id"))
        if pid is None:
            # A principal with no id can't be keyed or joined — skip it.
            logger.debug("transforms: server principal row with no principal_id; skipping")
            continue
        name = _get(r, "name") or ""
        type_desc = _get(r, "type_desc", "type_description") or ""
        is_fixed = _as_bool(_get(r, "is_fixed_role"))
        sid = _sid_to_string(_get(r, "sid"))
        is_ad = _is_ad_principal(name, type_desc, short_host)
        oid = ids.principal_oid(name, server_oid or "")
        p = _Principal(pid, name, type_desc, is_fixed, is_ad, sid, oid)
        principals.append(p)
        by_id[pid] = p

    # Role memberships: member_principal_id -> role_name (collect both name+role rows).
    for rm in _fetch_all(con, f"SELECT * FROM {schema}.server_role_members", "server_role_members"):
        member_id = _as_int(_get(rm, "member_principal_id"))
        role_name = _get(rm, "role_name") or ""
        member = by_id.get(member_id) if member_id is not None else None
        if member is not None and role_name:
            member.member_of.append(role_name)

    # Implicit public membership for every non-role principal (client.go parity).
    for p in principals:
        if p.type_desc != "SERVER_ROLE" and "public" not in p.member_of:
            p.member_of.append("public")

    # Directly-granted permissions (skip DENY — never an effective grant).
    for perm in _fetch_all(con, f"SELECT * FROM {schema}.server_permissions", "server_permissions"):
        grantee = _as_int(_get(perm, "grantee_principal_id"))
        state = (_get(perm, "state_desc") or "").upper()
        name = _get(perm, "permission_name") or ""
        owner = by_id.get(grantee) if grantee is not None else None
        if owner is not None and name and state != "DENY":
            owner.perms.add(name)

    logger.verbose("transforms: loaded %d server principal(s)", len(principals))
    return principals


def _load_database_principals(
    con: duckdb.DuckDBPyConnection, schema: str, server_oid: Optional[str]
) -> list[_Principal]:
    """Load database principals (per database) + role memberships + permissions.

    DB principals are keyed within a database; role names and the implicit
    ``public`` membership are scoped per database (client.go
    ``collectDatabaseRoleMemberships``). The DB a principal belongs to is the
    ``database_principals.database`` column dlt adds from the per-db emit, falling
    back to a single unnamed database when absent. Returns ``[]`` if missing.
    """
    rows = _fetch_all(con, f"SELECT * FROM {schema}.database_principals", "database_principals")
    if not rows:
        logger.warning("transforms: no database_principals; database-level derivation will be empty")
        return []

    principals: list[_Principal] = []
    # by (database, principal_id) so role joins stay inside one database.
    by_key: dict[tuple[str, int], _Principal] = {}
    for r in rows:
        pid = _as_int(_get(r, "principal_id"))
        if pid is None:
            logger.debug("transforms: db principal row with no principal_id; skipping")
            continue
        db = _get(r, "database", "database_name") or ""
        name = _get(r, "name") or ""
        type_desc = _get(r, "type_desc", "type_description") or ""
        is_fixed = _as_bool(_get(r, "is_fixed_role"))
        sid = _sid_to_string(_get(r, "sid"))
        oid = ids.db_principal_oid(name, server_oid or "", db)
        p = _Principal(pid, name, type_desc, is_fixed, False, sid, oid, database=db)
        principals.append(p)
        by_key[(db, pid)] = p

    # DB role memberships, scoped per database.
    for rm in _fetch_all(con, f"SELECT * FROM {schema}.database_role_members", "database_role_members"):
        member_id = _as_int(_get(rm, "member_principal_id"))
        role_name = _get(rm, "role_name") or ""
        db = _get(rm, "database", "database_name") or ""
        member = by_key.get((db, member_id)) if member_id is not None else None
        if member is not None and role_name:
            member.member_of.append(role_name)

    # Implicit public membership for user-type DB principals (client.go parity).
    user_types = {
        "SQL_USER", "WINDOWS_USER", "WINDOWS_GROUP", "ASYMMETRIC_KEY_MAPPED_USER",
        "CERTIFICATE_MAPPED_USER", "EXTERNAL_USER", "EXTERNAL_GROUPS",
    }
    for p in principals:
        if p.type_desc in user_types and "public" not in p.member_of:
            p.member_of.append("public")

    # Directly-granted DB permissions (skip DENY).
    for perm in _fetch_all(con, f"SELECT * FROM {schema}.database_permissions", "database_permissions"):
        grantee = _as_int(_get(perm, "grantee_principal_id"))
        db = _get(perm, "database", "database_name") or ""
        state = (_get(perm, "state_desc") or "").upper()
        name = _get(perm, "permission_name") or ""
        owner = by_key.get((db, grantee)) if grantee is not None else None
        if owner is not None and name and state != "DENY":
            owner.perms.add(name)

    logger.verbose("transforms: loaded %d database principal(s)", len(principals))
    return principals


# ---------------------------------------------------------------------------
# Principal maps
# ---------------------------------------------------------------------------
def _build_server_principal_map(
    con: duckdb.DuckDBPyConnection, schema: str, principals: list[_Principal]
) -> None:
    """(server_oid, principal_id) -> identity, used by convert to resolve a
    permission's ``TargetPrincipalID`` / a role membership to a concrete node."""
    server_oid = _server_oid_of(principals)
    rows = [
        (server_oid, p.principal_id, p.object_identifier, p.name, p.type_desc,
         p.is_fixed_role, p.sid, p.is_ad)
        for p in principals
    ]
    _create_table(
        con, schema, "server_principal_map",
        columns=[
            ("server_oid", "VARCHAR"), ("principal_id", "BIGINT"),
            ("object_identifier", "VARCHAR"), ("name", "VARCHAR"),
            ("type_description", "VARCHAR"), ("is_fixed_role", "BOOLEAN"),
            ("security_identifier", "VARCHAR"), ("is_active_directory_principal", "BOOLEAN"),
        ],
        rows=rows,
    )
    logger.info("transforms: server_principal_map built (%d row(s))", len(rows))


def _build_database_principal_map(
    con: duckdb.DuckDBPyConnection, schema: str, principals: list[_Principal]
) -> None:
    """(server_oid, database, principal_id) -> identity, for DB-level edge target
    resolution."""
    server_oid = _server_oid_of(principals)
    rows = [
        (server_oid, p.database or "", p.principal_id, p.object_identifier, p.name,
         p.type_desc, p.is_fixed_role, p.sid)
        for p in principals
    ]
    _create_table(
        con, schema, "database_principal_map",
        columns=[
            ("server_oid", "VARCHAR"), ("database", "VARCHAR"), ("principal_id", "BIGINT"),
            ("object_identifier", "VARCHAR"), ("name", "VARCHAR"),
            ("type_description", "VARCHAR"), ("is_fixed_role", "BOOLEAN"),
            ("security_identifier", "VARCHAR"),
        ],
        rows=rows,
    )
    logger.info("transforms: database_principal_map built (%d row(s))", len(rows))


# ---------------------------------------------------------------------------
# Role closures (transitive nested membership)
# ---------------------------------------------------------------------------
def _build_server_role_closure(
    con: duckdb.DuckDBPyConnection, schema: str, principals: list[_Principal]
) -> dict[str, set[str]]:
    """Transitive server-role membership: member_oid -> every role_oid it belongs
    to (directly OR through nested roles, including implicit ``public``).

    Mirrors the DFS in ``hasNestedRoleMembershipDFS`` (collector.go): a principal
    is "in" a role if any of its direct roles is that role or transitively
    contains it. We compute the full reachable role-name set per principal, then
    map names back to role object identifiers. Returns the in-memory closure
    (name-set per member_oid) so ``effective_high_priv`` can reuse it.
    """
    role_member_of = _role_member_of_map(principals)   # role_name -> set(role_name) it is a member of
    role_name_to_oid = {
        p.name: p.object_identifier for p in principals if p.type_desc == "SERVER_ROLE"
    }

    server_oid = _server_oid_of(principals)
    closure_names: dict[str, set[str]] = {}
    rows: list[tuple] = []
    for p in principals:
        reachable = _reachable_roles(p.member_of, role_member_of)
        closure_names[p.object_identifier] = reachable
        for role_name in reachable:
            role_oid = role_name_to_oid.get(role_name)
            if role_oid is None:
                # Membership in a name with no SERVER_ROLE principal (e.g. a role
                # the collector couldn't read) — still record the name-based OID
                # so convert can build the edge endpoint.
                role_oid = ids.principal_oid(role_name, server_oid)
            rows.append((server_oid, p.object_identifier, p.principal_id, role_oid, role_name))

    _create_table(
        con, schema, "server_role_closure",
        columns=[
            ("server_oid", "VARCHAR"), ("member_oid", "VARCHAR"),
            ("member_principal_id", "BIGINT"), ("role_oid", "VARCHAR"),
            ("role_name", "VARCHAR"),
        ],
        rows=rows,
    )
    logger.info("transforms: server_role_closure built (%d edge row(s))", len(rows))
    return closure_names


def _build_database_role_closure(
    con: duckdb.DuckDBPyConnection, schema: str, principals: list[_Principal]
) -> None:
    """Transitive database-role membership, scoped per database (parity with
    ``hasNestedDBRoleMembershipDFS``)."""
    server_oid = _server_oid_of(principals)
    # Group principals by database so role-name resolution stays inside one DB.
    by_db: dict[str, list[_Principal]] = {}
    for p in principals:
        by_db.setdefault(p.database or "", []).append(p)

    rows: list[tuple] = []
    for db, db_principals in by_db.items():
        role_member_of = _role_member_of_map(db_principals)
        role_name_to_oid = {
            p.name: p.object_identifier for p in db_principals if p.type_desc == "DATABASE_ROLE"
        }
        for p in db_principals:
            for role_name in _reachable_roles(p.member_of, role_member_of):
                role_oid = role_name_to_oid.get(role_name) or ids.db_principal_oid(role_name, server_oid, db)
                rows.append((server_oid, db, p.object_identifier, p.principal_id, role_oid, role_name))

    _create_table(
        con, schema, "database_role_closure",
        columns=[
            ("server_oid", "VARCHAR"), ("database", "VARCHAR"),
            ("member_oid", "VARCHAR"), ("member_principal_id", "BIGINT"),
            ("role_oid", "VARCHAR"), ("role_name", "VARCHAR"),
        ],
        rows=rows,
    )
    logger.info("transforms: database_role_closure built (%d edge row(s))", len(rows))


def _role_member_of_map(principals: Iterable[_Principal]) -> dict[str, set[str]]:
    """role_name -> the set of role names that role is directly a member of.

    Only SERVER_ROLE / DATABASE_ROLE principals can themselves be members of
    other roles in a nested chain; we key by name (the Go DFS keys on role name).
    """
    result: dict[str, set[str]] = {}
    for p in principals:
        if p.type_desc in ("SERVER_ROLE", "DATABASE_ROLE"):
            result[p.name] = set(p.member_of)
    return result


def _reachable_roles(direct: list[str], role_member_of: dict[str, set[str]]) -> set[str]:
    """Every role name reachable from *direct* memberships (BFS over nested roles).

    Faithful to ``hasNestedRoleMembershipDFS``: start from the direct role names,
    then for each role that is itself a role principal, follow its memberships.
    The ``visited`` set prevents cycles. ``public`` is included (it is a real
    membership for non-role principals) but does not chain to anything.
    """
    reachable: set[str] = set()
    queue: deque[str] = deque(direct)
    while queue:
        role_name = queue.popleft()
        if role_name in reachable:
            continue
        reachable.add(role_name)
        # Follow nested memberships of this role, if it is itself a role.
        for parent in role_member_of.get(role_name, ()):  # () when not a role principal
            if parent not in reachable:
                queue.append(parent)
    return reachable


# ---------------------------------------------------------------------------
# Fixed-role implicit permissions
# ---------------------------------------------------------------------------
def _build_server_fixed_role_permissions(
    con: duckdb.DuckDBPyConnection, schema: str, principals: list[_Principal]
) -> None:
    """Implicit permissions each fixed *server* role confers (one row per
    role x implied permission). Lets convert emit the fixed-role edges
    (sysadmin->ControlServer, securityadmin->GrantAnyPermission/AlterAnyLogin,
    ##MS_LoginManager##->AlterAnyLogin, ##MS_DatabaseConnector##->ConnectAnyDatabase)
    without re-deriving the table."""
    server_oid = _server_oid_of(principals)
    rows: list[tuple] = []
    for p in principals:
        if p.type_desc != "SERVER_ROLE" or not p.is_fixed_role:
            continue
        for perm in FIXED_SERVER_ROLE_PERMISSIONS.get(p.name, ()):
            rows.append((server_oid, p.principal_id, p.object_identifier, p.name, perm))
    _create_table(
        con, schema, "server_fixed_role_permissions",
        columns=[
            ("server_oid", "VARCHAR"), ("principal_id", "BIGINT"),
            ("object_identifier", "VARCHAR"), ("name", "VARCHAR"),
            ("permission", "VARCHAR"),
        ],
        rows=rows,
    )
    logger.info("transforms: server_fixed_role_permissions built (%d row(s))", len(rows))


def _build_database_fixed_role_permissions(
    con: duckdb.DuckDBPyConnection, schema: str, principals: list[_Principal]
) -> None:
    """Implicit permissions each fixed *database* role confers (db_owner->CONTROL,
    db_securityadmin->grant-any/alter-any-role/alter-any-app-role)."""
    server_oid = _server_oid_of(principals)
    rows: list[tuple] = []
    for p in principals:
        if p.type_desc != "DATABASE_ROLE" or not p.is_fixed_role:
            continue
        for perm in FIXED_DATABASE_ROLE_PERMISSIONS.get(p.name, ()):
            rows.append((server_oid, p.database or "", p.principal_id, p.object_identifier, p.name, perm))
    _create_table(
        con, schema, "database_fixed_role_permissions",
        columns=[
            ("server_oid", "VARCHAR"), ("database", "VARCHAR"), ("principal_id", "BIGINT"),
            ("object_identifier", "VARCHAR"), ("name", "VARCHAR"), ("permission", "VARCHAR"),
        ],
        rows=rows,
    )
    logger.info("transforms: database_fixed_role_permissions built (%d row(s))", len(rows))


# ---------------------------------------------------------------------------
# Effective high-privilege (server node props + Kerberoasting edges)
# ---------------------------------------------------------------------------
def _build_effective_high_priv(
    con: duckdb.DuckDBPyConnection,
    schema: str,
    server_oid: Optional[str],
    principals: list[_Principal],
    closure_names: dict[str, set[str]],
) -> None:
    """One row per principal with an effective high-privilege, plus a one-row
    server summary table feeding the server node's ``domainPrincipalsWith*`` props.

    Effective-permission semantics (``hasEffectivePermission``): a principal has a
    permission if it holds it directly, OR any role in its nested closure holds it
    directly, OR any fixed role in its closure implies it. Role-membership
    semantics (``hasNestedRoleMembership``): a principal "has" sysadmin/
    securityadmin if that role is in its nested closure. The Go server-node pass
    restricts to enabled AD principals whose SID is under the domain SID; we
    record ``is_domain`` per row and let convert apply the enabled/domain filters
    it already needs for the props (the raw enabled flag lives in
    server_principals).
    """
    # Index roles by name for direct-permission lookup during the effective check.
    role_perms_by_name: dict[str, set[str]] = {
        p.name: p.perms for p in principals if p.type_desc == "SERVER_ROLE"
    }
    domain_sid = _domain_sid(principals)

    rows: list[tuple] = []
    domain_with: dict[str, list[str]] = {key: [] for key in (
        "sysadmin", "securityadmin", "CONTROL SERVER", "IMPERSONATE ANY LOGIN",
    )}

    for p in principals:
        reachable = closure_names.get(p.object_identifier, set())
        # Role-based high-priv (sysadmin/securityadmin): membership in the role.
        has = {role: (role in reachable) for role in _ROLE_HIGH_PRIV}
        # Permission-based high-priv (CONTROL SERVER / IMPERSONATE ANY LOGIN):
        # direct grant, via a role's direct grant, or via a fixed-role implication.
        for perm in _PERM_HIGH_PRIV:
            has[perm] = _has_effective_permission(p, perm, reachable, role_perms_by_name)

        if not any(has.values()):
            continue

        is_domain = bool(
            p.is_ad and domain_sid and p.sid and p.sid.startswith(domain_sid + "-")
        )
        rows.append((
            server_oid, p.principal_id, p.object_identifier, p.name, p.sid, is_domain,
            has["sysadmin"], has["securityadmin"],
            has["CONTROL SERVER"], has["IMPERSONATE ANY LOGIN"],
        ))
        # Accumulate the domain-principal arrays for the server-node summary.
        if is_domain:
            for key, flag in has.items():
                if flag:
                    domain_with[key].append(p.object_identifier)

    _create_table(
        con, schema, "effective_high_priv",
        columns=[
            ("server_oid", "VARCHAR"), ("principal_id", "BIGINT"),
            ("object_identifier", "VARCHAR"), ("name", "VARCHAR"),
            ("security_identifier", "VARCHAR"), ("is_domain", "BOOLEAN"),
            ("has_sysadmin", "BOOLEAN"), ("has_securityadmin", "BOOLEAN"),
            ("has_control_server", "BOOLEAN"), ("has_impersonate_any_login", "BOOLEAN"),
        ],
        rows=rows,
    )

    # One-row-per-server summary: the four domainPrincipalsWith* arrays + the
    # is_any_domain_principal_sysadmin boolean the GetAdminTGS edge keys on.
    is_any = len(domain_with["sysadmin"]) > 0
    summary_rows = [(
        server_oid,
        domain_with["sysadmin"],
        domain_with["CONTROL SERVER"],
        domain_with["securityadmin"],
        domain_with["IMPERSONATE ANY LOGIN"],
        is_any,
    )]
    _create_table(
        con, schema, "effective_high_priv_summary",
        columns=[
            ("server_oid", "VARCHAR"),
            ("domainPrincipalsWithSysadmin", "VARCHAR[]"),
            ("domainPrincipalsWithControlServer", "VARCHAR[]"),
            ("domainPrincipalsWithSecurityadmin", "VARCHAR[]"),
            ("domainPrincipalsWithImpersonateAnyLogin", "VARCHAR[]"),
            ("isAnyDomainPrincipalSysadmin", "BOOLEAN"),
        ],
        rows=summary_rows,
    )
    logger.info(
        "transforms: effective_high_priv built (%d principal row(s); isAnyDomainPrincipalSysadmin=%s)",
        len(rows), is_any,
    )


def _has_effective_permission(
    principal: _Principal,
    target_permission: str,
    reachable_roles: set[str],
    role_perms_by_name: dict[str, set[str]],
) -> bool:
    """Port of ``hasEffectivePermission`` (collector.go).

    True when the principal holds *target_permission* directly, or any role in its
    nested closure holds it directly, or any fixed role in the closure implies it.
    ``public`` is excluded as a grantor of fixed-role permissions (matches the Go
    BFS skipping ``public``), but a permission directly granted *to* public still
    counts via that role's ``perms`` set.
    """
    # 1) Direct grant on the principal.
    if target_permission in principal.perms:
        return True
    # 2) Through any role in the nested closure.
    for role_name in reachable_roles:
        if role_name == "public":
            # Go skips public in the fixed-role/permission BFS; a real grant to
            # public is still surfaced via role_perms_by_name below, so only the
            # fixed-role implication is skipped here.
            if target_permission in role_perms_by_name.get(role_name, ()):
                return True
            continue
        # 2a) Direct grant on the role.
        if target_permission in role_perms_by_name.get(role_name, ()):
            return True
        # 2b) Fixed-role implication (sysadmin -> CONTROL SERVER, etc.).
        if target_permission in FIXED_SERVER_ROLE_PERMISSIONS.get(role_name, ()):
            return True
    return False


# ---------------------------------------------------------------------------
# Linked-server flags
# ---------------------------------------------------------------------------
def _build_linked_server_flags(
    con: duckdb.DuckDBPyConnection, schema: str, server_oid: Optional[str]
) -> None:
    """Per linked-server-login-mapping row: source server, resolved target, the
    remote-privilege flags, the full Go LinkedTo property set, and the
    ``LinkedAsAdmin`` precondition.

    Column names are dlt's snake_case normalization of the collected camelCase
    keys (``SourceServer`` -> ``source_server``, ``RemoteLogin`` ->
    ``remote_login``, ...). The remote-privilege flags (``remote_is_sysadmin``
    etc.) come from MSSQLHound's recursive linked-server probe (the Go
    ``collectLinkedServers`` server-side batch, ported in ``queries.py`` /
    ``server.py``), which runs an OPENQUERY privilege check AS the linked login
    on each linked server. ``ensure_columns`` still pre-creates every optional
    column so this coalesce SELECT binds even when dlt drops an all-NULL column
    (dlt column-dropping trap, memory sccm-dlt-coalesce-gotchas).

    ``is_linked_as_admin`` reproduces the Go LinkedAsAdmin gate exactly: the
    remote login is non-empty, is a SQL login (no backslash, so not a Windows
    login), has at least one remote admin privilege (sysadmin / securityadmin /
    CONTROL SERVER / IMPERSONATE ANY LOGIN), and the remote target is mixed-mode.

    Resolved target (Go ``resolveDataSourceToSID``): a linked server's
    ``data_source`` must resolve to the remote server's SID-based node ID
    (``<computerSID>:<port>``) so a LinkedTo/LinkedAsAdmin edge connects two SQL
    Server *nodes*, not a bare hostname string. We resolve the LOOPBACK case here:
    when the data_source's machine name matches the collected server (its
    ``machine_name`` or ``fqdn``), the target is the server's own ``server_oid``
    (10 loopback links + any self-referential back-link become SID->SID self-edges,
    which is what the validator's ``S-1-5-21-* -> S-1-5-21-*`` pattern requires).
    A genuinely REMOTE linked server (e.g. a different host like CAS-DB) still falls
    back to its ``data_source`` string — resolving a foreign host's computer SID
    needs an AD/LDAP lookup that is Stage-7b remote-server work, not done here.
    """
    table = f"{schema}.linked_servers"
    if not _table_exists(con, schema, "linked_servers"):
        logger.warning("transforms: no linked_servers table; building empty linked_server_flags")
        _create_table(con, schema, "linked_server_flags", columns=_LINKED_FLAG_COLUMNS, rows=[])
        return

    # Read the collected server's host identifiers so we can recognise loopback
    # data_sources and resolve them to the server's own OID. machine_name is the
    # short name (e.g. "ps1-db"); fqdn is "ps1-db.mayyhem.com". Some inputs (older
    # fixtures) only carry server_name, so we read whichever host columns exist and
    # fall back gracefully — an absent column just leaves that identifier blank,
    # which the loopback CASE already guards against (the ``<> ''`` checks).
    server_machine = ""
    server_fqdn = ""
    if _table_exists(con, schema, "servers"):
        present = {
            r[0] for r in con.execute(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_schema = ? AND table_name = 'servers'",
                [schema],
            ).fetchall()
        }
        machine_col = next((c for c in ("machine_name", "server_name") if c in present), None)
        fqdn_col = "fqdn" if "fqdn" in present else None
        select_cols = []
        if machine_col:
            select_cols.append(f"{machine_col} AS m")
        if fqdn_col:
            select_cols.append(f"{fqdn_col} AS f")
        if select_cols:
            srow = con.execute(
                f"SELECT {', '.join(select_cols)} FROM {schema}.servers LIMIT 1"
            ).fetchone()
            if srow:
                idx = 0
                if machine_col:
                    server_machine = (srow[idx] or "").strip()
                    idx += 1
                if fqdn_col:
                    server_fqdn = (srow[idx] or "").strip()

    # Pre-create the optional (snake_case) columns dlt may have dropped (an
    # all-NULL column on a server with no linked servers, or a column missing on a
    # partial probe), so the coalesce SELECT binds regardless.
    ensure_columns(con, schema, "linked_servers", {
        "source_server": "VARCHAR",
        "linked_server": "VARCHAR",
        "data_source": "VARCHAR",
        "product": "VARCHAR",
        "provider": "VARCHAR",
        "path": "VARCHAR",
        "data_access": "BOOLEAN",
        "rpc_out": "BOOLEAN",
        "local_login": "VARCHAR",
        "remote_login": "VARCHAR",
        "remote_current_login": "VARCHAR",
        "uses_impersonation": "BOOLEAN",
        "resolved_object_identifier": "VARCHAR",
        "resolved_source": "VARCHAR",
        "remote_is_sysadmin": "BOOLEAN",
        "remote_is_security_admin": "BOOLEAN",
        "remote_has_control_server": "BOOLEAN",
        "remote_has_impersonate_any_login": "BOOLEAN",
        "remote_is_mixed_mode": "BOOLEAN",
        "level": "BIGINT",
    })

    # server_oid / host names are internally derived (not user input), so inlining
    # them as SQL string literals is safe — DuckDB does not bind "?" inside
    # CREATE TABLE AS. We lower-case the host names for a case-insensitive match.
    def _lit(value: str) -> str:
        return "'" + (value or "").replace("'", "''") + "'"

    server_oid_lit = "''" if server_oid is None else _lit(server_oid)
    machine_lit = _lit(server_machine.lower())
    fqdn_lit = _lit(server_fqdn.lower())

    # Resolved endpoint ids (collect-time, Go processLinkedServers +
    # resolveLinkedServerSourceID): collection/server.py already resolved each link's
    # data_source -> <computerSID>:<port> (foreign hosts like CAS-DB) and stamped it
    # on `resolved_object_identifier`; a loopback (the 10 manufactured self-links)
    # resolves to THIS server's own SID, i.e. exactly `server_oid`. So we just take
    # the collect-resolved target verbatim (falling back to the bare data_source only
    # when collection couldn't resolve it). The host-based local test is kept ONLY as
    # a safety net for older fixtures whose rows predate collect-time resolution: if
    # `resolved_object_identifier` is blank and the link is a true loopback (both
    # source AND data_source name this server), collapse the target to `server_oid`.
    # Host extraction mirrors Go parseDataSource (host = everything before ':' / '\').
    def _host_sql(col: str) -> str:
        return f"lower(regexp_replace(CAST({col} AS VARCHAR), '[\\\\:].*$', ''))"

    def _is_local_sql(col: str) -> str:
        host = _host_sql(col)
        return (
            f"(({host} = {machine_lit} AND {machine_lit} <> '')"
            f" OR ({host} = {fqdn_lit} AND {fqdn_lit} <> '')"
            f" OR (split_part({host}, '.', 1) = {machine_lit} AND {machine_lit} <> ''))"
        )

    resolved_target_sql = f"""
            COALESCE(
                NULLIF(CAST(resolved_object_identifier AS VARCHAR), ''),
                CASE
                    WHEN {_is_local_sql('data_source')} AND {_is_local_sql('source_server')}
                    THEN {server_oid_lit}
                    ELSE CAST(data_source AS VARCHAR)
                END
            ) AS resolved_target"""
    # Resolved SOURCE id (Go: serverInfo.ObjectIdentifier for a self-sourced link;
    # the chained-source SID for a link discovered through a remote server). Collect
    # stamped `resolved_source` only on chained rows (different source host); a
    # self-row has none, so it defaults to this server's own OID.
    resolved_source_sql = f"""
            COALESCE(NULLIF(CAST(resolved_source AS VARCHAR), ''), {server_oid_lit})
            AS resolved_source"""
    safe_execute(
        con, "linked_server_flags",
        f"""
        CREATE OR REPLACE TABLE {schema}.linked_server_flags AS
        SELECT
            {server_oid_lit} AS server_oid,
            source_server,
            linked_server,
            data_source,
            {resolved_target_sql},
            {resolved_source_sql},
            product,
            provider,
            path,
            COALESCE(data_access, FALSE)                      AS data_access,
            COALESCE(rpc_out, FALSE)                          AS rpc_out,
            local_login,
            remote_login,
            remote_current_login,
            COALESCE(uses_impersonation, FALSE)                AS uses_impersonation,
            COALESCE(remote_is_sysadmin, FALSE)               AS remote_is_sysadmin,
            COALESCE(remote_is_security_admin, FALSE)         AS remote_is_securityadmin,
            COALESCE(remote_has_control_server, FALSE)        AS remote_has_control_server,
            COALESCE(remote_has_impersonate_any_login, FALSE) AS remote_has_impersonate_any_login,
            COALESCE(remote_is_mixed_mode, FALSE)             AS remote_is_mixed_mode,
            COALESCE(level, 0)                                AS level,
            (
                remote_login IS NOT NULL AND CAST(remote_login AS VARCHAR) <> ''
                AND POSITION('\\' IN CAST(remote_login AS VARCHAR)) = 0
                AND (
                    COALESCE(remote_is_sysadmin, FALSE)
                    OR COALESCE(remote_is_security_admin, FALSE)
                    OR COALESCE(remote_has_control_server, FALSE)
                    OR COALESCE(remote_has_impersonate_any_login, FALSE)
                )
                AND COALESCE(remote_is_mixed_mode, FALSE)
            ) AS is_linked_as_admin
        FROM {table}
        """,
    )
    count = _count(con, schema, "linked_server_flags")
    logger.info("transforms: linked_server_flags built (%d row(s))", count)


# The canonical linked_server_flags shape (used for the empty-table fallback).
# Must match the SELECT column list in _build_linked_server_flags.
_LINKED_FLAG_COLUMNS = [
    ("server_oid", "VARCHAR"), ("source_server", "VARCHAR"), ("linked_server", "VARCHAR"),
    ("data_source", "VARCHAR"), ("resolved_target", "VARCHAR"), ("resolved_source", "VARCHAR"),
    ("product", "VARCHAR"), ("provider", "VARCHAR"), ("path", "VARCHAR"),
    ("data_access", "BOOLEAN"), ("rpc_out", "BOOLEAN"),
    ("local_login", "VARCHAR"), ("remote_login", "VARCHAR"), ("remote_current_login", "VARCHAR"),
    ("uses_impersonation", "BOOLEAN"),
    ("remote_is_sysadmin", "BOOLEAN"), ("remote_is_securityadmin", "BOOLEAN"),
    ("remote_has_control_server", "BOOLEAN"), ("remote_has_impersonate_any_login", "BOOLEAN"),
    ("remote_is_mixed_mode", "BOOLEAN"), ("level", "BIGINT"), ("is_linked_as_admin", "BOOLEAN"),
]


# ---------------------------------------------------------------------------
# DuckDB / row helpers
# ---------------------------------------------------------------------------
def _create_table(
    con: duckdb.DuckDBPyConnection,
    schema: str,
    table: str,
    columns: list[tuple[str, str]],
    rows: list[tuple],
) -> None:
    """(Re)create ``schema.table`` with an explicit typed schema and insert *rows*.

    Building the table from an explicit DDL (rather than ``CREATE TABLE AS
    SELECT`` over the raw rows) keeps the derived schema stable even when a load
    is empty or dlt dropped a column — convert's SELECTs always bind.
    """
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    coldefs = ", ".join(f'"{name}" {sqltype}' for name, sqltype in columns)
    con.execute(f"CREATE OR REPLACE TABLE {schema}.{table} ({coldefs})")
    if not rows:
        return
    placeholders = ", ".join(["?"] * len(columns))
    con.executemany(f"INSERT INTO {schema}.{table} VALUES ({placeholders})", rows)


def _fetch_all(con: duckdb.DuckDBPyConnection, sql: str, label: str) -> list[dict]:
    """Run *sql* and return rows as column-named dicts; ``[]`` on a missing table."""
    try:
        cur = con.execute(sql)
    except duckdb.CatalogException as err:
        logger.warning("transforms: source table for %r missing: %s", label, err)
        return []
    except duckdb.Error as err:
        logger.error("transforms: query for %r failed: %s", label, err)
        return []
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def _fetch_one(con: duckdb.DuckDBPyConnection, sql: str, label: str) -> Optional[dict]:
    """Run *sql* and return the first row as a dict, or ``None``."""
    rows = _fetch_all(con, sql, label)
    return rows[0] if rows else None


def _table_exists(con: duckdb.DuckDBPyConnection, schema: str, table: str) -> bool:
    """True if ``schema.table`` exists in the catalog."""
    found = con.execute(
        "SELECT 1 FROM information_schema.tables WHERE table_schema = ? AND table_name = ?",
        [schema, table],
    ).fetchone()
    return found is not None


def _count(con: duckdb.DuckDBPyConnection, schema: str, table: str) -> int:
    """Row count of ``schema.table`` (0 if missing)."""
    try:
        return int(con.execute(f"SELECT COUNT(*) FROM {schema}.{table}").fetchone()[0])
    except duckdb.Error:
        return 0


def _get(row: dict, *names: str):
    """Return the first present (non-None) value among *names* (case variants)."""
    for name in names:
        if name in row and row[name] is not None:
            return row[name]
    return None


def _as_int(value) -> Optional[int]:
    """Coerce a raw value to int, or None when blank/uncoercible."""
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value) -> bool:
    """Coerce a raw value (0/1, '0'/'1', true/false, bool) to bool."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "t", "yes", "y")
    return False


def _server_oid_of(principals: list[_Principal]) -> Optional[str]:
    """Pull the server_oid embedded in any principal's object_identifier.

    Every principal OID is ``name@<server_oid>`` (server) or
    ``name@<server_oid>\\db`` (database), so the server_oid is the text after the
    first ``@`` up to the first ``\\``. Returns ``None`` for an empty list.
    """
    if not principals:
        return None
    oid = principals[0].object_identifier
    after_at = oid.partition("@")[2]
    return after_at.split("\\", 1)[0]


def _domain_sid(principals: list[_Principal]) -> str:
    """Derive the domain SID from the first AD principal's SID (client.go parity).

    The domain SID is ``S-1-5-21-<domainSID>`` — i.e. the principal SID with its
    final ``-<RID>`` stripped. Empty string when no domain (S-1-5-21-) AD
    principal is present.
    """
    for p in principals:
        if p.is_ad and p.sid.startswith("S-1-5-21-"):
            idx = p.sid.rfind("-")
            if idx > 0:
                return p.sid[:idx]
    return ""


# Pseudo-authorities that prefix a local/built-in account name (never AD).
_NON_AD_PREFIXES = ("NT SERVICE\\", "NT AUTHORITY\\", "BUILTIN\\")


def _is_ad_principal(name: str, type_desc: str, short_host: str = "") -> bool:
    """Reproduce client.go's ``IsActiveDirectoryPrincipal`` test.

    Must be a Windows login/group whose name has a backslash and is NOT an
    NT SERVICE / NT AUTHORITY / BUILTIN account, AND NOT a local-machine account
    (``<MACHINENAME>\\...``). The local-machine exclusion (Go ``!isLocalMachine``,
    client.go:1714-1717) matters because a machine-local group like
    ``ps1-db\\ConfigMgr_DViewAccess`` carries a domain-style ``S-1-5-21-*`` SID that
    is NOT under the server's own domain; without this check it would be mistaken
    for a domain principal and wrongly get a SID-keyed HasLogin / GetTGS edge. When
    *short_host* is empty (host unknown) the local-machine check is skipped.
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
    """Convert a ``0x...`` hex SID string to ``S-1-5-21-...`` form.

    Port of client.go ``convertHexSIDToString`` (which mirrors the PS1
    ``ConvertTo-SecurityIdentifier``). Returns ``""`` for an empty / malformed /
    non-SID input. The raw ``server_principals.sid`` column is the hex string
    produced by ``CONVERT(VARCHAR(85), p.sid, 1)``.
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
        # Not valid hex (e.g. an already-converted S-1-... value) — pass through
        # an S-1- value unchanged, else treat as no SID.
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
    "transforms",
    "FIXED_SERVER_ROLE_PERMISSIONS",
    "FIXED_DATABASE_ROLE_PERMISSIONS",
]
