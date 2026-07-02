"""Server- and database-level edge derivation (port of Go ``createEdges``).

``derive_edges(lookup)`` reproduces the Stage-6 portion of Go
``collector.createEdges`` + ``createFixedRoleEdges`` +
``createServerPermissionEdges`` + ``createDatabasePermissionEdges``, yielding
framework :class:`~openhound.core.models.entries_dataclass.Edge` objects (kind +
start/end :class:`EdgePath` + :class:`MSSQLEdgeProperties`). It reads the raw and
derived tables through :class:`~openhound_mssql.lookup.MSSQLLookup`, exactly the
data Go reads off its in-memory ``ServerInfo``:

* ``servers`` (one row) -> the server ObjectIdentifier + display name (server_oid).
* ``server_principals`` / ``database_principals`` (+ the ``*_principal_map``
  derived tables) -> the principal maps Go keys permissions/roles on by id.
* ``server_role_members`` / ``database_role_members`` -> the DIRECT explicit
  memberships the Go MemberOf-edge pass uses (NOT the nested closure). The implicit
  ``public`` membership is added on top of these (Go adds it to each principal's
  ``MemberOf`` during collection, so its MemberOf edges include public).
* ``server_permissions`` / ``database_permissions`` -> the GRANT/GRANT_WITH_GRANT
  permission rows that drive the per-permission edge switch.
* ``database_principal_logins`` -> the login<->db-user mapping (IsMappedTo).
* ``databases`` -> Contains/Owns/IsTrustedBy/ExecuteAsOwner.
* ``effective_high_priv`` (derived) -> the per-principal nested sysadmin /
  securityadmin / CONTROL SERVER / IMPERSONATE ANY LOGIN flags the ChangePassword
  gate and ExecuteAsOwner check need (Go ``hasNestedRoleMembership`` /
  ``hasEffectivePermission``).

OUT OF SCOPE (Stage 7): linked servers, credentials/proxies, AD-principal HasLogin
/ CoerceAndRelay, service accounts / Kerberos / HasSession, computer Host edges.

The ``--disable-nontraversable-edges`` / ``--disable-possible-edges`` toggles are
NOT applied here: this stage always emits every producible edge with its correct
``traversable`` flag, mirroring the Go default run. (Those toggles are a
collection-time concern; convert emits the full set and the flag is carried on
each edge.)
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Optional

from openhound.core.models.entries_dataclass import Edge, EdgePath

from .. import ids
from ..kinds import edges as ek
from ..kinds import nodes as nk
from ..models import _common
from .properties import EdgeCtx, build_edge_properties

logger = logging.getLogger(__name__)

# Permission states that confer a grant (Go: perm.State == GRANT|GRANT_WITH_GRANT).
_GRANT_STATES = {"GRANT", "GRANT_WITH_GRANT_OPTION"}
# Database principal type_descs treated as "users" for CONTROL-on-principal (Go).
_DB_USER_TYPES = {
    "WINDOWS_USER", "WINDOWS_GROUP", "SQL_USER", "ASYMMETRIC_KEY_MAPPED_USER",
    "CERTIFICATE_MAPPED_USER",
}


# ---------------------------------------------------------------------------
# In-memory principal record (the convert-side analogue of Go ServerPrincipal /
# DatabasePrincipal — only the fields the edge derivation needs).
# ---------------------------------------------------------------------------
@dataclass
class _Principal:
    principal_id: int
    name: str
    type_desc: str
    object_identifier: str
    is_fixed_role: bool = False
    is_disabled: bool = False
    owning_principal_id: Optional[int] = None
    database: Optional[str] = None  # set for database principals


def _bool(value) -> bool:
    return _common.as_bool(value)


def _int(value) -> Optional[int]:
    out = _common.as_int(value, default=-1)
    return out if out >= 0 else None


# ---------------------------------------------------------------------------
# Edge factory (Go createEdge): build the property bag + traversable flag.
# ---------------------------------------------------------------------------
def _edge(
    source_id: str,
    target_id: str,
    kind: str,
    ctx: EdgeCtx,
    *,
    with_grant: bool = False,
) -> Edge:
    """Build one framework Edge (Go ``createEdge``).

    ``traversable`` is taken from the kind's static partition (``kinds/edges.py``
    follows Go ``IsTraversableEdge``). The property bag is built by
    :func:`build_edge_properties`. ``source_id``/``target_id`` are also stamped
    into the ctx so the composition Cypher can reference them.
    """
    ctx.source_id = source_id
    ctx.target_id = target_id
    traversable = kind in ek.TRAVERSABLE_EDGE_KINDS or kind in ek.POSSIBLE_EDGE_KINDS
    props = build_edge_properties(kind, ctx, traversable=traversable, with_grant=with_grant)
    return Edge(
        kind=kind,
        start=EdgePath(match_by="id", value=source_id),
        end=EdgePath(match_by="id", value=target_id),
        properties=props,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def derive_edges(lookup) -> Iterator[Edge]:
    """Yield every Stage-6 server/database edge for the collected server.

    Reads the single server context + all principals/permissions/databases via
    *lookup* and yields edges in the same families Go ``createEdges`` produces (the
    emission order is irrelevant — the destination just collects them).
    """
    server_oid = _common.server_oid_for(lookup)
    if not server_oid:
        logger.warning("derive_edges: no server context; emitting no edges")
        return
    server_name = _common.sql_server_name_for(lookup)
    logger.info("derive_edges: deriving edges for server_oid=%s", server_oid)

    ctxd = _ServerData(lookup, server_oid, server_name)

    yield from _contains_edges(ctxd)
    yield from _ownership_edges(ctxd)
    yield from _member_of_edges(ctxd)
    yield from _is_mapped_to_edges(ctxd)
    yield from _fixed_role_edges(ctxd)
    yield from _server_permission_edges(ctxd)
    yield from _database_permission_edges(ctxd)
    yield from _trustworthy_edges(ctxd)


# ---------------------------------------------------------------------------
# Loaded server data (built once per convert run)
# ---------------------------------------------------------------------------
class _ServerData:
    """All principals/databases/permissions for the one collected server.

    Builds the per-id principal maps (server + per database) and the high-priv
    flag lookups once, so the edge passes don't re-scan DuckDB per row.
    """

    def __init__(self, lookup, server_oid: str, server_name: str) -> None:
        self.lookup = lookup
        self.server_oid = server_oid
        self.server_name = server_name

        # Server principals, by id + by object_identifier.
        self.server_principals: list[_Principal] = []
        self.server_by_id: dict[int, _Principal] = {}
        for row in lookup.table_rows("server_principals"):
            pid = _int(row.get("principal_id"))
            if pid is None:
                continue
            name = row.get("name") or ""
            p = _Principal(
                principal_id=pid,
                name=name,
                type_desc=row.get("type_desc") or "",
                object_identifier=ids.principal_oid(name, server_oid),
                is_fixed_role=_bool(row.get("is_fixed_role")),
                is_disabled=_bool(row.get("is_disabled")),
                owning_principal_id=_int(row.get("owning_principal_id")),
            )
            self.server_principals.append(p)
            self.server_by_id[pid] = p

        # Databases (each carries its DatabasePrincipals).
        self.databases: list[dict] = list(lookup.table_rows("databases"))

        # Database principals, grouped by database, by id within that database.
        self.db_principals: dict[str, list[_Principal]] = {}
        self.db_by_id: dict[tuple[str, int], _Principal] = {}
        for row in lookup.table_rows("database_principals"):
            pid = _int(row.get("principal_id"))
            if pid is None:
                continue
            db = row.get("database") or row.get("database_name") or ""
            name = row.get("name") or ""
            p = _Principal(
                principal_id=pid,
                name=name,
                type_desc=row.get("type_desc") or "",
                object_identifier=ids.db_principal_oid(name, server_oid, db),
                is_fixed_role=_bool(row.get("is_fixed_role")),
                owning_principal_id=_int(row.get("owning_principal_id")),
                database=db,
            )
            self.db_principals.setdefault(db, []).append(p)
            self.db_by_id[(db, pid)] = p

        # Per-principal effective high-priv flags (sysadmin / securityadmin /
        # CONTROL SERVER / IMPERSONATE ANY LOGIN), keyed by object_identifier.
        # Absent => the principal has none of them (Go: the nested checks return
        # false). Used by the ChangePassword gate + the ExecuteAsOwner owner check.
        self.high_priv: dict[str, dict] = {
            row.get("object_identifier"): row
            for row in lookup.high_priv_principals(server_oid)
        }

        # Engine version for the CVE-2025-49758 ChangePassword gate (Go reads
        # ServerInfo.VersionNumber/Version). The raw servers row carries
        # product_version (numeric) and full_version (@@VERSION banner).
        server_row = next(iter(lookup.table_rows("servers")), {}) or {}
        self._version = (
            server_row.get("product_version")
            or server_row.get("full_version")
            or ""
        )

    def server_version(self) -> str:
        """The collected engine version string for the CVE gate."""
        return self._version

    # -- high-priv helpers (Go hasNestedRoleMembership / hasEffectivePermission) --
    def has_sysadmin(self, oid: str) -> bool:
        return _bool(self.high_priv.get(oid, {}).get("has_sysadmin"))

    def has_securityadmin(self, oid: str) -> bool:
        return _bool(self.high_priv.get(oid, {}).get("has_securityadmin"))

    def has_control_server(self, oid: str) -> bool:
        return _bool(self.high_priv.get(oid, {}).get("has_control_server"))

    def has_impersonate_any_login(self, oid: str) -> bool:
        return _bool(self.high_priv.get(oid, {}).get("has_impersonate_any_login"))


# ---------------------------------------------------------------------------
# Node-kind helpers (Go getServerPrincipalType / getDatabasePrincipalType)
# ---------------------------------------------------------------------------
def _server_principal_kind(type_desc: str) -> str:
    return nk.SERVER_ROLE if type_desc == "SERVER_ROLE" else nk.LOGIN


def _database_principal_kind(type_desc: str) -> str:
    if type_desc == "DATABASE_ROLE":
        return nk.DATABASE_ROLE
    if type_desc == "APPLICATION_ROLE":
        return nk.APPLICATION_ROLE
    return nk.DATABASE_USER


# ===========================================================================
# CONTAINS edges
# ===========================================================================
def _contains_edges(d: _ServerData) -> Iterator[Edge]:
    """Server->db, server->server-principal, db->db-principal (Go createEdges)."""
    # Server contains databases.
    for db in d.databases:
        db_name = db.get("name") or ""
        db_oid = ids.database_oid(d.server_oid, db_name)
        yield _edge(
            d.server_oid, db_oid, ek.CONTAINS,
            EdgeCtx(source_name=d.server_name, source_type=nk.SERVER,
                    target_name=db_name, target_type=nk.DATABASE,
                    sql_server_id=d.server_oid),
        )

    # Server contains server principals (logins and server roles).
    for p in d.server_principals:
        yield _edge(
            d.server_oid, p.object_identifier, ek.CONTAINS,
            EdgeCtx(source_name=d.server_name, source_type=nk.SERVER,
                    target_name=p.name, target_type=_server_principal_kind(p.type_desc),
                    sql_server_id=d.server_oid),
        )

    # Database contains database principals.
    for db in d.databases:
        db_name = db.get("name") or ""
        db_oid = ids.database_oid(d.server_oid, db_name)
        for p in d.db_principals.get(db_name, []):
            yield _edge(
                db_oid, p.object_identifier, ek.CONTAINS,
                EdgeCtx(source_name=db_name, source_type=nk.DATABASE,
                        target_name=p.name, target_type=_database_principal_kind(p.type_desc),
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        database_name=db_name),
            )


# ===========================================================================
# OWNERSHIP edges
# ===========================================================================
def _ownership_edges(d: _ServerData) -> Iterator[Edge]:
    """Database, server-role and database-role ownership (Go createEdges)."""
    # Database ownership: owner login -> database. The owner is resolved from the
    # database's owner_name against the server principals (Go createDatabases sets
    # OwnerObjectIdentifier when the owner is a server principal).
    server_by_name = {p.name: p for p in d.server_principals}
    for db in d.databases:
        db_name = db.get("name") or ""
        owner_name = db.get("owner_name") or ""
        owner = server_by_name.get(owner_name)
        if owner is None:
            # Owner isn't a known server principal -> no Owns edge (Go: empty OID).
            logger.debug("derive_edges: db %r owner %r not a server principal; no Owns", db_name, owner_name)
            continue
        db_oid = ids.database_oid(d.server_oid, db_name)
        edge = _edge(
            owner.object_identifier, db_oid, ek.OWNS,
            EdgeCtx(source_name=owner_name, source_type=nk.LOGIN,
                    target_name=db_name, target_type=nk.DATABASE,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid),
        )
        # ownerPrincipalID typed prop (Go injects it on Owns).
        edge.properties.ownerPrincipalID = str(owner.principal_id)
        yield edge

    # Server role ownership: owning principal -> server role.
    for p in d.server_principals:
        if p.type_desc != "SERVER_ROLE" or p.owning_principal_id is None:
            continue
        owner = d.server_by_id.get(p.owning_principal_id)
        if owner is None:
            logger.debug("derive_edges: server role %r owner id %s unknown; no Owns",
                         p.name, p.owning_principal_id)
            continue
        owner_kind = nk.SERVER_ROLE if owner.type_desc == "SERVER_ROLE" else nk.LOGIN
        yield _edge(
            owner.object_identifier, p.object_identifier, ek.OWNS,
            EdgeCtx(source_name=owner.name, source_type=owner_kind,
                    target_name=p.name, target_type=nk.SERVER_ROLE,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid),
        )

    # Database role ownership: owning principal -> database role.
    for db_name, principals in d.db_principals.items():
        for p in principals:
            if p.type_desc != "DATABASE_ROLE" or p.owning_principal_id is None:
                continue
            owner = d.db_by_id.get((db_name, p.owning_principal_id))
            if owner is None:
                logger.debug("derive_edges: db role %r owner id %s unknown; no Owns",
                             p.name, p.owning_principal_id)
                continue
            if owner.type_desc == "DATABASE_ROLE":
                owner_kind = nk.DATABASE_ROLE
            elif owner.type_desc == "APPLICATION_ROLE":
                owner_kind = nk.APPLICATION_ROLE
            else:
                owner_kind = nk.DATABASE_USER
            yield _edge(
                owner.object_identifier, p.object_identifier, ek.OWNS,
                EdgeCtx(source_name=owner.name, source_type=owner_kind,
                        target_name=p.name, target_type=nk.DATABASE_ROLE,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        database_name=db_name),
            )


# Database principal type_descs that get the implicit ``public`` membership
# (client.go collectDatabaseRoleMemberships userTypes map). Server-level public is
# added to every principal that is not itself a SERVER_ROLE.
_DB_PUBLIC_MEMBER_TYPES = {
    "SQL_USER", "WINDOWS_USER", "WINDOWS_GROUP", "ASYMMETRIC_KEY_MAPPED_USER",
    "CERTIFICATE_MAPPED_USER", "EXTERNAL_USER", "EXTERNAL_GROUPS",
}


# ===========================================================================
# MEMBEROF edges (explicit/direct PLUS implicit public)
# ===========================================================================
def _member_of_edges(d: _ServerData) -> Iterator[Edge]:
    """Role memberships at server + database level (Go createEdges).

    Go adds the implicit ``public`` membership to every principal's ``MemberOf``
    during collection (client.go: "Add implicit public role membership for all
    logins" / "... for all database users"), then emits a MemberOf edge for each
    entry. We therefore emit BOTH the explicit memberships (from the raw
    role-member tables) AND an implicit ``public`` edge for every non-role server
    principal and every user-type database principal that isn't already an explicit
    member of ``public``. (The earlier "explicit only" note was wrong about Go: the
    edge step is explicit-only, but ``public`` is already in ``MemberOf`` by then.)
    """
    # Track explicit (member -> roleName) pairs so we don't double-emit public for a
    # principal that was explicitly added to it.
    server_explicit_public: set[int] = set()
    db_explicit_public: set[tuple[str, int]] = set()

    # Server role memberships from the raw role-member table (direct only).
    role_by_id = {p.principal_id: p for p in d.server_principals}
    for rm in d.lookup.table_rows("server_role_members"):
        member_id = _int(rm.get("member_principal_id"))
        role_id = _int(rm.get("role_principal_id"))
        if member_id is None or role_id is None:
            continue
        member = d.server_by_id.get(member_id)
        role = role_by_id.get(role_id)
        if member is None or role is None:
            continue
        if role.name == "public":
            server_explicit_public.add(member_id)
        yield _edge(
            member.object_identifier, role.object_identifier, ek.MEMBER_OF,
            EdgeCtx(source_name=member.name, source_type=_server_principal_kind(member.type_desc),
                    target_name=role.name, target_type=nk.SERVER_ROLE,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid),
        )

    # Implicit public at the server level: every non-SERVER_ROLE principal that is
    # not already an explicit member of public (client.go parity).
    server_public = next((p for p in d.server_principals if p.name == "public"), None)
    if server_public is not None:
        for p in d.server_principals:
            if p.type_desc == "SERVER_ROLE" or p.principal_id in server_explicit_public:
                continue
            yield _edge(
                p.object_identifier, server_public.object_identifier, ek.MEMBER_OF,
                EdgeCtx(source_name=p.name, source_type=_server_principal_kind(p.type_desc),
                        target_name="public", target_type=nk.SERVER_ROLE,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid),
            )

    # Database role memberships from the raw db role-member table (direct only).
    for rm in d.lookup.table_rows("database_role_members"):
        db_name = rm.get("database") or rm.get("database_name") or ""
        member_id = _int(rm.get("member_principal_id"))
        role_id = _int(rm.get("role_principal_id"))
        if member_id is None or role_id is None:
            continue
        member = d.db_by_id.get((db_name, member_id))
        role = d.db_by_id.get((db_name, role_id))
        if member is None or role is None:
            continue
        if role.name == "public":
            db_explicit_public.add((db_name, member_id))
        yield _edge(
            member.object_identifier, role.object_identifier, ek.MEMBER_OF,
            EdgeCtx(source_name=member.name, source_type=_database_principal_kind(member.type_desc),
                    target_name=role.name, target_type=nk.DATABASE_ROLE,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid,
                    database_name=db_name),
        )

    # Implicit public at the database level: every user-type DB principal that is
    # not already an explicit member of public (client.go userTypes parity).
    for db_name, principals in d.db_principals.items():
        db_public = next((p for p in principals if p.name == "public"), None)
        if db_public is None:
            continue
        for p in principals:
            if p.type_desc not in _DB_PUBLIC_MEMBER_TYPES:
                continue
            if (db_name, p.principal_id) in db_explicit_public:
                continue
            yield _edge(
                p.object_identifier, db_public.object_identifier, ek.MEMBER_OF,
                EdgeCtx(source_name=p.name, source_type=_database_principal_kind(p.type_desc),
                        target_name="public", target_type=nk.DATABASE_ROLE,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        database_name=db_name),
            )


# ===========================================================================
# MAPPING edges (login -> database user)
# ===========================================================================
def _is_mapped_to_edges(d: _ServerData) -> Iterator[Edge]:
    """Login -> database user mapping (Go createEdges, principal.ServerLogin)."""
    # database_principal_logins gives (db, db_principal_id) -> (server_login_name,
    # server_principal_id). The login OID is name@serverOID; the db user OID is the
    # db principal's object_identifier.
    for link in d.lookup.table_rows("database_principal_logins"):
        db_name = link.get("database") or link.get("database_name") or ""
        db_pid = _int(link.get("db_principal_id"))
        srv_pid = _int(link.get("server_principal_id"))
        if db_pid is None or srv_pid is None:
            continue
        login = d.server_by_id.get(srv_pid)
        db_user = d.db_by_id.get((db_name, db_pid))
        if login is None or db_user is None:
            continue
        yield _edge(
            login.object_identifier, db_user.object_identifier, ek.IS_MAPPED_TO,
            EdgeCtx(source_name=login.name, source_type=nk.LOGIN,
                    target_name=db_user.name, target_type=nk.DATABASE_USER,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid,
                    database_name=db_name),
        )


# ===========================================================================
# FIXED ROLE edges (Go createFixedRoleEdges)
# ===========================================================================
def _fixed_role_edges(d: _ServerData) -> Iterator[Edge]:
    """Implicit edges conferred by fixed server/database roles."""
    yield from _fixed_server_role_edges(d)
    yield from _fixed_database_role_edges(d)


def _fixed_server_role_edges(d: _ServerData) -> Iterator[Edge]:
    for role in d.server_principals:
        if role.type_desc != "SERVER_ROLE" or not role.is_fixed_role:
            continue
        if role.name == "sysadmin":
            # sysadmin has CONTROL SERVER.
            yield _edge(
                role.object_identifier, d.server_oid, ek.CONTROL_SERVER,
                EdgeCtx(source_name=role.name, source_type=nk.SERVER_ROLE,
                        target_name=d.server_name, target_type=nk.SERVER,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        is_fixed_role=True),
            )
        elif role.name == "securityadmin":
            # securityadmin can grant any permission + ALTER ANY LOGIN.
            yield _edge(
                role.object_identifier, d.server_oid, ek.GRANT_ANY_PERMISSION,
                EdgeCtx(source_name=role.name, source_type=nk.SERVER_ROLE,
                        target_name=d.server_name, target_type=nk.SERVER,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        is_fixed_role=True),
            )
            yield _edge(
                role.object_identifier, d.server_oid, ek.ALTER_ANY_LOGIN,
                EdgeCtx(source_name=role.name, source_type=nk.SERVER_ROLE,
                        target_name=d.server_name, target_type=nk.SERVER,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        is_fixed_role=True),
            )
            yield from _change_password_to_sql_logins(d, role)
        elif role.name == "##MS_LoginManager##":
            # SQL Server 2022+ fixed role: ALTER ANY LOGIN (+ ChangePassword).
            yield _edge(
                role.object_identifier, d.server_oid, ek.ALTER_ANY_LOGIN,
                EdgeCtx(source_name=role.name, source_type=nk.SERVER_ROLE,
                        target_name=d.server_name, target_type=nk.SERVER,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        is_fixed_role=True),
            )
            yield from _change_password_to_sql_logins(d, role)
        elif role.name == "##MS_DatabaseConnector##":
            # SQL Server 2022+ fixed role: CONNECT ANY DATABASE.
            yield _edge(
                role.object_identifier, d.server_oid, ek.CONNECT_ANY_DATABASE,
                EdgeCtx(source_name=role.name, source_type=nk.SERVER_ROLE,
                        target_name=d.server_name, target_type=nk.SERVER,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        is_fixed_role=True),
            )


def _change_password_to_sql_logins(d: _ServerData, source: _Principal) -> Iterator[Edge]:
    """ChangePassword edges from an ALTER-ANY-LOGIN source to eligible SQL logins.

    Mirrors the shared loop in the securityadmin / ##MS_LoginManager## branches
    (and the explicit ALTER ANY LOGIN permission case): target must be a SQL_LOGIN,
    not ``sa``, not the source itself, and must NOT already have sysadmin / CONTROL
    SERVER. The CVE-2025-49758 gate (:func:`_should_change_password`) then decides.
    """
    for target in d.server_principals:
        if target.type_desc != "SQL_LOGIN":
            continue
        if target.name == "sa":
            continue
        if target.object_identifier == source.object_identifier:
            continue
        if d.has_sysadmin(target.object_identifier) or d.has_control_server(target.object_identifier):
            continue
        if not _should_change_password(d, target):
            continue
        yield _edge(
            source.object_identifier, target.object_identifier, ek.CHANGE_PASSWORD,
            EdgeCtx(source_name=source.name, source_type=nk.SERVER_ROLE,
                    target_name=target.name, target_type=nk.LOGIN,
                    target_type_description=target.type_desc,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid,
                    permission="ALTER ANY LOGIN"),
        )


def _fixed_database_role_edges(d: _ServerData) -> Iterator[Edge]:
    for db_name, principals in d.db_principals.items():
        db_oid = ids.database_oid(d.server_oid, db_name)
        for role in principals:
            if role.type_desc != "DATABASE_ROLE" or not role.is_fixed_role:
                continue
            if role.name == "db_owner":
                # db_owner has CONTROL on the database: Control (non-trav) + ControlDB.
                for kind in (ek.CONTROL, ek.CONTROL_DB):
                    yield _edge(
                        role.object_identifier, db_oid, kind,
                        EdgeCtx(source_name=role.name, source_type=nk.DATABASE_ROLE,
                                target_name=db_name, target_type=nk.DATABASE,
                                target_type_description="DATABASE",
                                sql_server_name=d.server_name, sql_server_id=d.server_oid,
                                database_name=db_name, is_fixed_role=True),
                    )
            elif role.name == "db_securityadmin":
                # GrantAnyDBPermission + AlterAnyAppRole + AlterAnyDBRole on the db.
                for kind in (ek.GRANT_ANY_DB_PERMISSION, ek.ALTER_ANY_APP_ROLE, ek.ALTER_ANY_DB_ROLE):
                    yield _edge(
                        role.object_identifier, db_oid, kind,
                        EdgeCtx(source_name=role.name, source_type=nk.DATABASE_ROLE,
                                target_name=db_name, target_type=nk.DATABASE,
                                sql_server_name=d.server_name, sql_server_id=d.server_oid,
                                database_name=db_name, is_fixed_role=True),
                    )
                # AddMember to user-defined, non-public DB roles.
                for target in principals:
                    if target.type_desc == "DATABASE_ROLE" and not target.is_fixed_role and target.name != "public":
                        yield _edge(
                            role.object_identifier, target.object_identifier, ek.ADD_MEMBER,
                            EdgeCtx(source_name=role.name, source_type=nk.DATABASE_ROLE,
                                    target_name=target.name, target_type=nk.DATABASE_ROLE,
                                    target_type_description=target.type_desc,
                                    sql_server_name=d.server_name, sql_server_id=d.server_oid,
                                    database_name=db_name, is_fixed_role=True),
                        )
                # ChangePassword to application roles (via ALTER ANY APPLICATION ROLE).
                for app_role in principals:
                    if app_role.type_desc == "APPLICATION_ROLE":
                        yield _edge(
                            role.object_identifier, app_role.object_identifier, ek.CHANGE_PASSWORD,
                            EdgeCtx(source_name=role.name, source_type=nk.DATABASE_ROLE,
                                    target_name=app_role.name, target_type=nk.APPLICATION_ROLE,
                                    target_type_description=app_role.type_desc,
                                    sql_server_name=d.server_name, sql_server_id=d.server_oid,
                                    database_name=db_name, is_fixed_role=True),
                        )
            # db_accessadmin: no edges (Go comment).


def _should_change_password(d: _ServerData, target: _Principal) -> bool:
    """CVE-2025-49758 gate (Go ``shouldCreateChangePasswordEdge``).

    If the server is patched, suppress the edge when the target has securityadmin
    or IMPERSONATE ANY LOGIN (the patch blocks changing those targets' passwords
    without the current password). Unpatched / unprivileged target -> create it.
    The patch verdict is the inverse of the CVE-vulnerable flag (an unparseable
    version is conservatively treated as patched, matching Go ``IsPatched...``).
    """
    from ..cve import check_cve_2025_49758

    version = d.server_version()
    is_patched = not check_cve_2025_49758(version)["vulnerable"]
    if is_patched and (
        d.has_securityadmin(target.object_identifier)
        or d.has_impersonate_any_login(target.object_identifier)
    ):
        logger.debug("derive_edges: ChangePassword to %r suppressed (patched + protected target)", target.name)
        return False
    return True


# ===========================================================================
# SERVER PERMISSION edges (Go createServerPermissionEdges)
# ===========================================================================
def _server_permission_edges(d: _ServerData) -> Iterator[Edge]:
    for perm in d.lookup.table_rows("server_permissions"):
        state = (perm.get("state_desc") or "").upper()
        if state not in _GRANT_STATES:
            continue
        grantee_id = _int(perm.get("grantee_principal_id"))
        if grantee_id is None:
            continue
        source = d.server_by_id.get(grantee_id)
        if source is None:
            continue
        permission = perm.get("permission_name") or ""
        class_desc = perm.get("class_desc") or ""
        target_id = _int(perm.get("major_id"))
        with_grant = state == "GRANT_WITH_GRANT_OPTION"
        src_kind = _server_principal_kind(source.type_desc)

        if permission == "CONTROL SERVER":
            yield _edge(
                source.object_identifier, d.server_oid, ek.CONTROL_SERVER,
                EdgeCtx(source_name=source.name, source_type=src_kind,
                        target_name=d.server_name, target_type=nk.SERVER,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        permission=permission),
                with_grant=with_grant,
            )
        elif permission == "CONNECT SQL":
            if not source.is_disabled:
                yield _edge(
                    source.object_identifier, d.server_oid, ek.CONNECT,
                    EdgeCtx(source_name=source.name, source_type=src_kind,
                            target_name=d.server_name, target_type=nk.SERVER,
                            target_type_description="SERVER",
                            sql_server_name=d.server_name, sql_server_id=d.server_oid,
                            permission=permission),
                    with_grant=with_grant,
                )
        elif permission == "CONNECT ANY DATABASE":
            yield _edge(
                source.object_identifier, d.server_oid, ek.CONNECT_ANY_DATABASE,
                EdgeCtx(source_name=source.name, source_type=src_kind,
                        target_name=d.server_name, target_type=nk.SERVER,
                        target_type_description="SERVER",
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        permission=permission),
                with_grant=with_grant,
            )
        elif permission == "CONTROL":
            if class_desc == "SERVER_PRINCIPAL" and target_id is not None:
                yield from _server_control_on_principal(d, source, target_id, permission, with_grant)
        elif permission == "ALTER":
            if class_desc == "SERVER_PRINCIPAL" and target_id is not None:
                yield from _server_alter_on_principal(d, source, target_id, permission, with_grant)
        elif permission == "TAKE OWNERSHIP":
            if class_desc == "SERVER_PRINCIPAL" and target_id is not None:
                yield from _server_take_ownership(d, source, target_id, permission, with_grant)
        elif permission == "IMPERSONATE":
            if class_desc == "SERVER_PRINCIPAL" and target_id is not None:
                yield from _server_impersonate(d, source, target_id, permission, with_grant)
        elif permission == "IMPERSONATE ANY LOGIN":
            yield _edge(
                source.object_identifier, d.server_oid, ek.IMPERSONATE_ANY_LOGIN,
                EdgeCtx(source_name=source.name, source_type=src_kind,
                        target_name=d.server_name, target_type=nk.SERVER,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        permission=permission),
                with_grant=with_grant,
            )
        elif permission == "ALTER ANY LOGIN":
            yield _edge(
                source.object_identifier, d.server_oid, ek.ALTER_ANY_LOGIN,
                EdgeCtx(source_name=source.name, source_type=src_kind,
                        target_name=d.server_name, target_type=nk.SERVER,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        permission=permission),
                with_grant=with_grant,
            )
            # ChangePassword to eligible SQL logins (same gating as fixed roles, but
            # the source type is the granting principal's kind, not always ServerRole).
            for target in d.server_principals:
                if target.type_desc != "SQL_LOGIN":
                    continue
                if target.name == "sa" or target.object_identifier == source.object_identifier:
                    continue
                if d.has_sysadmin(target.object_identifier) or d.has_control_server(target.object_identifier):
                    continue
                if not _should_change_password(d, target):
                    continue
                yield _edge(
                    source.object_identifier, target.object_identifier, ek.CHANGE_PASSWORD,
                    EdgeCtx(source_name=source.name, source_type=src_kind,
                            target_name=target.name, target_type=nk.LOGIN,
                            target_type_description=target.type_desc,
                            sql_server_name=d.server_name, sql_server_id=d.server_oid,
                            permission=permission),
                    with_grant=with_grant,
                )
        elif permission == "ALTER ANY SERVER ROLE":
            yield _edge(
                source.object_identifier, d.server_oid, ek.ALTER_ANY_SERVER_ROLE,
                EdgeCtx(source_name=source.name, source_type=src_kind,
                        target_name=d.server_name, target_type=nk.SERVER,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        permission=permission),
                with_grant=with_grant,
            )
            # AddMember to each applicable server role.
            member_names = _direct_member_role_names(d, source)
            for target in d.server_principals:
                if target.type_desc != "SERVER_ROLE":
                    continue
                if _can_alter_server_role(target, member_names):
                    yield _edge(
                        source.object_identifier, target.object_identifier, ek.ADD_MEMBER,
                        EdgeCtx(source_name=source.name, source_type=src_kind,
                                target_name=target.name, target_type=nk.SERVER_ROLE,
                                target_type_description=target.type_desc,
                                sql_server_name=d.server_name, sql_server_id=d.server_oid,
                                permission=permission),
                        with_grant=with_grant,
                    )


def _direct_member_role_names(d: _ServerData, principal: _Principal) -> set[str]:
    """Direct server-role names *principal* is a member of (Go principal.MemberOf).

    Used for the fixed-role AddMember preconditions ("source is a member of the
    target fixed role"). Reads the raw server_role_members table.
    """
    names: set[str] = set()
    role_by_id = {p.principal_id: p for p in d.server_principals}
    for rm in d.lookup.table_rows("server_role_members"):
        if _int(rm.get("member_principal_id")) == principal.principal_id:
            role = role_by_id.get(_int(rm.get("role_principal_id")))
            if role is not None:
                names.add(role.name)
    return names


def _can_alter_server_role(target: _Principal, source_member_role_names: set[str]) -> bool:
    """ALTER ANY SERVER ROLE add-member precondition (Go createServerPermissionEdges).

    User-defined role: always. Fixed role (except sysadmin): only if the source is
    a direct member of that role (``source_member_role_names`` carries the source's
    direct server-role memberships).
    """
    if not target.is_fixed_role:
        return True
    if target.name == "sysadmin":
        return False
    return target.name in source_member_role_names


def _server_control_on_principal(
    d: _ServerData, source: _Principal, target_id: int, permission: str, with_grant: bool
) -> Iterator[Edge]:
    target = d.server_by_id.get(target_id)
    if target is None:
        return
    src_kind = _server_principal_kind(source.type_desc)
    is_server_role = target.type_desc == "SERVER_ROLE"
    target_kind = nk.SERVER_ROLE if is_server_role else nk.LOGIN
    base = dict(source_name=source.name, source_type=src_kind,
                target_name=target.name, target_type=target_kind,
                target_type_description=target.type_desc,
                sql_server_name=d.server_name, sql_server_id=d.server_oid,
                permission=permission)
    # Non-traversable Control first.
    yield _edge(source.object_identifier, target.object_identifier, ek.CONTROL, EdgeCtx(**base), with_grant=with_grant)
    if not is_server_role:
        # CONTROL on login => ExecuteAs (impersonate), even sa.
        yield _edge(source.object_identifier, target.object_identifier, ek.EXECUTE_AS, EdgeCtx(**base), with_grant=with_grant)
    else:
        # CONTROL on role => AddMember (if allowed) + ChangeOwner.
        member_names = _direct_member_role_names(d, source)
        can_add = (not target.is_fixed_role) or (target.is_fixed_role and target.name != "sysadmin" and target.name in member_names)
        if can_add:
            yield _edge(source.object_identifier, target.object_identifier, ek.ADD_MEMBER, EdgeCtx(**base), with_grant=with_grant)
        yield _edge(source.object_identifier, target.object_identifier, ek.CHANGE_OWNER, EdgeCtx(**base), with_grant=with_grant)


def _server_alter_on_principal(
    d: _ServerData, source: _Principal, target_id: int, permission: str, with_grant: bool
) -> Iterator[Edge]:
    target = d.server_by_id.get(target_id)
    if target is None:
        return
    src_kind = _server_principal_kind(source.type_desc)
    is_server_role = target.type_desc == "SERVER_ROLE"
    target_kind = nk.SERVER_ROLE if is_server_role else nk.LOGIN
    base = dict(source_name=source.name, source_type=src_kind,
                target_name=target.name, target_type=target_kind,
                target_type_description=target.type_desc,
                sql_server_name=d.server_name, sql_server_id=d.server_oid,
                permission=permission)
    yield _edge(source.object_identifier, target.object_identifier, ek.ALTER, EdgeCtx(**base), with_grant=with_grant)
    if is_server_role:
        member_names = _direct_member_role_names(d, source)
        can_add = (not target.is_fixed_role) or (target.is_fixed_role and target.name != "sysadmin" and target.name in member_names)
        if can_add:
            yield _edge(source.object_identifier, target.object_identifier, ek.ADD_MEMBER, EdgeCtx(**base), with_grant=with_grant)


def _server_take_ownership(
    d: _ServerData, source: _Principal, target_id: int, permission: str, with_grant: bool
) -> Iterator[Edge]:
    target = d.server_by_id.get(target_id)
    if target is None:
        return
    src_kind = _server_principal_kind(source.type_desc)
    target_kind = nk.SERVER_ROLE if target.type_desc == "SERVER_ROLE" else nk.LOGIN
    base = dict(source_name=source.name, source_type=src_kind,
                target_name=target.name, target_type=target_kind,
                target_type_description=target.type_desc,
                sql_server_name=d.server_name, sql_server_id=d.server_oid,
                permission=permission)
    yield _edge(source.object_identifier, target.object_identifier, ek.TAKE_OWNERSHIP, EdgeCtx(**base), with_grant=with_grant)
    if target.type_desc == "SERVER_ROLE":
        yield _edge(source.object_identifier, target.object_identifier, ek.CHANGE_OWNER, EdgeCtx(**base), with_grant=with_grant)


def _server_impersonate(
    d: _ServerData, source: _Principal, target_id: int, permission: str, with_grant: bool
) -> Iterator[Edge]:
    target = d.server_by_id.get(target_id)
    if target is None:
        return
    src_kind = _server_principal_kind(source.type_desc)
    base = dict(source_name=source.name, source_type=src_kind,
                target_name=target.name, target_type=nk.LOGIN,
                target_type_description=target.type_desc,
                sql_server_name=d.server_name, sql_server_id=d.server_oid,
                permission=permission)
    yield _edge(source.object_identifier, target.object_identifier, ek.IMPERSONATE, EdgeCtx(**base), with_grant=with_grant)
    yield _edge(source.object_identifier, target.object_identifier, ek.EXECUTE_AS, EdgeCtx(**base), with_grant=with_grant)


# ===========================================================================
# DATABASE PERMISSION edges (Go createDatabasePermissionEdges)
# ===========================================================================
def _database_permission_edges(d: _ServerData) -> Iterator[Edge]:
    for db in d.databases:
        db_name = db.get("name") or ""
        db_oid = ids.database_oid(d.server_oid, db_name)
        principals = d.db_principals.get(db_name, [])
        by_id = {p.principal_id: p for p in principals}
        yield from _database_permission_edges_for_db(d, db_name, db_oid, principals, by_id)


def _database_permission_edges_for_db(
    d: _ServerData, db_name: str, db_oid: str, principals: list[_Principal], by_id: dict[int, _Principal]
) -> Iterator[Edge]:
    for perm in d.lookup.table_rows("database_permissions"):
        if (perm.get("database") or perm.get("database_name") or "") != db_name:
            continue
        state = (perm.get("state_desc") or "").upper()
        if state not in _GRANT_STATES:
            continue
        grantee_id = _int(perm.get("grantee_principal_id"))
        if grantee_id is None:
            continue
        source = by_id.get(grantee_id)
        if source is None:
            continue
        permission = perm.get("permission_name") or ""
        class_desc = perm.get("class_desc") or ""
        target_id = _int(perm.get("major_id"))
        with_grant = state == "GRANT_WITH_GRANT_OPTION"
        src_kind = _database_principal_kind(source.type_desc)

        if permission == "CONTROL":
            yield from _db_control(d, db_name, db_oid, source, src_kind, class_desc, target_id, by_id, permission, with_grant)
        elif permission == "CONNECT":
            if class_desc == "DATABASE":
                yield _edge(
                    source.object_identifier, db_oid, ek.CONNECT,
                    EdgeCtx(source_name=source.name, source_type=src_kind,
                            target_name=db_name, target_type=nk.DATABASE,
                            target_type_description="DATABASE",
                            sql_server_name=d.server_name, sql_server_id=d.server_oid,
                            database_name=db_name, permission=permission),
                    with_grant=with_grant,
                )
        elif permission == "ALTER":
            yield from _db_alter(d, db_name, db_oid, source, src_kind, class_desc, target_id, principals, by_id, permission, with_grant)
        elif permission == "ALTER ANY ROLE":
            yield from _db_alter_any_role(d, db_name, db_oid, source, src_kind, principals, permission, with_grant)
        elif permission == "ALTER ANY APPLICATION ROLE":
            yield from _db_alter_any_app_role(d, db_name, db_oid, source, src_kind, principals, permission, with_grant)
        elif permission == "IMPERSONATE":
            if class_desc == "DATABASE_PRINCIPAL" and target_id is not None:
                yield from _db_impersonate(d, db_name, source, src_kind, target_id, by_id, permission, with_grant)
        elif permission == "TAKE OWNERSHIP":
            yield from _db_take_ownership(d, db_name, db_oid, source, src_kind, class_desc, target_id, principals, by_id, permission, with_grant)


def _db_control(d, db_name, db_oid, source, src_kind, class_desc, target_id, by_id, permission, with_grant):
    if class_desc == "DATABASE":
        base = dict(source_name=source.name, source_type=src_kind,
                    target_name=db_name, target_type=nk.DATABASE,
                    target_type_description="DATABASE",
                    sql_server_name=d.server_name, sql_server_id=d.server_oid,
                    database_name=db_name, permission=permission)
        yield _edge(source.object_identifier, db_oid, ek.CONTROL, EdgeCtx(**base), with_grant=with_grant)
        yield _edge(source.object_identifier, db_oid, ek.CONTROL_DB, EdgeCtx(**base), with_grant=with_grant)
    elif class_desc == "DATABASE_PRINCIPAL" and target_id is not None:
        target = by_id.get(target_id)
        if target is None:
            return
        target_kind = _database_principal_kind(target.type_desc)
        is_role = target.type_desc == "DATABASE_ROLE"
        is_user = target.type_desc in _DB_USER_TYPES
        base = dict(source_name=source.name, source_type=src_kind,
                    target_name=target.name, target_type=target_kind,
                    target_type_description=target.type_desc,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid,
                    database_name=db_name, permission=permission)
        yield _edge(source.object_identifier, target.object_identifier, ek.CONTROL, EdgeCtx(**base), with_grant=with_grant)
        if is_role:
            yield _edge(source.object_identifier, target.object_identifier, ek.ADD_MEMBER, EdgeCtx(**base), with_grant=with_grant)
            yield _edge(source.object_identifier, target.object_identifier, ek.CHANGE_OWNER, EdgeCtx(**base), with_grant=with_grant)
        elif is_user:
            yield _edge(source.object_identifier, target.object_identifier, ek.EXECUTE_AS, EdgeCtx(**base), with_grant=with_grant)


def _db_alter(d, db_name, db_oid, source, src_kind, class_desc, target_id, principals, by_id, permission, with_grant):
    if class_desc == "DATABASE":
        yield _edge(
            source.object_identifier, db_oid, ek.ALTER,
            EdgeCtx(source_name=source.name, source_type=src_kind,
                    target_name=db_name, target_type=nk.DATABASE,
                    target_type_description="DATABASE",
                    sql_server_name=d.server_name, sql_server_id=d.server_oid,
                    database_name=db_name, permission=permission),
            with_grant=with_grant,
        )
        # ALTER on database grants effective ALTER ANY ROLE + ALTER ANY APP ROLE.
        is_db_owner = "db_owner" in _direct_db_member_role_names(d, db_name, source)
        for target in principals:
            if target.object_identifier == source.object_identifier:
                continue
            if target.type_desc == "DATABASE_ROLE":
                if target.name != "public" and (is_db_owner or not target.is_fixed_role):
                    yield _edge(
                        source.object_identifier, target.object_identifier, ek.ADD_MEMBER,
                        EdgeCtx(source_name=source.name, source_type=src_kind,
                                target_name=target.name, target_type=nk.DATABASE_ROLE,
                                target_type_description=target.type_desc,
                                sql_server_name=d.server_name, sql_server_id=d.server_oid,
                                database_name=db_name, permission=permission),
                        with_grant=with_grant,
                    )
            elif target.type_desc == "APPLICATION_ROLE":
                yield _edge(
                    source.object_identifier, target.object_identifier, ek.CHANGE_PASSWORD,
                    EdgeCtx(source_name=source.name, source_type=src_kind,
                            target_name=target.name, target_type=nk.APPLICATION_ROLE,
                            target_type_description=target.type_desc,
                            sql_server_name=d.server_name, sql_server_id=d.server_oid,
                            database_name=db_name, permission=permission),
                    with_grant=with_grant,
                )
    elif class_desc == "DATABASE_PRINCIPAL" and target_id is not None:
        target = by_id.get(target_id)
        if target is None:
            return
        target_kind = _database_principal_kind(target.type_desc)
        is_role = target.type_desc == "DATABASE_ROLE"
        base = dict(source_name=source.name, source_type=src_kind,
                    target_name=target.name, target_type=target_kind,
                    target_type_description=target.type_desc,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid,
                    database_name=db_name, permission=permission)
        yield _edge(source.object_identifier, target.object_identifier, ek.ALTER, EdgeCtx(**base), with_grant=with_grant)
        if is_role:
            yield _edge(source.object_identifier, target.object_identifier, ek.ADD_MEMBER, EdgeCtx(**base), with_grant=with_grant)


def _db_alter_any_role(d, db_name, db_oid, source, src_kind, principals, permission, with_grant):
    yield _edge(
        source.object_identifier, db_oid, ek.ALTER_ANY_DB_ROLE,
        EdgeCtx(source_name=source.name, source_type=src_kind,
                target_name=db_name, target_type=nk.DATABASE,
                sql_server_name=d.server_name, sql_server_id=d.server_oid,
                database_name=db_name, permission=permission),
        with_grant=with_grant,
    )
    is_db_owner = "db_owner" in _direct_db_member_role_names(d, db_name, source)
    for target in principals:
        if target.type_desc != "DATABASE_ROLE":
            continue
        if target.object_identifier == source.object_identifier:
            continue
        if target.name == "public":
            continue
        if is_db_owner or not target.is_fixed_role:
            yield _edge(
                source.object_identifier, target.object_identifier, ek.ADD_MEMBER,
                EdgeCtx(source_name=source.name, source_type=src_kind,
                        target_name=target.name, target_type=nk.DATABASE_ROLE,
                        target_type_description=target.type_desc,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        database_name=db_name, permission=permission),
                with_grant=with_grant,
            )


def _db_alter_any_app_role(d, db_name, db_oid, source, src_kind, principals, permission, with_grant):
    yield _edge(
        source.object_identifier, db_oid, ek.ALTER_ANY_APP_ROLE,
        EdgeCtx(source_name=source.name, source_type=src_kind,
                target_name=db_name, target_type=nk.DATABASE,
                sql_server_name=d.server_name, sql_server_id=d.server_oid,
                database_name=db_name, permission=permission),
        with_grant=with_grant,
    )
    for app_role in principals:
        if app_role.type_desc == "APPLICATION_ROLE" and app_role.object_identifier != source.object_identifier:
            yield _edge(
                source.object_identifier, app_role.object_identifier, ek.CHANGE_PASSWORD,
                EdgeCtx(source_name=source.name, source_type=src_kind,
                        target_name=app_role.name, target_type=nk.APPLICATION_ROLE,
                        target_type_description=app_role.type_desc,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        database_name=db_name, permission=permission),
                with_grant=with_grant,
            )


def _db_impersonate(d, db_name, source, src_kind, target_id, by_id, permission, with_grant):
    target = by_id.get(target_id)
    if target is None:
        return
    base = dict(source_name=source.name, source_type=src_kind,
                target_name=target.name, target_type=nk.DATABASE_USER,
                target_type_description=target.type_desc,
                sql_server_name=d.server_name, sql_server_id=d.server_oid,
                database_name=db_name, permission=permission)
    yield _edge(source.object_identifier, target.object_identifier, ek.IMPERSONATE, EdgeCtx(**base), with_grant=with_grant)
    yield _edge(source.object_identifier, target.object_identifier, ek.EXECUTE_AS, EdgeCtx(**base), with_grant=with_grant)


def _db_take_ownership(d, db_name, db_oid, source, src_kind, class_desc, target_id, principals, by_id, permission, with_grant):
    if class_desc == "DATABASE":
        yield _edge(
            source.object_identifier, db_oid, ek.TAKE_OWNERSHIP,
            EdgeCtx(source_name=source.name, source_type=src_kind,
                    target_name=db_name, target_type=nk.DATABASE,
                    target_type_description="DATABASE",
                    sql_server_name=d.server_name, sql_server_id=d.server_oid,
                    database_name=db_name, permission=permission),
            with_grant=with_grant,
        )
        # ChangeOwner to all database roles.
        for target in principals:
            if target.type_desc == "DATABASE_ROLE":
                yield _edge(
                    source.object_identifier, target.object_identifier, ek.CHANGE_OWNER,
                    EdgeCtx(source_name=source.name, source_type=src_kind,
                            target_name=target.name, target_type=nk.DATABASE_ROLE,
                            target_type_description=target.type_desc,
                            sql_server_name=d.server_name, sql_server_id=d.server_oid,
                            database_name=db_name, permission=permission),
                    with_grant=with_grant,
                )
    elif target_id is not None:
        target = by_id.get(target_id)
        if target is None:
            return
        target_kind = _database_principal_kind(target.type_desc)
        base = dict(source_name=source.name, source_type=src_kind,
                    target_name=target.name, target_type=target_kind,
                    target_type_description=target.type_desc,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid,
                    database_name=db_name, permission=permission)
        yield _edge(source.object_identifier, target.object_identifier, ek.TAKE_OWNERSHIP, EdgeCtx(**base), with_grant=with_grant)
        if target.type_desc == "DATABASE_ROLE":
            yield _edge(source.object_identifier, target.object_identifier, ek.CHANGE_OWNER, EdgeCtx(**base), with_grant=with_grant)


def _direct_db_member_role_names(d: _ServerData, db_name: str, principal: _Principal) -> set[str]:
    """Direct database-role names *principal* is a member of (Go principal.MemberOf).

    Used for the db_owner precondition on ALTER / ALTER ANY ROLE add-member edges.
    """
    names: set[str] = set()
    by_id = {p.principal_id: p for p in d.db_principals.get(db_name, [])}
    for rm in d.lookup.table_rows("database_role_members"):
        if (rm.get("database") or rm.get("database_name") or "") != db_name:
            continue
        if _int(rm.get("member_principal_id")) == principal.principal_id:
            role = by_id.get(_int(rm.get("role_principal_id")))
            if role is not None:
                names.add(role.name)
    return names


# ===========================================================================
# TRUSTWORTHY edges (IsTrustedBy + ExecuteAsOwner) — Go createEdges
# ===========================================================================
def _trustworthy_edges(d: _ServerData) -> Iterator[Edge]:
    server_by_name = {p.name: p for p in d.server_principals}
    for db in d.databases:
        if not _bool(db.get("is_trustworthy_on")):
            continue
        db_name = db.get("name") or ""
        db_oid = ids.database_oid(d.server_oid, db_name)
        owner_name = db.get("owner_name") or ""
        owner = server_by_name.get(owner_name)

        # IsTrustedBy: database -> server (always for trustworthy DBs).
        yield _edge(
            db_oid, d.server_oid, ek.IS_TRUSTED_BY,
            EdgeCtx(source_name=db_name, source_type=nk.DATABASE,
                    target_name=d.server_name, target_type=nk.SERVER,
                    sql_server_name=d.server_name, sql_server_id=d.server_oid),
        )

        # ExecuteAsOwner: database -> server when the owner has high privileges.
        if owner is None:
            continue
        oid = owner.object_identifier
        owner_sysadmin = d.has_sysadmin(oid)
        owner_securityadmin = d.has_securityadmin(oid)
        owner_control_server = d.has_control_server(oid)
        owner_impersonate = d.has_impersonate_any_login(oid)
        if owner_sysadmin or owner_securityadmin or owner_control_server or owner_impersonate:
            edge = _edge(
                db_oid, d.server_oid, ek.EXECUTE_AS_OWNER,
                EdgeCtx(source_name=db_name, source_type=nk.DATABASE,
                        target_name=d.server_name, target_type=nk.SERVER,
                        sql_server_name=d.server_name, sql_server_id=d.server_oid,
                        database_name=db_name),
            )
            yield edge


__all__ = ["derive_edges"]
