"""Direct role-membership / member / explicit-permission maps for node assets.

The principal node builders (server_principal.py, database_principal.py) need three
per-principal facts that Go computes during collection and reads off the in-memory
``ServerPrincipal`` / ``DatabasePrincipal``:

* ``memberOfRoles`` — the *direct* role names a principal is a member of (NOT the
  transitive closure ``transforms`` builds for edges), plus the implicit ``public``
  membership for non-role principals (client.go ``collectServerRoleMemberships`` /
  ``collectDatabaseRoleMemberships``).
* ``members`` — for a role, the *direct* member names (client.go same functions).
* ``explicitPermissions`` — every ``permission_name`` granted/denied to the
  principal in ``server_permissions`` / ``database_permissions`` (the collection
  query already filters to GRANT / GRANT_WITH_GRANT_OPTION / DENY), PLUS the
  fixed-role *predefined* permissions Go appends for ``##MS_LoginManager##`` and
  ``##MS_DatabaseConnector##`` at the server level (client.go
  ``collectServerPermissions`` lines 1886-1920; the database-level predefined map
  is empty).

These are read from the RAW DuckDB tables (``server_role_members``,
``server_permissions``, ``database_role_members``, ``database_permissions``) and
the resulting maps are memoized on the injected lookup instance, so a full convert
scans each raw table once instead of once per principal. ``self._lookup`` is the
read-only preproc DuckDB.
"""
from __future__ import annotations

import logging
from typing import Optional

from . import _common

logger = logging.getLogger(__name__)

# Cache attribute names planted on the lookup instance (one set per convert run).
_SRV_ATTR = "_mssql_server_membership_cache"
_DB_ATTR = "_mssql_database_membership_cache"

# Server-level fixed-role predefined permissions Go appends to explicitPermissions
# (client.go collectServerPermissions). sysadmin / securityadmin are intentionally
# absent (createFixedRoleEdges handles those by name).
_FIXED_SERVER_PREDEFINED: dict[str, list[str]] = {
    "##MS_LoginManager##": ["ALTER ANY LOGIN"],
    "##MS_DatabaseConnector##": ["CONNECT ANY DATABASE"],
}
# Database-level predefined map is empty in Go (createFixedRoleEdges handles all
# fixed-db-role permissions by name).
_FIXED_DATABASE_PREDEFINED: dict[str, list[str]] = {}


class _ServerMembership:
    """Per-server direct memberships + members + explicit permissions, by principal_id."""

    def __init__(self, lookup) -> None:
        # member_principal_id -> [role names] (direct memberships).
        self.member_of: dict[int, list[str]] = {}
        # role_principal_id -> [member names] (direct members of a role).
        self.members: dict[int, list[str]] = {}
        # grantee_principal_id -> [permission names] (explicit grants/denies).
        self.perms: dict[int, list[str]] = {}
        self._build(lookup)

    def _build(self, lookup) -> None:
        # principal_id -> name, for resolving member names in role membership rows.
        id_to_name: dict[int, str] = {}
        for row in lookup.table_rows("server_principals"):
            pid = _common.as_int(row.get("principal_id"), default=-1)
            if pid >= 0:
                id_to_name[pid] = row.get("name") or ""

        for rm in lookup.table_rows("server_role_members"):
            member_id = _common.as_int(rm.get("member_principal_id"), default=-1)
            role_id = _common.as_int(rm.get("role_principal_id"), default=-1)
            role_name = rm.get("role_name") or ""
            if member_id >= 0 and role_name:
                self.member_of.setdefault(member_id, []).append(role_name)
            if role_id >= 0:
                self.members.setdefault(role_id, []).append(id_to_name.get(member_id, ""))

        for perm in lookup.table_rows("server_permissions"):
            grantee = _common.as_int(perm.get("grantee_principal_id"), default=-1)
            name = perm.get("permission_name") or ""
            if grantee >= 0 and name:
                self.perms.setdefault(grantee, []).append(name)

        logger.debug("members: built server membership maps (%d principals with roles)",
                     len(self.member_of))


class _DatabaseMembership:
    """Per-(database, principal_id) direct memberships + members + explicit perms."""

    def __init__(self, lookup) -> None:
        # (database, member_principal_id) -> [role names].
        self.member_of: dict[tuple[str, int], list[str]] = {}
        # (database, role_principal_id) -> [member names].
        self.members: dict[tuple[str, int], list[str]] = {}
        # (database, grantee_principal_id) -> [permission names].
        self.perms: dict[tuple[str, int], list[str]] = {}
        self._build(lookup)

    def _build(self, lookup) -> None:
        # (database, principal_id) -> name.
        id_to_name: dict[tuple[str, int], str] = {}
        for row in lookup.table_rows("database_principals"):
            db = row.get("database") or row.get("database_name") or ""
            pid = _common.as_int(row.get("principal_id"), default=-1)
            if pid >= 0:
                id_to_name[(db, pid)] = row.get("name") or ""

        for rm in lookup.table_rows("database_role_members"):
            db = rm.get("database") or rm.get("database_name") or ""
            member_id = _common.as_int(rm.get("member_principal_id"), default=-1)
            role_id = _common.as_int(rm.get("role_principal_id"), default=-1)
            role_name = rm.get("role_name") or ""
            if member_id >= 0 and role_name:
                self.member_of.setdefault((db, member_id), []).append(role_name)
            if role_id >= 0:
                self.members.setdefault((db, role_id), []).append(
                    id_to_name.get((db, member_id), "")
                )

        for perm in lookup.table_rows("database_permissions"):
            db = perm.get("database") or perm.get("database_name") or ""
            grantee = _common.as_int(perm.get("grantee_principal_id"), default=-1)
            name = perm.get("permission_name") or ""
            if grantee >= 0 and name:
                self.perms.setdefault((db, grantee), []).append(name)

        logger.debug("members: built database membership maps (%d (db,principal) with roles)",
                     len(self.member_of))


def _server_membership(lookup) -> _ServerMembership:
    cached = getattr(lookup, _SRV_ATTR, None)
    if cached is None:
        cached = _ServerMembership(lookup)
        setattr(lookup, _SRV_ATTR, cached)
    return cached


def _database_membership(lookup) -> _DatabaseMembership:
    cached = getattr(lookup, _DB_ATTR, None)
    if cached is None:
        cached = _DatabaseMembership(lookup)
        setattr(lookup, _DB_ATTR, cached)
    return cached


# ---------------------------------------------------------------------------
# Server-level public API
# ---------------------------------------------------------------------------
def server_member_of(lookup, principal_id: int, type_desc: str) -> list[str]:
    """Direct role names *principal_id* is a member of, + implicit ``public``.

    Implicit ``public`` is added for every non-``SERVER_ROLE`` principal that is
    not already a member of it (client.go parity).
    """
    roles = list(_server_membership(lookup).member_of.get(principal_id, []))
    if type_desc != "SERVER_ROLE" and "public" not in roles:
        roles.append("public")
    return roles


def server_role_members(lookup, role_principal_id: int) -> list[str]:
    """Direct member names of the server role *role_principal_id*."""
    return list(_server_membership(lookup).members.get(role_principal_id, []))


def server_explicit_permissions(lookup, principal_id: int, name: str, is_fixed_role: bool) -> list[str]:
    """Explicit permission names for a server principal, incl. fixed-role predefined.

    The raw grants/denies, plus the predefined permissions Go appends for the
    ``##MS_LoginManager##`` / ``##MS_DatabaseConnector##`` fixed roles (dedup-safe).
    """
    perms = list(_server_membership(lookup).perms.get(principal_id, []))
    if is_fixed_role:
        for predefined in _FIXED_SERVER_PREDEFINED.get(name, ()):
            if predefined not in perms:
                perms.append(predefined)
    return perms


# ---------------------------------------------------------------------------
# Database-level public API
# ---------------------------------------------------------------------------
# Database principal types that get the implicit ``public`` membership (client.go).
_DB_USER_TYPES = {
    "SQL_USER", "WINDOWS_USER", "WINDOWS_GROUP", "ASYMMETRIC_KEY_MAPPED_USER",
    "CERTIFICATE_MAPPED_USER", "EXTERNAL_USER", "EXTERNAL_GROUPS",
}


def database_member_of(lookup, database: str, principal_id: int, type_desc: str) -> list[str]:
    """Direct role names a DB principal is a member of, + implicit ``public``.

    Implicit ``public`` is added for user-type DB principals (client.go parity);
    roles/app-roles do not get it.
    """
    roles = list(_database_membership(lookup).member_of.get((database, principal_id), []))
    if type_desc in _DB_USER_TYPES and "public" not in roles:
        roles.append("public")
    return roles


def database_role_members(lookup, database: str, role_principal_id: int) -> list[str]:
    """Direct member names of the database role *role_principal_id* in *database*."""
    return list(_database_membership(lookup).members.get((database, role_principal_id), []))


def database_explicit_permissions(lookup, database: str, principal_id: int) -> list[str]:
    """Explicit permission names for a DB principal (no predefined — Go's db map is empty)."""
    perms = list(_database_membership(lookup).perms.get((database, principal_id), []))
    if _FIXED_DATABASE_PREDEFINED:  # currently empty; kept for parity if Go adds entries
        pass
    return perms


# ---------------------------------------------------------------------------
# Database-user <-> server-login links (databaseUsers / serverLogin properties)
# ---------------------------------------------------------------------------
_LINKS_ATTR = "_mssql_login_links_cache"


class _LoginLinks:
    """The database-user <-> server-login mapping, both directions.

    Built from the raw ``database_principal_logins`` table (db_principal_id <->
    server_principal_id per database), joined to ``server_principals`` (login OID
    + name) and ``database_principals`` (db-user name). Reproduces Go's
    ``loginDatabaseUsers`` map (login OID -> ["user@db", ...]) and
    ``ServerLogin`` ref (db user -> login name).
    """

    def __init__(self, lookup) -> None:
        # login object_identifier -> ["userName@dbName", ...].
        self.login_database_users: dict[str, list[str]] = {}
        # (database, db_principal_id) -> server login name.
        self.db_user_server_login: dict[tuple[str, int], str] = {}
        self._build(lookup)

    def _build(self, lookup) -> None:
        server_oid = _common.server_oid_for(lookup)

        # server_principal_id -> (object_identifier, name).
        login_by_id: dict[int, tuple[str, str]] = {}
        for row in lookup.table_rows("server_principals"):
            pid = _common.as_int(row.get("principal_id"), default=-1)
            if pid >= 0:
                name = row.get("name") or ""
                login_by_id[pid] = (_login_oid(name, server_oid), name)

        # (database, db_principal_id) -> db-user name.
        dbuser_name: dict[tuple[str, int], str] = {}
        for row in lookup.table_rows("database_principals"):
            db = row.get("database") or row.get("database_name") or ""
            pid = _common.as_int(row.get("principal_id"), default=-1)
            if pid >= 0:
                dbuser_name[(db, pid)] = row.get("name") or ""

        for link in lookup.table_rows("database_principal_logins"):
            db = link.get("database") or link.get("database_name") or ""
            db_pid = _common.as_int(link.get("db_principal_id"), default=-1)
            srv_pid = _common.as_int(link.get("server_principal_id"), default=-1)
            login = login_by_id.get(srv_pid)
            if login is None or db_pid < 0:
                # Link references a login/user we can't resolve — skip it.
                continue
            login_oid, login_name = login
            self.db_user_server_login[(db, db_pid)] = (
                link.get("server_login_name") or login_name
            )
            user_name = dbuser_name.get((db, db_pid), "")
            if user_name:
                # Go entry format: "userName@databaseName".
                self.login_database_users.setdefault(login_oid, []).append(f"{user_name}@{db}")

        logger.debug("members: built login-link maps (%d login(s) with db users)",
                     len(self.login_database_users))


def _login_oid(name: str, server_oid: str) -> str:
    """Server-login object identifier ``name@serverOID`` (matches ids.principal_oid)."""
    return f"{name}@{server_oid}"


def _login_links(lookup) -> _LoginLinks:
    cached = getattr(lookup, _LINKS_ATTR, None)
    if cached is None:
        cached = _LoginLinks(lookup)
        setattr(lookup, _LINKS_ATTR, cached)
    return cached


def login_database_users(lookup, login_oid: str) -> list[str]:
    """``["userName@dbName", ...]`` for the server login *login_oid* (Go parity)."""
    return list(_login_links(lookup).login_database_users.get(login_oid, []))


def db_user_server_login(lookup, database: str, db_principal_id: int) -> str | None:
    """Mapped server-login name for a database user, or ``None`` when unmapped."""
    return _login_links(lookup).db_user_server_login.get((database, db_principal_id))


# ---------------------------------------------------------------------------
# Server principal lookup by NAME (database owner resolution)
# ---------------------------------------------------------------------------
_BY_NAME_ATTR = "_mssql_server_principal_by_name_cache"


def server_principal_by_name(lookup, name: str) -> Optional[dict]:
    """The first server principal whose ``name`` matches *name*, or ``None``.

    Returns a dict with ``principal_id`` and ``object_identifier`` keys, used to
    resolve a database's owner login -> OwnerPrincipalID / OwnerObjectIdentifier
    (Go collectDatabases matches db.OwnerLoginName against the server principals).
    """
    index = getattr(lookup, _BY_NAME_ATTR, None)
    if index is None:
        server_oid = _common.server_oid_for(lookup)
        index = {}
        for row in lookup.table_rows("server_principals"):
            pname = row.get("name") or ""
            pid = _common.as_int(row.get("principal_id"), default=-1)
            if pname and pid >= 0 and pname not in index:
                index[pname] = {
                    "principal_id": pid,
                    "object_identifier": _login_oid(pname, server_oid),
                }
        setattr(lookup, _BY_NAME_ATTR, index)
        logger.debug("members: built server-principal-by-name index (%d names)", len(index))
    return index.get(name)


__all__ = [
    "server_member_of", "server_role_members", "server_explicit_permissions",
    "database_member_of", "database_role_members", "database_explicit_permissions",
    "login_database_users", "db_user_server_login",
]
