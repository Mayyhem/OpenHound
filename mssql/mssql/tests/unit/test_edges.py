"""Fixture-based unit tests for Stage-6 edge derivation (``edges.derive_edges``).

These exercise the port of Go ``createEdges`` / ``createFixedRoleEdges`` /
``createServerPermissionEdges`` / ``createDatabasePermissionEdges`` against a tiny
in-memory fake of :class:`~openhound_mssql.lookup.MSSQLLookup` (no DuckDB), so the
edge logic is verified independently of the live pipeline.

The fake returns the raw rows ``derive_edges`` reads (``servers`` /
``server_principals`` / ``server_role_members`` / ``server_permissions`` /
``databases`` / ``database_principals`` / ``database_role_members`` /
``database_permissions`` / ``database_principal_logins``) plus the derived
``effective_high_priv`` rows (via ``high_priv_principals``). It also supports the
``_common`` caching attributes that ``server_oid_for`` plants on the instance.
"""
from __future__ import annotations

from openhound_mssql.edges import derive_edges
from openhound_mssql.kinds import edges as ek


class FakeLookup:
    """Minimal stand-in for MSSQLLookup over in-memory fixture tables."""

    def __init__(self, tables: dict[str, list[dict]], high_priv: list[dict] | None = None):
        self._tables = tables
        self._high_priv = high_priv or []

    def table_rows(self, table: str):
        # Yield copies so a consumer can't mutate the fixture across passes.
        for row in self._tables.get(table, []):
            yield dict(row)

    def high_priv_principals(self, server_oid: str):
        return [dict(r) for r in self._high_priv]


# A single server keyed by machine name (no computer SID collected) -> the
# server_oid is "<lowerhost>:1433" (ids.server_oid default-instance/default-port).
_SERVER_OID = "ps1-db:1433"
_SERVER_ROW = {
    "machine_name": "PS1-DB",
    "server_name": "PS1-DB",
    "instance_name": "MSSQLSERVER",
    "fqdn": "ps1-db.mayyhem.com",
    "sql_server_name_display": "ps1-db.mayyhem.com:1433",
    "product_version": "16.0.4210.1",  # SQL 2022, patched for CVE
    "full_version": "Microsoft SQL Server 2022 - 16.0.4210.1",
}


def _by_kind(edges):
    counts: dict[str, int] = {}
    for e in edges:
        counts[e.kind] = counts.get(e.kind, 0) + 1
    return counts


def _edges_of(edges, kind):
    return [e for e in edges if e.kind == kind]


def _principal_oid(name: str) -> str:
    return f"{name}@{_SERVER_OID}"


def test_control_server_permission_yields_control_server_edge():
    """A login granted CONTROL SERVER -> MSSQL_ControlServer to the server."""
    tables = {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 10, "name": "attacker", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
        "server_role_members": [],
        "server_permissions": [
            {"grantee_principal_id": 10, "permission_name": "CONTROL SERVER",
             "state_desc": "GRANT", "class_desc": "SERVER", "major_id": 0},
        ],
        "databases": [],
        "database_principals": [],
        "database_role_members": [],
        "database_permissions": [],
        "database_principal_logins": [],
    }
    edges = list(derive_edges(FakeLookup(tables)))
    cs = _edges_of(edges, ek.CONTROL_SERVER)
    assert len(cs) == 1
    edge = cs[0]
    assert edge.start.value == _principal_oid("attacker")
    assert edge.end.value == _SERVER_OID
    assert edge.properties.traversable is True
    assert edge.properties.general  # ControlServer general text present


def test_with_grant_option_sets_with_grant_flag():
    """GRANT_WITH_GRANT_OPTION carries withGrant=True on the edge props."""
    tables = {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 10, "name": "attacker", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
        "server_role_members": [],
        "server_permissions": [
            {"grantee_principal_id": 10, "permission_name": "CONTROL SERVER",
             "state_desc": "GRANT_WITH_GRANT_OPTION", "class_desc": "SERVER", "major_id": 0},
        ],
        "databases": [], "database_principals": [], "database_role_members": [],
        "database_permissions": [], "database_principal_logins": [],
    }
    edges = list(derive_edges(FakeLookup(tables)))
    cs = _edges_of(edges, ek.CONTROL_SERVER)[0]
    assert cs.properties.withGrant is True


def test_nested_membership_yields_member_of_edge():
    """A login that is a direct member of a server role -> MSSQL_MemberOf (no public)."""
    tables = {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 10, "name": "alice", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
            {"principal_id": 20, "name": "customrole", "type_desc": "SERVER_ROLE",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
        "server_role_members": [
            {"member_principal_id": 10, "role_principal_id": 20, "role_name": "customrole"},
        ],
        "server_permissions": [],
        "databases": [], "database_principals": [], "database_role_members": [],
        "database_permissions": [], "database_principal_logins": [],
    }
    edges = list(derive_edges(FakeLookup(tables)))
    member_of = _edges_of(edges, ek.MEMBER_OF)
    # Exactly one MemberOf edge: alice -> customrole. NO implicit public edge.
    assert len(member_of) == 1
    edge = member_of[0]
    assert edge.start.value == _principal_oid("alice")
    assert edge.end.value == _principal_oid("customrole")
    assert edge.properties.traversable is True


def test_sysadmin_fixed_role_yields_control_server():
    """The sysadmin fixed server role -> MSSQL_ControlServer (createFixedRoleEdges)."""
    tables = {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 3, "name": "sysadmin", "type_desc": "SERVER_ROLE",
             "is_disabled": 0, "is_fixed_role": 1},
        ],
        "server_role_members": [],
        "server_permissions": [],
        "databases": [], "database_principals": [], "database_role_members": [],
        "database_permissions": [], "database_principal_logins": [],
    }
    edges = list(derive_edges(FakeLookup(tables)))
    cs = _edges_of(edges, ek.CONTROL_SERVER)
    assert len(cs) == 1
    assert cs[0].start.value == _principal_oid("sysadmin")
    assert cs[0].end.value == _SERVER_OID


def test_db_owner_fixed_role_yields_control_and_control_db():
    """db_owner fixed db role -> MSSQL_Control (non-trav) + MSSQL_ControlDB (trav)."""
    tables = {
        "servers": [_SERVER_ROW],
        "server_principals": [],
        "server_role_members": [],
        "server_permissions": [],
        "databases": [
            {"database_id": 5, "name": "appdb", "owner_name": "sa", "is_trustworthy_on": 0},
        ],
        "database_principals": [
            {"principal_id": 16384, "name": "db_owner", "type_desc": "DATABASE_ROLE",
             "is_fixed_role": 1, "database": "appdb"},
        ],
        "database_role_members": [],
        "database_permissions": [],
        "database_principal_logins": [],
    }
    edges = list(derive_edges(FakeLookup(tables)))
    db_oid = f"{_SERVER_OID}\\appdb"
    role_oid = f"db_owner@{_SERVER_OID}\\appdb"

    control = _edges_of(edges, ek.CONTROL)
    control_db = _edges_of(edges, ek.CONTROL_DB)
    assert len(control) == 1
    assert len(control_db) == 1
    assert control[0].start.value == role_oid and control[0].end.value == db_oid
    assert control_db[0].start.value == role_oid and control_db[0].end.value == db_oid
    # Control is non-traversable; ControlDB is traversable (Go IsTraversableEdge).
    assert control[0].properties.traversable is False
    assert control_db[0].properties.traversable is True


def test_securityadmin_yields_grant_any_permission_and_alter_any_login():
    """securityadmin fixed role -> GrantAnyPermission + AlterAnyLogin (+ChangePassword)."""
    tables = {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 5, "name": "securityadmin", "type_desc": "SERVER_ROLE",
             "is_disabled": 0, "is_fixed_role": 1},
            # An ordinary SQL login (no high priv) -> a ChangePassword target.
            {"principal_id": 30, "name": "weaklogin", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
        "server_role_members": [],
        "server_permissions": [],
        "databases": [], "database_principals": [], "database_role_members": [],
        "database_permissions": [], "database_principal_logins": [],
    }
    edges = list(derive_edges(FakeLookup(tables)))
    counts = _by_kind(edges)
    assert counts.get(ek.GRANT_ANY_PERMISSION) == 1
    assert counts.get(ek.ALTER_ANY_LOGIN) == 1
    # weaklogin has no sysadmin/CONTROL SERVER and server is patched but weaklogin
    # has no securityadmin/IMPERSONATE ANY LOGIN -> ChangePassword edge is created.
    cp = _edges_of(edges, ek.CHANGE_PASSWORD)
    assert len(cp) == 1
    assert cp[0].start.value == _principal_oid("securityadmin")
    assert cp[0].end.value == _principal_oid("weaklogin")


def test_change_password_suppressed_for_high_priv_target_when_patched():
    """Patched server: ChangePassword to a securityadmin target is suppressed (CVE gate)."""
    tables = {
        "servers": [_SERVER_ROW],  # 16.0.4210.1 is patched
        "server_principals": [
            {"principal_id": 5, "name": "securityadmin", "type_desc": "SERVER_ROLE",
             "is_disabled": 0, "is_fixed_role": 1},
            {"principal_id": 30, "name": "privlogin", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
        "server_role_members": [],
        "server_permissions": [],
        "databases": [], "database_principals": [], "database_role_members": [],
        "database_permissions": [], "database_principal_logins": [],
    }
    # privlogin effectively has securityadmin -> the patch blocks ChangePassword.
    high_priv = [{
        "object_identifier": _principal_oid("privlogin"), "principal_id": 30,
        "has_sysadmin": False, "has_securityadmin": True,
        "has_control_server": False, "has_impersonate_any_login": False,
    }]
    edges = list(derive_edges(FakeLookup(tables, high_priv)))
    assert _edges_of(edges, ek.CHANGE_PASSWORD) == []


def test_contains_and_owns_for_database():
    """Server Contains db; owner login Owns db with ownerPrincipalID injected."""
    tables = {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 1, "name": "sa", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
        "server_role_members": [],
        "server_permissions": [],
        "databases": [
            {"database_id": 5, "name": "appdb", "owner_name": "sa", "is_trustworthy_on": 0},
        ],
        "database_principals": [],
        "database_role_members": [],
        "database_permissions": [],
        "database_principal_logins": [],
    }
    edges = list(derive_edges(FakeLookup(tables)))
    db_oid = f"{_SERVER_OID}\\appdb"

    contains = [e for e in _edges_of(edges, ek.CONTAINS)
                if e.start.value == _SERVER_OID and e.end.value == db_oid]
    assert len(contains) == 1

    owns = _edges_of(edges, ek.OWNS)
    assert len(owns) == 1
    assert owns[0].start.value == _principal_oid("sa")
    assert owns[0].end.value == db_oid
    assert owns[0].properties.ownerPrincipalID == "1"


def test_is_mapped_to_login_to_db_user():
    """A login mapped to a db user -> MSSQL_IsMappedTo."""
    tables = {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 10, "name": "appsvc", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
        "server_role_members": [],
        "server_permissions": [],
        "databases": [
            {"database_id": 5, "name": "appdb", "owner_name": "sa", "is_trustworthy_on": 0},
        ],
        "database_principals": [
            {"principal_id": 7, "name": "appuser", "type_desc": "SQL_USER",
             "is_fixed_role": 0, "database": "appdb"},
        ],
        "database_role_members": [],
        "database_permissions": [],
        "database_principal_logins": [
            {"database": "appdb", "db_principal_id": 7, "server_principal_id": 10,
             "server_login_name": "appsvc"},
        ],
    }
    edges = list(derive_edges(FakeLookup(tables)))
    mapped = _edges_of(edges, ek.IS_MAPPED_TO)
    assert len(mapped) == 1
    assert mapped[0].start.value == _principal_oid("appsvc")
    assert mapped[0].end.value == f"appuser@{_SERVER_OID}\\appdb"


def test_db_control_on_user_yields_execute_as():
    """CONTROL on a db user (class DATABASE_PRINCIPAL) -> Control + ExecuteAs."""
    tables = {
        "servers": [_SERVER_ROW],
        "server_principals": [],
        "server_role_members": [],
        "server_permissions": [],
        "databases": [
            {"database_id": 5, "name": "appdb", "owner_name": "sa", "is_trustworthy_on": 0},
        ],
        "database_principals": [
            {"principal_id": 7, "name": "attacker", "type_desc": "SQL_USER",
             "is_fixed_role": 0, "database": "appdb"},
            {"principal_id": 8, "name": "victim", "type_desc": "SQL_USER",
             "is_fixed_role": 0, "database": "appdb"},
        ],
        "database_role_members": [],
        "database_permissions": [
            {"database": "appdb", "grantee_principal_id": 7, "permission_name": "CONTROL",
             "state_desc": "GRANT", "class_desc": "DATABASE_PRINCIPAL", "major_id": 8,
             "target_name": "victim"},
        ],
        "database_principal_logins": [],
    }
    edges = list(derive_edges(FakeLookup(tables)))
    control = _edges_of(edges, ek.CONTROL)
    execute_as = _edges_of(edges, ek.EXECUTE_AS)
    assert len(control) == 1
    assert len(execute_as) == 1
    attacker = f"attacker@{_SERVER_OID}\\appdb"
    victim = f"victim@{_SERVER_OID}\\appdb"
    assert control[0].start.value == attacker and control[0].end.value == victim
    assert execute_as[0].start.value == attacker and execute_as[0].end.value == victim
    # ExecuteAs is traversable; Control is not.
    assert execute_as[0].properties.traversable is True
    assert control[0].properties.traversable is False
    # ExecuteAs carries composition Cypher (db-user branch).
    assert execute_as[0].properties.composition


def test_trustworthy_db_with_high_priv_owner_yields_execute_as_owner():
    """A trustworthy db owned by a sysadmin login -> IsTrustedBy + ExecuteAsOwner."""
    tables = {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 1, "name": "sa", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
        "server_role_members": [],
        "server_permissions": [],
        "databases": [
            {"database_id": 5, "name": "trustdb", "owner_name": "sa", "is_trustworthy_on": 1},
        ],
        "database_principals": [],
        "database_role_members": [],
        "database_permissions": [],
        "database_principal_logins": [],
    }
    # sa has effective sysadmin.
    high_priv = [{
        "object_identifier": _principal_oid("sa"), "principal_id": 1,
        "has_sysadmin": True, "has_securityadmin": False,
        "has_control_server": False, "has_impersonate_any_login": False,
    }]
    edges = list(derive_edges(FakeLookup(tables, high_priv)))
    db_oid = f"{_SERVER_OID}\\trustdb"
    trusted = _edges_of(edges, ek.IS_TRUSTED_BY)
    exec_owner = _edges_of(edges, ek.EXECUTE_AS_OWNER)
    assert len(trusted) == 1
    assert trusted[0].start.value == db_oid and trusted[0].end.value == _SERVER_OID
    assert len(exec_owner) == 1
    assert exec_owner[0].start.value == db_oid and exec_owner[0].end.value == _SERVER_OID
    assert exec_owner[0].properties.composition  # ExecuteAsOwner composition present


def test_trustworthy_db_without_high_priv_owner_no_execute_as_owner():
    """A trustworthy db owned by a non-priv login -> IsTrustedBy only."""
    tables = {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 50, "name": "lowowner", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
        "server_role_members": [],
        "server_permissions": [],
        "databases": [
            {"database_id": 9, "name": "trustdb", "owner_name": "lowowner", "is_trustworthy_on": 1},
        ],
        "database_principals": [],
        "database_role_members": [],
        "database_permissions": [],
        "database_principal_logins": [],
    }
    edges = list(derive_edges(FakeLookup(tables)))  # no high-priv rows
    assert len(_edges_of(edges, ek.IS_TRUSTED_BY)) == 1
    assert _edges_of(edges, ek.EXECUTE_AS_OWNER) == []
