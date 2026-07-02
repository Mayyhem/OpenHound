"""Unit tests for the preproc edge derivation (``edge_rules.build_graph_edges``).

These exercise the Stage-6 port end-to-end at the preproc layer: build a tiny
in-memory DuckDB holding the raw tables (``servers`` / ``server_principals`` /
``server_role_members`` / ``server_permissions`` / ``databases`` /
``database_principals`` / ``database_role_members`` / ``database_permissions`` /
``database_principal_logins``) plus the derived ``effective_high_priv`` table,
run :func:`openhound_mssql.edge_rules.build_graph_edges`, and assert on the rows
written into ``mssql.graph_edges``.

This complements ``test_edges.py`` (which tests the convert-time
``derive_edges`` generator directly): here we verify the DuckDB-backed adapter,
the table shape, and the traversable-gating that ``build_graph_edges`` adds.

Each fixture covers a derivation rule the prompt calls out:
CONTROL SERVER -> ControlServer; ALTER-on-role -> AddMember; nested MemberOf;
sysadmin / db_owner / securityadmin fixed-role edges; and a negative (no
permission, no edge).
"""
from __future__ import annotations

import duckdb
import pytest

from openhound_mssql.edge_rules import build_graph_edges
from openhound_mssql.kinds import edges as ek

# Single server keyed by machine name (no computer SID) -> "<lowerhost>:1433".
_SERVER_OID = "ps1-db:1433"
_SERVER_ROW = {
    "machine_name": "PS1-DB",
    "server_name": "PS1-DB",
    "instance_name": "MSSQLSERVER",
    "fqdn": "ps1-db.mayyhem.com",
    "sql_server_name_display": "ps1-db.mayyhem.com:1433",
    "product_version": "16.0.4210.1",  # SQL 2022, patched for CVE-2025-49758
    "full_version": "Microsoft SQL Server 2022 - 16.0.4210.1",
}

# The raw + derived tables build_graph_edges reads. Empty unless a fixture fills
# them, so every test starts from a known-empty base.
_TABLES: tuple[str, ...] = (
    "servers",
    "server_principals",
    "server_role_members",
    "server_permissions",
    "databases",
    "database_principals",
    "database_role_members",
    "database_permissions",
    "database_principal_logins",
    "effective_high_priv",
)


def _principal_oid(name: str) -> str:
    return f"{name}@{_SERVER_OID}"


def _load(con: duckdb.DuckDBPyConnection, tables: dict[str, list[dict]]) -> None:
    """Create mssql.<table> for every known table; fill from *tables*.

    Tables are built from the union of keys across that table's fixture rows, so a
    sparsely-populated fixture still produces a well-typed table. Every value is
    stored as VARCHAR and coerced by the derivation's own ``_int`` / ``_bool``
    helpers — DuckDB type fidelity is irrelevant to the edge logic under test.
    """
    con.execute("CREATE SCHEMA IF NOT EXISTS mssql")
    for table in _TABLES:
        rows = tables.get(table, [])
        cols: list[str] = []
        for row in rows:
            for key in row:
                if key not in cols:
                    cols.append(key)
        if not cols:
            # An empty table still needs at least one column to exist; a single
            # dummy column the derivation never reads is harmless.
            con.execute(f"CREATE OR REPLACE TABLE mssql.{table} (_empty VARCHAR)")
            continue
        coldefs = ", ".join(f'"{c}" VARCHAR' for c in cols)
        con.execute(f"CREATE OR REPLACE TABLE mssql.{table} ({coldefs})")
        for row in rows:
            values = [None if row.get(c) is None else str(row.get(c)) for c in cols]
            placeholders = ", ".join(["?"] * len(cols))
            con.execute(f"INSERT INTO mssql.{table} VALUES ({placeholders})", values)


def _edges(con: duckdb.DuckDBPyConnection) -> list[dict]:
    """Read mssql.graph_edges back as a list of column-named dicts."""
    cur = con.execute("SELECT * FROM mssql.graph_edges")
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def _of_kind(rows: list[dict], kind: str) -> list[dict]:
    return [r for r in rows if r["kind"] == kind]


@pytest.fixture
def con():
    c = duckdb.connect(":memory:")
    yield c
    c.close()


def test_graph_edges_table_always_created_even_with_no_data(con):
    """build_graph_edges creates an empty-but-shaped table when there is no server."""
    _load(con, {})  # no servers row
    build_graph_edges(con, "mssql")
    rows = _edges(con)
    assert rows == []
    # The shared-contract + property-bag columns must exist.
    cols = {c[0] for c in con.execute("SELECT * FROM mssql.graph_edges").description}
    for expected in ("start_id", "end_id", "kind", "traversable", "collection_source",
                     "general", "composition", "with_grant", "owner_principal_id"):
        assert expected in cols


def test_control_server_permission_yields_control_server_edge(con):
    """CONTROL SERVER grant -> a traversable MSSQL_ControlServer edge to the server."""
    _load(con, {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 10, "name": "attacker", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
        "server_permissions": [
            {"grantee_principal_id": 10, "permission_name": "CONTROL SERVER",
             "state_desc": "GRANT", "class_desc": "SERVER", "major_id": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    cs = _of_kind(_edges(con), ek.CONTROL_SERVER)
    assert len(cs) == 1
    assert cs[0]["start_id"] == _principal_oid("attacker")
    assert cs[0]["end_id"] == _SERVER_OID
    assert cs[0]["traversable"] is True
    assert cs[0]["general"]  # documentation bag populated
    assert cs[0]["collection_source"] == ["MSSQL-createEdges"]


def test_alter_on_user_defined_role_yields_add_member(con):
    """ALTER on a user-defined server role -> MSSQL_Alter (non-trav) + MSSQL_AddMember."""
    _load(con, {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 10, "name": "attacker", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
            {"principal_id": 20, "name": "customrole", "type_desc": "SERVER_ROLE",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
        # ALTER on the role principal (class SERVER_PRINCIPAL, major_id = role id).
        "server_permissions": [
            {"grantee_principal_id": 10, "permission_name": "ALTER",
             "state_desc": "GRANT", "class_desc": "SERVER_PRINCIPAL", "major_id": 20},
        ],
    })
    build_graph_edges(con, "mssql")
    rows = _edges(con)
    alter = _of_kind(rows, ek.ALTER)
    add_member = _of_kind(rows, ek.ADD_MEMBER)
    assert len(alter) == 1
    assert len(add_member) == 1
    role_oid = _principal_oid("customrole")
    assert alter[0]["end_id"] == role_oid
    assert add_member[0]["start_id"] == _principal_oid("attacker")
    assert add_member[0]["end_id"] == role_oid
    # Alter is non-traversable; AddMember is traversable (Go IsTraversableEdge).
    assert alter[0]["traversable"] is False
    assert add_member[0]["traversable"] is True


def test_nested_membership_yields_member_of(con):
    """A login that is a direct member of a server role -> MSSQL_MemberOf (no public)."""
    _load(con, {
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
    })
    build_graph_edges(con, "mssql")
    member_of = _of_kind(_edges(con), ek.MEMBER_OF)
    # Exactly one MemberOf: alice -> customrole. No implicit public edge.
    assert len(member_of) == 1
    assert member_of[0]["start_id"] == _principal_oid("alice")
    assert member_of[0]["end_id"] == _principal_oid("customrole")
    assert member_of[0]["traversable"] is True


def test_sysadmin_fixed_role_yields_control_server(con):
    """The sysadmin fixed server role -> MSSQL_ControlServer (createFixedRoleEdges)."""
    _load(con, {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 3, "name": "sysadmin", "type_desc": "SERVER_ROLE",
             "is_disabled": 0, "is_fixed_role": 1},
        ],
    })
    build_graph_edges(con, "mssql")
    cs = _of_kind(_edges(con), ek.CONTROL_SERVER)
    assert len(cs) == 1
    assert cs[0]["start_id"] == _principal_oid("sysadmin")
    assert cs[0]["end_id"] == _SERVER_OID


def test_db_owner_fixed_role_yields_control_and_control_db(con):
    """db_owner fixed db role -> MSSQL_Control (non-trav) + MSSQL_ControlDB (trav)."""
    _load(con, {
        "servers": [_SERVER_ROW],
        "databases": [
            {"database_id": 5, "name": "appdb", "owner_name": "sa", "is_trustworthy_on": 0},
        ],
        "database_principals": [
            {"principal_id": 16384, "name": "db_owner", "type_desc": "DATABASE_ROLE",
             "is_fixed_role": 1, "database": "appdb"},
        ],
    })
    build_graph_edges(con, "mssql")
    rows = _edges(con)
    db_oid = f"{_SERVER_OID}\\appdb"
    role_oid = f"db_owner@{_SERVER_OID}\\appdb"
    control = _of_kind(rows, ek.CONTROL)
    control_db = _of_kind(rows, ek.CONTROL_DB)
    assert len(control) == 1 and len(control_db) == 1
    assert control[0]["start_id"] == role_oid and control[0]["end_id"] == db_oid
    assert control_db[0]["start_id"] == role_oid and control_db[0]["end_id"] == db_oid
    assert control[0]["traversable"] is False
    assert control_db[0]["traversable"] is True


def test_securityadmin_yields_grant_any_permission_and_alter_any_login(con):
    """securityadmin fixed role -> GrantAnyPermission + AlterAnyLogin (+ ChangePassword)."""
    _load(con, {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 5, "name": "securityadmin", "type_desc": "SERVER_ROLE",
             "is_disabled": 0, "is_fixed_role": 1},
            {"principal_id": 30, "name": "weaklogin", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    rows = _edges(con)
    assert len(_of_kind(rows, ek.GRANT_ANY_PERMISSION)) == 1
    assert len(_of_kind(rows, ek.ALTER_ANY_LOGIN)) == 1
    # weaklogin has no sysadmin/CONTROL SERVER and (no effective_high_priv row ->)
    # no securityadmin/IMPERSONATE ANY LOGIN -> ChangePassword edge IS created.
    cp = _of_kind(rows, ek.CHANGE_PASSWORD)
    assert len(cp) == 1
    assert cp[0]["start_id"] == _principal_oid("securityadmin")
    assert cp[0]["end_id"] == _principal_oid("weaklogin")


def test_change_password_suppressed_for_high_priv_target_when_patched(con):
    """Patched server: ChangePassword to a securityadmin target is suppressed (CVE gate)."""
    _load(con, {
        "servers": [_SERVER_ROW],  # 16.0.4210.1 is patched for CVE-2025-49758
        "server_principals": [
            {"principal_id": 5, "name": "securityadmin", "type_desc": "SERVER_ROLE",
             "is_disabled": 0, "is_fixed_role": 1},
            {"principal_id": 30, "name": "privlogin", "type_desc": "SQL_LOGIN",
             "is_disabled": 0, "is_fixed_role": 0},
        ],
        # privlogin effectively has securityadmin -> the patch blocks ChangePassword.
        "effective_high_priv": [
            {"server_oid": _SERVER_OID, "object_identifier": _principal_oid("privlogin"),
             "principal_id": 30, "has_sysadmin": 0, "has_securityadmin": 1,
             "has_control_server": 0, "has_impersonate_any_login": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    assert _of_kind(_edges(con), ek.CHANGE_PASSWORD) == []


def test_negative_no_permission_no_edges(con):
    """A lone disabled login with no permissions yields only its Contains edge."""
    _load(con, {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 10, "name": "nobody", "type_desc": "SQL_LOGIN",
             "is_disabled": 1, "is_fixed_role": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    rows = _edges(con)
    # Contains (server -> login) is structural and always present; no privilege edges.
    kinds = {r["kind"] for r in rows}
    assert kinds == {ek.CONTAINS}
    assert not any(r["kind"] in (ek.CONTROL_SERVER, ek.CONNECT, ek.MEMBER_OF) for r in rows)


def test_disable_nontraversable_drops_control_keeps_control_db(con, monkeypatch):
    """--disable-nontraversable-edges drops Control but keeps the traversable ControlDB."""
    monkeypatch.setenv("SOURCES__MSSQL__DISABLE_NONTRAVERSABLE_EDGES", "true")
    _load(con, {
        "servers": [_SERVER_ROW],
        "databases": [
            {"database_id": 5, "name": "appdb", "owner_name": "sa", "is_trustworthy_on": 0},
        ],
        "database_principals": [
            {"principal_id": 16384, "name": "db_owner", "type_desc": "DATABASE_ROLE",
             "is_fixed_role": 1, "database": "appdb"},
        ],
    })
    build_graph_edges(con, "mssql")
    rows = _edges(con)
    assert _of_kind(rows, ek.CONTROL) == []          # non-traversable -> dropped
    assert len(_of_kind(rows, ek.CONTROL_DB)) == 1   # traversable -> kept
