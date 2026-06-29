"""Unit tests for the preproc derived tables (`openhound_mssql.transforms`) and
the convert-time lookups (`openhound_mssql.lookup`).

A small in-memory DuckDB fixture stands in for the dlt-loaded raw tables. The
scenario exercises the load-bearing derivation logic ported from MSSQLHound:

  * SID hex -> S-1-5-... conversion (server_principal_map / domain detection),
  * nested server-role membership closure (custom role -> sysadmin),
  * effective high-privilege (sysadmin via nested role; CONTROL SERVER via a
    direct grant on a role) restricted to domain principals,
  * fixed-role implied permissions (sysadmin -> CONTROL SERVER),
  * database role closure + database fixed-role permissions (db_owner -> CONTROL),
  * linked_server_flags shape + the LinkedAsAdmin precondition.

Expected values come from the Go logic in
``MSSQLHound/internal/collector/collector.go``.
"""
from __future__ import annotations

import duckdb
import pytest

from openhound_mssql.lookup import MSSQLLookup
from openhound_mssql.transforms import transforms

SCHEMA = "mssql"

# Server keyed by lowercased hostname (no resolved SID in the raw servers row),
# default-instance port fallback => "<host>:1433".
SERVER_OID = "ps1-db:1433"

# A real domain SID (matches the spec examples). domainadmin is a member of a
# custom role that nests into sysadmin; the domain SID is this SID minus its RID.
DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"
DOMAINADMIN_SID = f"{DOMAIN_SID}-1104"
# sa is a SQL login (no AD SID).
SA_SID_HEX = "0x01"  # invalid/degenerate -> "" (sa has no real SID for our purposes)


def _hex_sid(sid_string: str) -> str:
    """Encode an ``S-1-5-21-...`` SID back into the ``0x...`` hex form the raw
    ``server_principals.sid`` column carries (so the transform's decoder runs)."""
    parts = sid_string.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    sub_auths = [int(p) for p in parts[3:]]
    raw = bytes([revision, len(sub_auths)])
    raw += authority.to_bytes(6, "big")
    for sub in sub_auths:
        raw += sub.to_bytes(4, "little")
    return "0x" + raw.hex().upper()


@pytest.fixture()
def con() -> duckdb.DuckDBPyConnection:
    """Build an in-memory DuckDB seeded with the raw tables, run transforms()."""
    con = duckdb.connect(":memory:")
    con.execute(f"CREATE SCHEMA {SCHEMA}")

    # --- servers (one row; server_oid derives to ps1-db:1433) ---------------
    # Columns are dlt's snake_case form of the collected camelCase keys, exactly
    # as the live preproc load produces them (machine_name, not MachineName).
    con.execute(f"""
        CREATE TABLE {SCHEMA}.servers AS SELECT * FROM (VALUES
            ('PS1-DB', 'PS1-DB')
        ) AS t("server_name", "machine_name")
    """)

    # --- server_principals --------------------------------------------------
    # principal_id, name, type_desc, is_fixed_role, sid(hex)
    con.execute(f"""
        CREATE TABLE {SCHEMA}.server_principals AS SELECT * FROM (VALUES
            (1,   'sa',                'SQL_LOGIN',    false, '0x01'),
            (2,   'public',            'SERVER_ROLE',  true,  '0x01'),
            (3,   'sysadmin',          'SERVER_ROLE',  true,  '0x01'),
            (10,  'CustomAdmins',      'SERVER_ROLE',  false, '0x01'),
            (20,  'MAYYHEM\\domainadmin', 'WINDOWS_LOGIN', false, '{_hex_sid(DOMAINADMIN_SID)}'),
            (30,  'CtrlRole',          'SERVER_ROLE',  false, '0x01'),
            (40,  'MAYYHEM\\ctrluser', 'WINDOWS_LOGIN', false, '{_hex_sid(DOMAIN_SID + "-1200")}')
        ) AS t("principal_id","name","type_desc","is_fixed_role","sid")
    """)

    # --- server_role_members ------------------------------------------------
    # member_principal_id, role_principal_id, role_name
    #   CustomAdmins(10) -> sysadmin(3)         (nested role)
    #   domainadmin(20)  -> CustomAdmins(10)    (=> effective sysadmin via nesting)
    #   ctrluser(40)     -> CtrlRole(30)        (CtrlRole has a direct CONTROL SERVER grant)
    con.execute(f"""
        CREATE TABLE {SCHEMA}.server_role_members AS SELECT * FROM (VALUES
            (10, 3,  'sysadmin'),
            (20, 10, 'CustomAdmins'),
            (40, 30, 'CtrlRole')
        ) AS t("member_principal_id","role_principal_id","role_name")
    """)

    # --- server_permissions -------------------------------------------------
    # grantee_principal_id, permission_name, state_desc
    #   CtrlRole(30) granted CONTROL SERVER  => ctrluser inherits CONTROL SERVER.
    con.execute(f"""
        CREATE TABLE {SCHEMA}.server_permissions AS SELECT * FROM (VALUES
            (30, 'CONTROL SERVER', 'GRANT')
        ) AS t("grantee_principal_id","permission_name","state_desc")
    """)

    # --- databases + database_principals + roles ----------------------------
    con.execute(f"""
        CREATE TABLE {SCHEMA}.databases AS SELECT * FROM (VALUES
            (5, 'appdb')
        ) AS t("database_id","name")
    """)
    # db principals: dbo(SQL_USER), db_owner(fixed role), appuser(SQL_USER)
    con.execute(f"""
        CREATE TABLE {SCHEMA}.database_principals AS SELECT * FROM (VALUES
            (1, 'dbo',      'SQL_USER',      false, 'appdb'),
            (2, 'db_owner', 'DATABASE_ROLE', true,  'appdb'),
            (5, 'appuser',  'SQL_USER',      false, 'appdb')
        ) AS t("principal_id","name","type_desc","is_fixed_role","database")
    """)
    # appuser(5) -> db_owner(2)
    con.execute(f"""
        CREATE TABLE {SCHEMA}.database_role_members AS SELECT * FROM (VALUES
            (5, 2, 'db_owner', 'appdb')
        ) AS t("member_principal_id","role_principal_id","role_name","database")
    """)
    con.execute(f"CREATE TABLE {SCHEMA}.database_permissions AS SELECT * FROM (VALUES "
                f"(NULL::BIGINT, NULL::VARCHAR, NULL::VARCHAR)) AS t(\"grantee_principal_id\",\"permission_name\",\"state_desc\") WHERE false")

    # --- linked_servers (level-0; remote flags absent, as Stage 3 collects) -
    # snake_case columns, matching dlt's normalization of the collected keys.
    con.execute(f"""
        CREATE TABLE {SCHEMA}.linked_servers AS SELECT * FROM (VALUES
            ('PS1-DB', 'CAS-DB', 'cas-db.mayyhem.com', 'All Logins', 'sa_remote', 0)
        ) AS t("source_server","linked_server","data_source","local_login","remote_login","level")
    """)

    transforms(con, SCHEMA)
    return con


def _rows(con, table):
    cur = con.execute(f"SELECT * FROM {SCHEMA}.{table}")
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


# ---------------------------------------------------------------------------
# server_principal_map
# ---------------------------------------------------------------------------
def test_server_principal_map_resolves_oid_and_sid(con):
    rows = {r["principal_id"]: r for r in _rows(con, "server_principal_map")}
    assert len(rows) == 7
    # OID is name@server_oid; SID decoded from hex; AD flag for the windows login.
    da = rows[20]
    assert da["object_identifier"] == f"MAYYHEM\\domainadmin@{SERVER_OID}"
    assert da["security_identifier"] == DOMAINADMIN_SID
    assert da["is_active_directory_principal"] is True
    # sa is a SQL login: no SID, not AD.
    assert rows[1]["security_identifier"] == ""
    assert rows[1]["is_active_directory_principal"] is False


# ---------------------------------------------------------------------------
# server_role_closure (nested)
# ---------------------------------------------------------------------------
def test_server_role_closure_includes_nested_and_public(con):
    closure = _rows(con, "server_role_closure")
    by_member = {}
    for r in closure:
        by_member.setdefault(r["member_oid"], set()).add(r["role_name"])
    da_oid = f"MAYYHEM\\domainadmin@{SERVER_OID}"
    # domainadmin -> CustomAdmins -> sysadmin (nested), plus implicit public.
    assert {"CustomAdmins", "sysadmin", "public"} <= by_member[da_oid]


# ---------------------------------------------------------------------------
# effective_high_priv
# ---------------------------------------------------------------------------
def test_effective_high_priv_domainadmin_sysadmin_via_nesting(con):
    rows = {r["object_identifier"]: r for r in _rows(con, "effective_high_priv")}
    da = rows[f"MAYYHEM\\domainadmin@{SERVER_OID}"]
    assert da["has_sysadmin"] is True
    assert da["is_domain"] is True


def test_effective_high_priv_control_server_via_role_grant(con):
    rows = {r["object_identifier"]: r for r in _rows(con, "effective_high_priv")}
    ctrl = rows[f"MAYYHEM\\ctrluser@{SERVER_OID}"]
    assert ctrl["has_control_server"] is True
    assert ctrl["has_sysadmin"] is False


def test_effective_high_priv_summary_lists_domain_principals(con):
    summary = _rows(con, "effective_high_priv_summary")
    assert len(summary) == 1
    s = summary[0]
    assert s["isAnyDomainPrincipalSysadmin"] is True
    da_oid = f"MAYYHEM\\domainadmin@{SERVER_OID}"
    ctrl_oid = f"MAYYHEM\\ctrluser@{SERVER_OID}"
    assert da_oid in list(s["domainPrincipalsWithSysadmin"])
    assert ctrl_oid in list(s["domainPrincipalsWithControlServer"])


# ---------------------------------------------------------------------------
# fixed-role implied permissions
# ---------------------------------------------------------------------------
def test_server_fixed_role_permissions_sysadmin_control_server(con):
    rows = _rows(con, "server_fixed_role_permissions")
    pairs = {(r["name"], r["permission"]) for r in rows}
    assert ("sysadmin", "CONTROL SERVER") in pairs


def test_database_fixed_role_permissions_db_owner_control(con):
    rows = _rows(con, "database_fixed_role_permissions")
    pairs = {(r["name"], r["permission"]) for r in rows}
    assert ("db_owner", "CONTROL") in pairs


# ---------------------------------------------------------------------------
# database_role_closure
# ---------------------------------------------------------------------------
def test_database_role_closure_scoped_per_db(con):
    rows = _rows(con, "database_role_closure")
    appuser_oid = f"appuser@{SERVER_OID}\\appdb"
    roles = {r["role_name"] for r in rows if r["member_oid"] == appuser_oid}
    # appuser -> db_owner (direct) + implicit public.
    assert {"db_owner", "public"} <= roles


# ---------------------------------------------------------------------------
# linked_server_flags
# ---------------------------------------------------------------------------
def test_linked_server_flags_shape_and_admin_precondition(con):
    rows = _rows(con, "linked_server_flags")
    assert len(rows) == 1
    r = rows[0]
    assert r["resolved_target"] == "cas-db.mayyhem.com"   # falls back to DataSource
    assert r["remote_login"] == "sa_remote"
    # Remote flags absent in Stage-3 collection -> not yet linked-as-admin.
    assert r["is_linked_as_admin"] is False


# ---------------------------------------------------------------------------
# MSSQLLookup over the derived tables
# ---------------------------------------------------------------------------
def test_lookup_server_principal_and_effective_high_priv(con):
    lookup = MSSQLLookup(con, schema=SCHEMA)
    da = lookup.server_principal(SERVER_OID, 20)
    assert da is not None
    assert da["name"] == "MAYYHEM\\domainadmin"

    summary = lookup.effective_high_priv(SERVER_OID)
    assert summary["isAnyDomainPrincipalSysadmin"] is True

    members = lookup.role_members(f"sysadmin@{SERVER_OID}")
    member_oids = {m["member_oid"] for m in members}
    # CustomAdmins (direct) and domainadmin (nested) are both members of sysadmin.
    assert f"MAYYHEM\\domainadmin@{SERVER_OID}" in member_oids
    assert f"CustomAdmins@{SERVER_OID}" in member_oids

    fixed = lookup.fixed_role_permissions(SERVER_OID)
    assert any(f["name"] == "sysadmin" and f["permission"] == "CONTROL SERVER" for f in fixed)

    db_fixed = lookup.fixed_role_permissions(SERVER_OID, "appdb")
    assert any(f["name"] == "db_owner" and f["permission"] == "CONTROL" for f in db_fixed)

    links = lookup.linked_server_flags(SERVER_OID)
    assert len(links) == 1


def test_lookup_missing_principal_returns_none(con):
    lookup = MSSQLLookup(con, schema=SCHEMA)
    assert lookup.server_principal(SERVER_OID, 9999) is None
    assert lookup.database_principal(SERVER_OID, "appdb", 9999) is None
