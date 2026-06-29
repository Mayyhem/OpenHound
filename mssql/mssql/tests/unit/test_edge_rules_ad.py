"""Unit tests for the Stage-7b edge derivation (``edges.derive_ad`` via
``edge_rules.build_graph_edges``).

These exercise the AD / linked-server / credential / service-account / coercion
edges end-to-end at the preproc layer: build a tiny in-memory DuckDB holding the
raw + derived tables ``derive_ad_edges`` reads, run
:func:`openhound_mssql.edge_rules.build_graph_edges`, and assert on the rows
written into ``mssql.graph_edges``. They complement ``test_edge_rules.py`` (the
Stage-6 server/database edges) and ``test_edges.py`` (the convert-time generator).

Each fixture covers a rule the prompt calls out: HostFor/ExecuteOnHost,
HasLogin (domain + local group), CoerceAndRelayToMSSQL, ServiceAccountFor +
HasSession + GetTGS + GetAdminTGS, LinkedTo + LinkedAsAdmin, and the three
credential edges (HasMappedCred / HasProxyCred / HasDBScopedCred).
"""
from __future__ import annotations

import duckdb
import pytest

from openhound_mssql.edge_rules import build_graph_edges
from openhound_mssql.kinds import edges as ek

# Server keyed by a resolved computer SID -> "<computerSID>:1433" (SID-based OID,
# matching Go and the transforms derivation).
_COMPUTER_SID = "S-1-5-21-111-222-333-1001"
_SERVER_OID = f"{_COMPUTER_SID}:1433"
_DOMAIN_SID = "S-1-5-21-111-222-333"  # the domain SID (principal SID minus RID)
_SERVER_ROW = {
    "machine_name": "PS1-DB",
    "server_name": "PS1-DB",
    "instance_name": "MSSQLSERVER",
    "computer_sid": _COMPUTER_SID,
    "fqdn": "ps1-db.mayyhem.com",
    "sql_server_name_display": "ps1-db.mayyhem.com:1433",
    "extended_protection": "Off",
    "port": 1433,
}

# The full set of tables derive_ad_edges (and the Stage-6 derive_edges it runs
# alongside) read. Empty unless a fixture fills them.
_TABLES: tuple[str, ...] = (
    "servers",
    "server_principals",
    "server_principal_map",
    "server_role_members",
    "server_permissions",
    "databases",
    "database_principals",
    "database_role_members",
    "database_permissions",
    "database_principal_logins",
    "effective_high_priv",
    "effective_high_priv_summary",
    "ad_resolved",
    "service_accounts",
    "linked_server_flags",
    "credentials",
    "server_principal_credentials",
    "proxy_accounts",
    "proxy_logins",
    "proxy_subsystems",
    "database_scoped_credentials",
)


def _login_oid(name: str) -> str:
    return f"{name}@{_SERVER_OID}"


def _principal_map_row(principal_id, name, type_desc, sid="", is_ad=False, is_fixed_role=0):
    """A server_principal_map row (the shape transforms._build_server_principal_map writes)."""
    return {
        "server_oid": _SERVER_OID,
        "principal_id": principal_id,
        "object_identifier": _login_oid(name),
        "name": name,
        "type_description": type_desc,
        "is_fixed_role": is_fixed_role,
        "security_identifier": sid,
        "is_active_directory_principal": 1 if is_ad else 0,
    }


def _load(con: duckdb.DuckDBPyConnection, tables: dict[str, list[dict]]) -> None:
    """Create mssql.<table> for every known table; fill from *tables*.

    Every value is stored as VARCHAR and coerced by the derivation's own helpers —
    DuckDB type fidelity is irrelevant to the edge logic under test. The
    collection_source list column on graph_edges is built by build_graph_edges, not
    here, so no special typing is needed.
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
            con.execute(f"CREATE OR REPLACE TABLE mssql.{table} (_empty VARCHAR)")
            continue
        coldefs = ", ".join(f'"{c}" VARCHAR' for c in cols)
        con.execute(f"CREATE OR REPLACE TABLE mssql.{table} ({coldefs})")
        for row in rows:
            values = [None if row.get(c) is None else str(row.get(c)) for c in cols]
            placeholders = ", ".join(["?"] * len(cols))
            con.execute(f"INSERT INTO mssql.{table} VALUES ({placeholders})", values)


def _edges(con: duckdb.DuckDBPyConnection) -> list[dict]:
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


# ---------------------------------------------------------------------------
# Host edges
# ---------------------------------------------------------------------------
def test_host_for_and_execute_on_host(con):
    """A resolved computer SID -> HostFor (Computer->Server) + ExecuteOnHost (Server->Computer)."""
    _load(con, {"servers": [_SERVER_ROW]})
    build_graph_edges(con, "mssql")
    rows = _edges(con)
    host_for = _of_kind(rows, ek.HOST_FOR)
    execute_on_host = _of_kind(rows, ek.EXECUTE_ON_HOST)
    assert len(host_for) == 1
    assert host_for[0]["start_id"] == _COMPUTER_SID
    assert host_for[0]["end_id"] == _SERVER_OID
    assert host_for[0]["traversable"] is True
    assert len(execute_on_host) == 1
    assert execute_on_host[0]["start_id"] == _SERVER_OID
    assert execute_on_host[0]["end_id"] == _COMPUTER_SID
    # ExecuteOnHost has a composition Cypher (Go edgeCompositionGenerators).
    assert execute_on_host[0]["composition"]


def test_no_computer_sid_no_host_edges(con):
    """Without a computer SID there is no Computer node -> no Host/ExecuteOnHost."""
    row = dict(_SERVER_ROW)
    row.pop("computer_sid")
    _load(con, {"servers": [row]})
    build_graph_edges(con, "mssql")
    rows = _edges(con)
    assert _of_kind(rows, ek.HOST_FOR) == []
    assert _of_kind(rows, ek.EXECUTE_ON_HOST) == []


# ---------------------------------------------------------------------------
# HasLogin
# ---------------------------------------------------------------------------
def test_has_login_for_enabled_domain_login_with_connect(con):
    """An enabled AD login with CONNECT SQL -> HasLogin from its SID to the login."""
    sid = f"{_DOMAIN_SID}-1105"
    _load(con, {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 10, "name": "MAYYHEM\\dba", "type_desc": "WINDOWS_LOGIN",
             "is_disabled": 0, "sid": sid},
        ],
        "server_principal_map": [
            _principal_map_row(10, "MAYYHEM\\dba", "WINDOWS_LOGIN", sid=sid, is_ad=True),
        ],
        "server_permissions": [
            {"grantee_principal_id": 10, "permission_name": "CONNECT SQL",
             "state_desc": "GRANT", "class_desc": "SERVER", "major_id": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    has_login = _of_kind(_edges(con), ek.HAS_LOGIN)
    assert len(has_login) == 1
    assert has_login[0]["start_id"] == sid
    assert has_login[0]["end_id"] == _login_oid("MAYYHEM\\dba")
    assert has_login[0]["traversable"] is True
    assert has_login[0]["general"]


def test_no_has_login_for_disabled_login(con):
    """A disabled AD login yields no HasLogin (Go skips disabled)."""
    sid = f"{_DOMAIN_SID}-1106"
    _load(con, {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 11, "name": "MAYYHEM\\stale", "type_desc": "WINDOWS_LOGIN",
             "is_disabled": 1, "sid": sid},
        ],
        "server_principal_map": [
            _principal_map_row(11, "MAYYHEM\\stale", "WINDOWS_LOGIN", sid=sid, is_ad=True),
        ],
        "server_permissions": [
            {"grantee_principal_id": 11, "permission_name": "CONNECT SQL",
             "state_desc": "GRANT", "class_desc": "SERVER", "major_id": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    assert _of_kind(_edges(con), ek.HAS_LOGIN) == []


def test_has_login_for_local_builtin_group(con):
    """A BUILTIN local group with CONNECT SQL -> HasLogin from <host>-<SID>."""
    sid = "S-1-5-32-544"  # BUILTIN\Administrators
    _load(con, {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 12, "name": "BUILTIN\\Administrators", "type_desc": "WINDOWS_GROUP",
             "is_disabled": 0, "sid": sid},
        ],
        "server_principal_map": [
            _principal_map_row(12, "BUILTIN\\Administrators", "WINDOWS_GROUP", sid=sid, is_ad=False),
        ],
        "server_permissions": [
            {"grantee_principal_id": 12, "permission_name": "CONNECT SQL",
             "state_desc": "GRANT", "class_desc": "SERVER", "major_id": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    has_login = _of_kind(_edges(con), ek.HAS_LOGIN)
    assert len(has_login) == 1
    assert has_login[0]["start_id"] == f"{_SERVER_ROW['fqdn']}-{sid}"
    assert has_login[0]["end_id"] == _login_oid("BUILTIN\\Administrators")


# ---------------------------------------------------------------------------
# CoerceAndRelayToMSSQL
# ---------------------------------------------------------------------------
def test_coerce_and_relay_for_computer_login_epa_off(con):
    """EPA Off + an enabled computer-account login -> CoerceAndRelay from Authenticated Users."""
    sid = f"{_DOMAIN_SID}-1107"
    _load(con, {
        "servers": [_SERVER_ROW],  # extended_protection = Off
        "server_principals": [
            {"principal_id": 13, "name": "MAYYHEM\\WS01$", "type_desc": "WINDOWS_LOGIN",
             "is_disabled": 0, "sid": sid},
        ],
        "server_principal_map": [
            _principal_map_row(13, "MAYYHEM\\WS01$", "WINDOWS_LOGIN", sid=sid, is_ad=True),
        ],
        "server_permissions": [
            {"grantee_principal_id": 13, "permission_name": "CONNECT SQL",
             "state_desc": "GRANT", "class_desc": "SERVER", "major_id": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    rows = _edges(con)
    coerce = _of_kind(rows, ek.COERCE_AND_RELAY_TO_MSSQL)
    assert len(coerce) == 1
    # Start = Authenticated Users (domain-prefixed S-1-5-11), end = the login.
    assert coerce[0]["start_id"] == "mayyhem.com-S-1-5-11"
    assert coerce[0]["end_id"] == _login_oid("MAYYHEM\\WS01$")
    assert coerce[0]["traversable"] is True
    assert coerce[0]["composition"]  # CoerceAndRelay has composition Cypher
    # The computer account is also a domain SID -> it still gets a HasLogin.
    assert len(_of_kind(rows, ek.HAS_LOGIN)) == 1


def test_no_coerce_when_epa_required(con):
    """EPA Required suppresses CoerceAndRelay even for a computer login."""
    row = dict(_SERVER_ROW)
    row["extended_protection"] = "Required"
    sid = f"{_DOMAIN_SID}-1108"
    _load(con, {
        "servers": [row],
        "server_principals": [
            {"principal_id": 14, "name": "MAYYHEM\\WS02$", "type_desc": "WINDOWS_LOGIN",
             "is_disabled": 0, "sid": sid},
        ],
        "server_principal_map": [
            _principal_map_row(14, "MAYYHEM\\WS02$", "WINDOWS_LOGIN", sid=sid, is_ad=True),
        ],
        "server_permissions": [
            {"grantee_principal_id": 14, "permission_name": "CONNECT SQL",
             "state_desc": "GRANT", "class_desc": "SERVER", "major_id": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    assert _of_kind(_edges(con), ek.COERCE_AND_RELAY_TO_MSSQL) == []


# ---------------------------------------------------------------------------
# Service account edges
# ---------------------------------------------------------------------------
def test_service_account_edges_domain_account(con):
    """A domain service account -> ServiceAccountFor + HasSession + GetTGS (no admin -> no GetAdminTGS)."""
    sa_sid = f"{_DOMAIN_SID}-2001"
    login_sid = f"{_DOMAIN_SID}-1105"
    _load(con, {
        "servers": [_SERVER_ROW],
        "service_accounts": [
            {"service_account": "MAYYHEM\\sqlsvc", "servicename": "SQL Server", "ServiceType": "SQLServer"},
        ],
        # ad_resolved maps the service account name -> its domain SID.
        "ad_resolved": [
            {"sid": sa_sid, "name": "MAYYHEM\\sqlsvc", "samAccountName": "sqlsvc",
             "type": "user", "enabled": 1},
        ],
        # An enabled domain login with CONNECT SQL -> a GetTGS target.
        "server_principals": [
            {"principal_id": 20, "name": "MAYYHEM\\analyst", "type_desc": "WINDOWS_LOGIN",
             "is_disabled": 0, "sid": login_sid},
        ],
        "server_principal_map": [
            _principal_map_row(20, "MAYYHEM\\analyst", "WINDOWS_LOGIN", sid=login_sid, is_ad=True),
        ],
        "server_permissions": [
            {"grantee_principal_id": 20, "permission_name": "CONNECT SQL",
             "state_desc": "GRANT", "class_desc": "SERVER", "major_id": 0},
        ],
        # No domain principal is sysadmin -> no GetAdminTGS.
        "effective_high_priv_summary": [
            {"server_oid": _SERVER_OID, "isAnyDomainPrincipalSysadmin": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    rows = _edges(con)
    saf = _of_kind(rows, ek.SERVICE_ACCOUNT_FOR)
    has_session = _of_kind(rows, ek.HAS_SESSION)
    get_tgs = _of_kind(rows, ek.GET_TGS)
    assert len(saf) == 1
    assert saf[0]["start_id"] == sa_sid and saf[0]["end_id"] == _SERVER_OID
    # ServiceAccointFor is a "possible" edge -> traversable by default.
    assert saf[0]["traversable"] is True
    # HasSession: computer -> the (non-computer) service account.
    assert len(has_session) == 1
    assert has_session[0]["start_id"] == _COMPUTER_SID and has_session[0]["end_id"] == sa_sid
    # GetTGS: service account -> the enabled domain login.
    assert len(get_tgs) == 1
    assert get_tgs[0]["start_id"] == sa_sid and get_tgs[0]["end_id"] == _login_oid("MAYYHEM\\analyst")
    # No admin -> no GetAdminTGS.
    assert _of_kind(rows, ek.GET_ADMIN_TGS) == []


def test_get_admin_tgs_when_a_domain_principal_is_sysadmin(con):
    """isAnyDomainPrincipalSysadmin -> GetAdminTGS from the service account to the server."""
    sa_sid = f"{_DOMAIN_SID}-2002"
    _load(con, {
        "servers": [_SERVER_ROW],
        "service_accounts": [
            {"service_account": "MAYYHEM\\sqlsvc2", "servicename": "SQL Server", "ServiceType": "SQLServer"},
        ],
        "ad_resolved": [
            {"sid": sa_sid, "name": "MAYYHEM\\sqlsvc2", "samAccountName": "sqlsvc2",
             "type": "user", "enabled": 1},
        ],
        "effective_high_priv_summary": [
            {"server_oid": _SERVER_OID, "isAnyDomainPrincipalSysadmin": 1},
        ],
    })
    build_graph_edges(con, "mssql")
    admin_tgs = _of_kind(_edges(con), ek.GET_ADMIN_TGS)
    assert len(admin_tgs) == 1
    assert admin_tgs[0]["start_id"] == sa_sid and admin_tgs[0]["end_id"] == _SERVER_OID
    assert admin_tgs[0]["composition"]  # GetAdminTGS has composition Cypher


# ---------------------------------------------------------------------------
# Linked servers
# ---------------------------------------------------------------------------
def test_linked_to_and_linked_as_admin(con):
    """A linked-server-flags row -> LinkedTo (possible); admin precondition -> LinkedAsAdmin."""
    _load(con, {
        "servers": [_SERVER_ROW],
        "linked_server_flags": [
            # An admin link: SQL remote login + remote sysadmin + mixed-mode -> is_linked_as_admin true.
            {"server_oid": _SERVER_OID, "source_server": "PS1-DB", "linked_server": "CAS-DB",
             "data_source": "cas-db.mayyhem.com", "resolved_target": "cas-db.mayyhem.com",
             "local_login": "sa", "remote_login": "sa", "remote_current_login": "sa",
             "remote_is_sysadmin": 1, "remote_is_securityadmin": 0,
             "remote_has_control_server": 0, "remote_has_impersonate_any_login": 0,
             "remote_is_mixed_mode": 1, "is_linked_as_admin": 1,
             "uses_impersonation": 1, "data_access": 1, "rpc_out": 1, "level": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    rows = _edges(con)
    linked_to = _of_kind(rows, ek.LINKED_TO)
    linked_admin = _of_kind(rows, ek.LINKED_AS_ADMIN)
    assert len(linked_to) == 1
    assert linked_to[0]["start_id"] == _SERVER_OID
    assert linked_to[0]["end_id"] == "cas-db.mayyhem.com"
    # LinkedTo is a "possible" edge -> traversable by default (flips off under --disable-possible).
    assert linked_to[0]["traversable"] is True
    # The full Go property bag is carried (per-link uniqueness + entity panel).
    assert linked_to[0]["local_login"] == "sa"
    assert linked_to[0]["remote_login"] == "sa"
    assert linked_to[0]["remote_is_sysadmin"] is True
    # LinkedAsAdmin emitted because the precondition held.
    assert len(linked_admin) == 1
    assert linked_admin[0]["start_id"] == _SERVER_OID and linked_admin[0]["end_id"] == "cas-db.mayyhem.com"
    assert linked_admin[0]["traversable"] is True


def test_linked_to_without_admin_precondition(con):
    """A non-admin link -> LinkedTo only, no LinkedAsAdmin."""
    _load(con, {
        "servers": [_SERVER_ROW],
        "linked_server_flags": [
            {"server_oid": _SERVER_OID, "source_server": "PS1-DB", "linked_server": "REP-DB",
             "data_source": "rep-db.mayyhem.com", "resolved_target": "rep-db.mayyhem.com",
             "local_login": "All Logins", "remote_login": "", "remote_is_sysadmin": 0,
             "remote_is_securityadmin": 0, "remote_has_control_server": 0,
             "remote_has_impersonate_any_login": 0, "remote_is_mixed_mode": 0,
             "is_linked_as_admin": 0, "level": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    rows = _edges(con)
    assert len(_of_kind(rows, ek.LINKED_TO)) == 1
    assert _of_kind(rows, ek.LINKED_AS_ADMIN) == []


def test_distinct_local_logins_keep_separate_linked_to_edges(con):
    """Two login mappings to the same target -> two distinct LinkedTo rows (no collapse)."""
    base = {
        "server_oid": _SERVER_OID, "source_server": "PS1-DB", "linked_server": "CAS-DB",
        "data_source": "cas-db.mayyhem.com", "resolved_target": "cas-db.mayyhem.com",
        "remote_login": "", "remote_is_sysadmin": 0, "remote_is_securityadmin": 0,
        "remote_has_control_server": 0, "remote_has_impersonate_any_login": 0,
        "remote_is_mixed_mode": 0, "is_linked_as_admin": 0, "level": 0,
    }
    _load(con, {
        "servers": [_SERVER_ROW],
        "linked_server_flags": [
            {**base, "local_login": "sa"},
            {**base, "local_login": "appuser"},
        ],
    })
    build_graph_edges(con, "mssql")
    linked_to = _of_kind(_edges(con), ek.LINKED_TO)
    assert len(linked_to) == 2
    assert {r["local_login"] for r in linked_to} == {"sa", "appuser"}


# ---------------------------------------------------------------------------
# Credential edges
# ---------------------------------------------------------------------------
def test_has_mapped_cred(con):
    """A login with a mapped domain credential -> HasMappedCred to the resolved SID + credentialId."""
    cred_sid = f"{_DOMAIN_SID}-3001"
    _load(con, {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 30, "name": "appsvc", "type_desc": "SQL_LOGIN", "is_disabled": 0},
        ],
        "server_principal_map": [
            _principal_map_row(30, "appsvc", "SQL_LOGIN"),
        ],
        "credentials": [
            {"credential_id": 5, "name": "AppCred", "credential_identity": "MAYYHEM\\extacct"},
        ],
        "server_principal_credentials": [
            {"principal_id": 30, "credential_id": 5, "credential_name": "AppCred",
             "credential_identity": "MAYYHEM\\extacct"},
        ],
        "ad_resolved": [
            {"sid": cred_sid, "name": "MAYYHEM\\extacct", "samAccountName": "extacct",
             "type": "user", "enabled": 1},
        ],
    })
    build_graph_edges(con, "mssql")
    mapped = _of_kind(_edges(con), ek.HAS_MAPPED_CRED)
    assert len(mapped) == 1
    assert mapped[0]["start_id"] == _login_oid("appsvc")
    assert mapped[0]["end_id"] == cred_sid
    assert mapped[0]["credential_id"] == "5"  # string, matching Go fmt.Sprintf("%d")
    # HasMappedCred is a "possible" edge -> traversable by default.
    assert mapped[0]["traversable"] is True


def test_has_proxy_cred(con):
    """A login authorized for a proxy with a domain credential -> HasProxyCred + credentialId/proxyId."""
    proxy_sid = f"{_DOMAIN_SID}-3002"
    _load(con, {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 31, "name": "jobrunner", "type_desc": "SQL_LOGIN", "is_disabled": 0},
        ],
        "server_principal_map": [
            _principal_map_row(31, "jobrunner", "SQL_LOGIN"),
        ],
        "proxy_accounts": [
            {"proxy_id": 7, "proxy_name": "ETL_Proxy", "credential_id": 9,
             "credential_name": "ProxyCred", "credential_identity": "MAYYHEM\\proxyacct", "enabled": 1},
        ],
        "proxy_logins": [
            {"proxy_id": 7, "login_name": "jobrunner"},
        ],
        "proxy_subsystems": [
            {"proxy_id": 7, "subsystem": "CmdExec"},
        ],
        "ad_resolved": [
            {"sid": proxy_sid, "name": "MAYYHEM\\proxyacct", "samAccountName": "proxyacct",
             "type": "user", "enabled": 1},
        ],
    })
    build_graph_edges(con, "mssql")
    proxy = _of_kind(_edges(con), ek.HAS_PROXY_CRED)
    assert len(proxy) == 1
    assert proxy[0]["start_id"] == _login_oid("jobrunner")
    assert proxy[0]["end_id"] == proxy_sid
    assert proxy[0]["credential_id"] == "9"
    assert proxy[0]["proxy_id"] == "7"
    assert proxy[0]["general"] and "ETL_Proxy" in proxy[0]["general"]


def test_has_db_scoped_cred(con):
    """A database-scoped domain credential -> HasDBScopedCred from the database to the SID."""
    cred_sid = f"{_DOMAIN_SID}-3003"
    _load(con, {
        "servers": [_SERVER_ROW],
        "database_scoped_credentials": [
            {"credential_id": 3, "name": "DbCred", "credential_identity": "MAYYHEM\\dbextacct",
             "database": "appdb"},
        ],
        "ad_resolved": [
            {"sid": cred_sid, "name": "MAYYHEM\\dbextacct", "samAccountName": "dbextacct",
             "type": "user", "enabled": 1},
        ],
    })
    build_graph_edges(con, "mssql")
    dbcred = _of_kind(_edges(con), ek.HAS_DB_SCOPED_CRED)
    assert len(dbcred) == 1
    assert dbcred[0]["start_id"] == f"{_SERVER_OID}\\appdb"
    assert dbcred[0]["end_id"] == cred_sid
    assert dbcred[0]["credential_id"] == "3"


def test_no_cred_edge_for_unresolved_identity(con):
    """A credential identity that doesn't resolve to a domain SID -> no HasMappedCred (Go gate)."""
    _load(con, {
        "servers": [_SERVER_ROW],
        "server_principals": [
            {"principal_id": 32, "name": "appsvc2", "type_desc": "SQL_LOGIN", "is_disabled": 0},
        ],
        "server_principal_map": [
            _principal_map_row(32, "appsvc2", "SQL_LOGIN"),
        ],
        "credentials": [
            {"credential_id": 6, "name": "LocalCred", "credential_identity": "localmachine\\svc"},
        ],
        "server_principal_credentials": [
            {"principal_id": 32, "credential_id": 6, "credential_identity": "localmachine\\svc"},
        ],
        # ad_resolved has no matching entry -> no resolved SID -> no edge.
    })
    build_graph_edges(con, "mssql")
    assert _of_kind(_edges(con), ek.HAS_MAPPED_CRED) == []


# ---------------------------------------------------------------------------
# Toggle interaction
# ---------------------------------------------------------------------------
def test_disable_possible_flips_linked_to_nontraversable(con, monkeypatch):
    """--disable-possible-edges flips LinkedTo (a possible kind) to non-traversable."""
    monkeypatch.setenv("SOURCES__MSSQL__DISABLE_POSSIBLE_EDGES", "true")
    _load(con, {
        "servers": [_SERVER_ROW],
        "linked_server_flags": [
            {"server_oid": _SERVER_OID, "source_server": "PS1-DB", "linked_server": "CAS-DB",
             "data_source": "cas-db.mayyhem.com", "resolved_target": "cas-db.mayyhem.com",
             "local_login": "sa", "remote_login": "", "remote_is_sysadmin": 0,
             "remote_is_securityadmin": 0, "remote_has_control_server": 0,
             "remote_has_impersonate_any_login": 0, "remote_is_mixed_mode": 0,
             "is_linked_as_admin": 0, "level": 0},
        ],
    })
    build_graph_edges(con, "mssql")
    linked_to = _of_kind(_edges(con), ek.LINKED_TO)
    assert len(linked_to) == 1
    assert linked_to[0]["traversable"] is False  # possible kind, demoted
