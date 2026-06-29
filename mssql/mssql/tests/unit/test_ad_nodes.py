"""Unit tests for the Stage-7a AD node derivation (``openhound_mssql.ad_nodes``)
and the convert AD node asset (``openhound_mssql.models.ad_node``).

Two layers:

* Pure helpers (``kinds_for`` / ``display_name`` / ``authenticated_users_id`` /
  ``local_group_id`` / ``has_connect_sql``) — the id/kind/connect rules ported
  verbatim from Go ``createADNodes``.
* ``build_ad_nodes`` over an in-memory DuckDB fixture exercising every node
  category Go creates: host Computer (SID id), Authenticated Users (EPA Off +
  enabled computer login), a domain login (User+Base, SID id, enriched), a local
  group (Group+Base, ``<host>-<SID>`` id), and a credential identity (from
  ``ad_resolved``). Also covers the gating (disabled / no-connect logins dropped)
  and the dedupe (host computer not duplicated by a service account on the same
  SID).

Expected values come from the Go logic in
``MSSQLHound/internal/collector/collector.go`` ``createADNodes``.
"""
from __future__ import annotations

import duckdb
import pytest

from openhound_mssql import ad_nodes
from openhound_mssql.kinds import nodes as nk
from openhound_mssql.models.ad_node import ADNode

SCHEMA = "mssql"

DOMAIN = "mayyhem.com"
DOMAIN_SID = "S-1-5-21-1004336348-1177238915-682003330"
COMPUTER_SID = f"{DOMAIN_SID}-1109"          # the host computer account
DOMAINADMIN_SID = f"{DOMAIN_SID}-1104"        # a domain user with a login
SVCACCT_SID = f"{DOMAIN_SID}-1500"            # a credential identity
LOCAL_GROUP_SID = "S-1-5-32-544"              # BUILTIN\Administrators


def _hex_sid(sid_string: str) -> str:
    """Encode ``S-1-5-21-...`` back into the ``0x...`` hex the raw sid column has."""
    parts = sid_string.split("-")
    revision = int(parts[1])
    authority = int(parts[2])
    sub_auths = [int(p) for p in parts[3:]]
    raw = bytes([revision, len(sub_auths)])
    raw += authority.to_bytes(6, "big")
    for sub in sub_auths:
        raw += sub.to_bytes(4, "little")
    return "0x" + raw.hex().upper()


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------
def test_kinds_for_object_class_wins():
    assert ad_nodes.kinds_for("anything", "computer", "") == [nk.COMPUTER, nk.BASE]
    assert ad_nodes.kinds_for("anything", "group", "") == [nk.GROUP, nk.BASE]
    assert ad_nodes.kinds_for("anything", "user", "") == [nk.USER, nk.BASE]


def test_kinds_for_name_and_type_heuristic():
    # No object class: `$` suffix -> Computer; "GROUP" in type -> Group; else User.
    assert ad_nodes.kinds_for("PS1-DB$", None, "WINDOWS_LOGIN") == [nk.COMPUTER, nk.BASE]
    assert ad_nodes.kinds_for("MAYYHEM\\Admins", None, "WINDOWS_GROUP") == [nk.GROUP, nk.BASE]
    assert ad_nodes.kinds_for("MAYYHEM\\jdoe", None, "WINDOWS_LOGIN") == [nk.USER, nk.BASE]


def test_display_name_strips_netbios_and_appends_domain():
    assert ad_nodes.display_name("MAYYHEM\\jdoe", DOMAIN) == f"jdoe@{DOMAIN}"
    # Already @-qualified: left as-is.
    assert ad_nodes.display_name("jdoe@mayyhem.com", DOMAIN) == "jdoe@mayyhem.com"
    # No domain configured: returned unchanged (after NetBIOS strip).
    assert ad_nodes.display_name("MAYYHEM\\jdoe", "") == "jdoe"


def test_authenticated_users_id():
    assert ad_nodes.authenticated_users_id(DOMAIN) == f"{DOMAIN}-S-1-5-11"
    assert ad_nodes.authenticated_users_id("") == "S-1-5-11"


def test_local_group_id():
    assert ad_nodes.local_group_id("ps1-db", LOCAL_GROUP_SID) == f"ps1-db-{LOCAL_GROUP_SID}"


def test_has_connect_sql():
    # Direct CONNECT SQL grant.
    assert ad_nodes.has_connect_sql({"CONNECT SQL"}, set()) is True
    # Implicit via sysadmin / securityadmin membership.
    assert ad_nodes.has_connect_sql(set(), {"sysadmin"}) is True
    assert ad_nodes.has_connect_sql(set(), {"securityadmin"}) is True
    # Neither -> no connect.
    assert ad_nodes.has_connect_sql({"VIEW SERVER STATE"}, {"public"}) is False


# ---------------------------------------------------------------------------
# build_ad_nodes over a DuckDB fixture
# ---------------------------------------------------------------------------
@pytest.fixture()
def con() -> duckdb.DuckDBPyConnection:
    con = duckdb.connect(":memory:")
    con.execute(f"CREATE SCHEMA {SCHEMA}")

    # servers: carries the resolved computer SID + fqdn + EPA Off.
    con.execute(f"""
        CREATE TABLE {SCHEMA}.servers AS SELECT * FROM (VALUES
            ('PS1-DB', 'PS1-DB', '{COMPUTER_SID}', 'ps1-db.{DOMAIN}', 'Off')
        ) AS t("server_name","machine_name","computer_sid","fqdn","extended_protection")
    """)

    # server_principals:
    #   sa(1)         SQL_LOGIN, no SID                          -> no AD node
    #   domainadmin(20) WINDOWS_LOGIN, domain SID, sysadmin      -> User+Base node
    #   PS1-DB$(50)   WINDOWS_LOGIN, computer SID, CONNECT SQL   -> drives Auth Users
    #   builtinAdmins(60) WINDOWS_GROUP, S-1-5-32-544, CONNECT   -> local Group node
    #   disabledUser(70) WINDOWS_LOGIN, domain SID, but disabled -> dropped
    #   noConnectUser(80) WINDOWS_LOGIN, domain SID, no connect  -> dropped
    con.execute(f"""
        CREATE TABLE {SCHEMA}.server_principals AS SELECT * FROM (VALUES
            (1,  'sa',                   'SQL_LOGIN',     false, '0x01'),
            (20, 'MAYYHEM\\domainadmin', 'WINDOWS_LOGIN', false, '{_hex_sid(DOMAINADMIN_SID)}'),
            (50, 'MAYYHEM\\PS1-DB$',     'WINDOWS_LOGIN', false, '{_hex_sid(COMPUTER_SID)}'),
            (60, 'BUILTIN\\Administrators','WINDOWS_GROUP',false,'{_hex_sid(LOCAL_GROUP_SID)}'),
            (70, 'MAYYHEM\\disabledusr', 'WINDOWS_LOGIN', true,  '{_hex_sid(DOMAIN_SID + "-1300")}'),
            (80, 'MAYYHEM\\noconnusr',   'WINDOWS_LOGIN', false, '{_hex_sid(DOMAIN_SID + "-1400")}')
        ) AS t("principal_id","name","type_desc","is_disabled","sid")
    """)

    # role memberships: domainadmin(20) is in sysadmin -> implicit CONNECT SQL.
    con.execute(f"""
        CREATE TABLE {SCHEMA}.server_role_members AS SELECT * FROM (VALUES
            (20, 3, 'sysadmin')
        ) AS t("member_principal_id","role_principal_id","role_name")
    """)

    # permissions: PS1-DB$(50) + builtinAdmins(60) granted CONNECT SQL directly;
    # noConnectUser(80) only has an unrelated grant.
    con.execute(f"""
        CREATE TABLE {SCHEMA}.server_permissions AS SELECT * FROM (VALUES
            (50, 'CONNECT SQL', 'GRANT'),
            (60, 'CONNECT SQL', 'GRANT'),
            (80, 'VIEW SERVER STATE', 'GRANT')
        ) AS t("grantee_principal_id","permission_name","state_desc")
    """)

    # ad_resolved: collect-time resolutions (dlt-snake-cased columns). The host
    # computer (deduped against the servers-derived node), domainadmin (enrich),
    # and a credential identity (drives a standalone User node).
    con.execute(f"""
        CREATE TABLE {SCHEMA}.ad_resolved AS SELECT * FROM (VALUES
            ('{COMPUTER_SID}',   'ps1-db.{DOMAIN}',      'computer', 'PS1-DB$',     true,  'CN=PS1-DB,OU=x', 'ps1-db.{DOMAIN}', NULL,            'host_computer'),
            ('{DOMAINADMIN_SID}','domainadmin@{DOMAIN}', 'user',     'domainadmin', true,  'CN=da,OU=x',     NULL,              'domainadmin@{DOMAIN}', 'server_principal'),
            ('{SVCACCT_SID}',    'sqlsvc@{DOMAIN}',      'user',     'sqlsvc',      true,  'CN=svc,OU=x',    NULL,              'sqlsvc@{DOMAIN}',  'credential')
        ) AS t("sid","name","type","sam_account_name","enabled","dn","dns_host_name","upn","source")
    """)

    ad_nodes.build_ad_nodes(con, SCHEMA, f"{COMPUTER_SID}:1433")
    return con


def _nodes(con) -> dict[str, dict]:
    cur = con.execute(f"SELECT * FROM {SCHEMA}.ad_nodes")
    cols = [c[0] for c in cur.description]
    return {r[0]: dict(zip(cols, r)) for r in cur.fetchall()}


def test_host_computer_node(con):
    nodes = _nodes(con)
    host = nodes[COMPUTER_SID]
    assert list(host["kinds"]) == [nk.COMPUTER, nk.BASE]
    assert host["SID"] == COMPUTER_SID
    assert host["SAMAccountName"] == "PS1-DB$"
    assert host["isDomainPrincipal"] is True
    assert host["DNSHostName"] == f"ps1-db.{DOMAIN}"        # raw FQDN stays lowercase
    assert host["domain"] == DOMAIN.upper()                 # Go uppercases the AD-node domain


def test_authenticated_users_node(con):
    nodes = _nodes(con)
    # Go uppercases the domain for the Authenticated Users id + name.
    auth_id = ad_nodes.authenticated_users_id(DOMAIN.upper())
    assert auth_id in nodes, "EPA Off + enabled computer login should create Authenticated Users"
    assert list(nodes[auth_id]["kinds"]) == [nk.GROUP, nk.BASE]
    assert nodes[auth_id]["name"] == f"AUTHENTICATED USERS@{DOMAIN.upper()}"


def test_domain_login_node_enriched(con):
    nodes = _nodes(con)
    da = nodes[DOMAINADMIN_SID]
    assert list(da["kinds"]) == [nk.USER, nk.BASE]
    assert da["name"] == f"domainadmin@{DOMAIN.upper()}"  # NetBIOS stripped + @DOMAIN (Go uppercases)
    assert da["SID"] == DOMAINADMIN_SID
    assert da["SAMAccountName"] == "domainadmin"        # from ad_resolved enrichment
    assert da["isEnabled"] is True
    assert da["distinguishedName"] == "CN=da,OU=x"
    assert da["isDomainPrincipal"] is True


def test_local_group_node(con):
    nodes = _nodes(con)
    # Local-group id keys off the connection host (the FQDN), matching Go's
    # serverInfo.Hostname.
    gid = ad_nodes.local_group_id(f"ps1-db.{DOMAIN}", LOCAL_GROUP_SID)
    assert gid in nodes
    assert list(nodes[gid]["kinds"]) == [nk.GROUP, nk.BASE]
    assert nodes[gid]["name"] == "BUILTIN\\Administrators"
    # Local group props: name + isActiveDirectoryPrincipal only (no SID/domain).
    assert nodes[gid]["SID"] is None


def test_credential_identity_node(con):
    nodes = _nodes(con)
    svc = nodes[SVCACCT_SID]
    assert list(svc["kinds"]) == [nk.USER, nk.BASE]
    assert svc["name"] == f"sqlsvc@{DOMAIN}"
    assert svc["SID"] == SVCACCT_SID
    assert svc["SAMAccountName"] == "sqlsvc"


def test_disabled_and_noconnect_logins_dropped(con):
    nodes = _nodes(con)
    assert f"{DOMAIN_SID}-1300" not in nodes, "disabled login must not get a node"
    assert f"{DOMAIN_SID}-1400" not in nodes, "login without CONNECT SQL must not get a node"


def test_node_count(con):
    # host Computer + Authenticated Users + domainadmin + BUILTIN group + svc cred = 5.
    assert len(_nodes(con)) == 5


def test_sa_sql_login_has_no_ad_node(con):
    # sa is a SQL login (no SID); it must never produce an AD node.
    nodes = _nodes(con)
    assert all(node.get("name") != "sa" for node in nodes.values())


# ---------------------------------------------------------------------------
# Convert asset (ad_nodes row -> MSSQLNode)
# ---------------------------------------------------------------------------
def test_ad_node_asset_emits_iconless_node():
    asset = ADNode(
        id=DOMAINADMIN_SID,
        kinds=[nk.USER, nk.BASE],
        name=f"domainadmin@{DOMAIN}",
        SID=DOMAINADMIN_SID,
        domain=DOMAIN,
        isDomainPrincipal=True,
        SAMAccountName="domainadmin",
        isEnabled=True,
    )
    node = asset.as_node
    assert node is not None
    assert node.id == DOMAINADMIN_SID
    assert node.kinds == [nk.USER, nk.BASE]
    assert node.icon is None, "AD nodes carry NO icon"
    assert node.properties.SID == DOMAINADMIN_SID
    assert node.properties.SAMAccountName == "domainadmin"
    assert node.properties.isDomainPrincipal is True


def test_ad_node_asset_drops_row_without_id():
    assert ADNode(id=None, kinds=[nk.USER, nk.BASE], name="x").as_node is None


def test_ad_node_asset_omits_absent_props():
    # A local group row sets only name + isActiveDirectoryPrincipal.
    asset = ADNode(
        id="ps1-db-S-1-5-32-544",
        kinds=[nk.GROUP, nk.BASE],
        name="BUILTIN\\Administrators",
        isActiveDirectoryPrincipal=False,
    )
    node = asset.as_node
    assert node is not None
    # SID / domain / SAMAccountName were never set -> stay None (omitted at emit).
    assert node.properties.SID is None
    assert node.properties.domain is None
    assert node.properties.isActiveDirectoryPrincipal is False
