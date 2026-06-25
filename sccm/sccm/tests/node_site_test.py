# src/openhound_sccm/node_site_test.py
"""Tests for the node_site coalesce table produced by transforms._node_site()."""
import duckdb

from openhound_sccm.transforms import transforms


def test_node_site_has_root_env():
    """A site row gets root_site_code joined from site_hierarchy."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # adminservice_site_definitions seeds site_hierarchy (required by _site_hierarchy)
    # and also contributes to node_site. Full column set matches real collector output.
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
        "(VALUES ('CAS', NULL, 4, NULL, NULL, NULL), "
        "        ('PS1', 'CAS', 2, NULL, NULL, NULL)) "
        "AS t(site_code, parent_site_code, site_type, site_guid, sql_server_name, sql_database_name)"
    )
    # adminservice_sites contributes site_name, server_name, etc.
    con.execute(
        "CREATE TABLE sccm.adminservice_sites AS SELECT * FROM "
        "(VALUES ('PS1', 'Primary', 'srv.lab', 'CAS', 2, '5.0', NULL, NULL)) "
        "AS t(site_code, site_name, server_name, reporting_site_code, type, version, build_number, install_dir)"
    )
    transforms(con)
    row = con.execute(
        "SELECT site_code, root_site_code, site_type FROM sccm.node_site WHERE site_code='PS1'"
    ).fetchone()
    assert row == ("PS1", "CAS", 2)


def test_node_site_cas_has_root_equal_to_itself():
    """The CAS is its own root."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
        "(VALUES ('CAS', NULL, 4, NULL, NULL, NULL), "
        "        ('PS1', 'CAS', 2, NULL, NULL, NULL)) "
        "AS t(site_code, parent_site_code, site_type, site_guid, sql_server_name, sql_database_name)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_sites AS SELECT * FROM "
        "(VALUES ('CAS', 'CAS Site', 'cas.lab', NULL, 4, '5.0', NULL, NULL)) "
        "AS t(site_code, site_name, server_name, reporting_site_code, type, version, build_number, install_dir)"
    )
    transforms(con)
    row = con.execute(
        "SELECT site_code, root_site_code FROM sccm.node_site WHERE site_code='CAS'"
    ).fetchone()
    assert row == ("CAS", "CAS")


def test_node_site_unions_ldap_source():
    """A site guid seen only in ldap_sites still lands in node_site via union."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
        "(VALUES ('PS1', NULL, 2, NULL, NULL, NULL)) "
        "AS t(site_code, parent_site_code, site_type, site_guid, sql_server_name, sql_database_name)"
    )
    con.execute(
        "CREATE TABLE sccm.ldap_sites AS SELECT 'PS1' AS site_code, "
        "'{guid-1234}' AS site_guid, NULL AS parent_site_code"
    )
    transforms(con)
    row = con.execute(
        "SELECT site_code, site_guid FROM sccm.node_site WHERE site_code='PS1'"
    ).fetchone()
    assert row[0] == "PS1"
    assert row[1] == "{guid-1234}"


def test_node_site_lists_and_sql_account():
    """node_site gains sql_service_account_name from site_systems and
    admin_users / stored_accounts list columns from _enrich_site_lists."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('CAS', NULL, 4)) "
        "AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_sites AS "
        "SELECT 'CAS' AS site_code, 'CAS Site' AS site_name, 'srv' AS server_name, 4 AS type"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_admins AS "
        "SELECT 'MAYYHEM\\adm' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_reserved_accounts AS "
        "SELECT 'S-1-5-21-1-2-3-1300' AS object_sid, 'CAS' AS site_code, 'svc_naa' AS name"
    )
    con.execute(
        "CREATE TABLE sccm.adminservice_site_systems AS "
        "SELECT '\\\\SQL01.lab' AS network_os_path, 'CAS' AS site_code, "
        "'SMS SQL Server' AS role_name, "
        "'MAYYHEM\\sqlsvc' AS sql_server_service_logon_account"
    )
    transforms(con)
    r = con.execute(
        "SELECT sql_service_account_name, admin_users, stored_accounts "
        "FROM sccm.node_site WHERE site_code='CAS'"
    ).fetchone()
    assert r[0] == "MAYYHEM\\sqlsvc"
    assert r[1] == ["MAYYHEM\\ADM@CAS"]
    assert r[2] == ["S-1-5-21-1-2-3-1300"]


def test_node_site_ldap_distinguished_name_and_source_forest():
    """distinguished_name and source_forest from ldap_sites land in node_site."""
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.adminservice_site_definitions AS "
        "SELECT * FROM (VALUES ('CAS', NULL, 4)) "
        "AS t(site_code, parent_site_code, site_type)"
    )
    con.execute(
        "CREATE TABLE sccm.ldap_sites AS "
        "SELECT 'CAS' AS site_code, NULL AS site_guid, NULL AS parent_site_code, "
        "'CN=CAS,CN=SMS-Site-CAS,CN=System,DC=lab,DC=local' AS distinguished_name, "
        "'lab.local' AS source_forest"
    )
    transforms(con)
    row = con.execute(
        "SELECT distinguished_name, source_forest FROM sccm.node_site WHERE site_code='CAS'"
    ).fetchone()
    assert row[0] == "CN=CAS,CN=SMS-Site-CAS,CN=System,DC=lab,DC=local"
    assert row[1] == "lab.local"
