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
