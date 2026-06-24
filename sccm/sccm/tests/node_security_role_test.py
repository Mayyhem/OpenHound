# src/openhound_sccm/node_security_role_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_node_security_role_one_row_per_id():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS000AR' AS role_id, "
                "'Full Administrator' AS role_name, 'desc' AS role_description, true AS is_built_in, "
                "false AS is_sec_admin_role")
    transforms(con)
    r = con.execute("SELECT role_id, role_name, root_site_code FROM sccm.node_security_role").fetchone()
    assert r == ("SMS000AR", "Full Administrator", "CAS")
