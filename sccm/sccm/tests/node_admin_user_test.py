# src/openhound_sccm/node_admin_user_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_node_admin_user_one_row_per_logon():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    # same admin replicated from two sites -> one node (dedup on upper(logon_name))
    # Use single backslash in the SQL literal ('MAYYHEM\sccmadmin') so DuckDB stores
    # one backslash — matching the assertion below. Python \\  -> SQL \ -> stored \.
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT * FROM (VALUES "
                "('MAYYHEM\\sccmadmin','S-1-5-21-1-2-3-1110','adm', false, 1), "
                "('MAYYHEM\\sccmadmin','S-1-5-21-1-2-3-1110','adm', false, 1)) "
                "AS t(logon_name, admin_sid, display_name, is_group, account_type)")
    transforms(con)
    rows = con.execute("SELECT logon_name, admin_sid, root_site_code FROM sccm.node_admin_user").fetchall()
    assert rows == [("MAYYHEM\\sccmadmin", "S-1-5-21-1-2-3-1110", "CAS")]
