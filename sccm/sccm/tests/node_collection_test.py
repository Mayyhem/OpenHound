# src/openhound_sccm/node_collection_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_node_collection_one_row_per_id_with_root():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4), ('PS1','CAS',2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT "
                "'PS100016' AS collection_id, 'All Systems' AS name, 2 AS collection_type, "
                "42 AS member_count, false AS is_built_in, 'PS1' AS source_site_code")
    transforms(con)
    rows = con.execute("SELECT collection_id, name, member_count, root_site_code FROM sccm.node_collection").fetchall()
    assert rows == [("PS100016", "All Systems", 42, "CAS")]
