import duckdb
from openhound_sccm.transforms import transforms

def test_graph_edges_deduplicated_across_sources():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    # the SAME admin in BOTH adminservice and wmi -> _edge_is_mapped_to would insert twice
    row = "SELECT 'MAYYHEM\\a' AS logon_name, 'S-1-5-21-1-2-3-1110' AS admin_sid, false AS is_group"
    con.execute(f"CREATE TABLE sccm.adminservice_admins AS {row}")
    con.execute(f"CREATE TABLE sccm.wmi_admins AS {row}")
    transforms(con)
    cnt = con.execute("SELECT count(*) FROM sccm.graph_edges "
                      "WHERE kind='SCCM_IsMappedTo' AND end_id='MAYYHEM\\A@CAS'").fetchone()[0]
    assert cnt == 1   # deduped, not 2
