# src/openhound_sccm/edge_has_member_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_edge_has_member_device_and_user_skip_builtin():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # single primary PS1 -> root resolves to PS1
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    # a device resource (-> ClientDevice smsid) and a user resource (-> user SID)
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'alice' AS name, "
                "'S-1-5-21-1-2-3-1106' AS sid, 9 AS resource_id, 'PS1' AS source_site_code")
    # memberships: device (7), user (9), and a built-in pseudo-resource (skipped)
    con.execute("CREATE TABLE sccm.adminservice_collection_members AS SELECT * FROM (VALUES "
                "('PS100016', 7, 'PS1'), ('PS100016', 9, 'PS1'), ('PS100016', 2046820352, 'PS1')) "
                "AS t(collection_id, resource_id, site_code)")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='SCCM_HasMember' ORDER BY end_id").fetchall()
    assert rows == [("PS100016@PS1", "GUID-1"), ("PS100016@PS1", "S-1-5-21-1-2-3-1106")]
