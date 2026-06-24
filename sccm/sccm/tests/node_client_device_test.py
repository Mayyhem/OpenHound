# src/openhound_sccm/node_client_device_test.py
import duckdb
from openhound_sccm.transforms import transforms


def test_node_client_device_filters_and_keys_on_smsid():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT * FROM (VALUES "
                "('GUID-1','WS01', 7, 'PS1', true,  false, 'MAYYHEM\\\\alice','MAYYHEM\\\\bob','MAYYHEM\\\\carol'), "
                "('GUID-2','WS02', 8, 'PS1', false, false, NULL, NULL, NULL), "       # not a client -> dropped
                "('GUID-3','WS03', 9, 'PS1', true,  true,  NULL, NULL, NULL)) "        # obsolete -> dropped
                "AS t(smsid, name, resource_id, site_code, is_client, is_obsolete, primary_user, current_logon_user, user_name)")
    transforms(con)
    rows = con.execute("SELECT smsid, name, resource_id_str, possible FROM sccm.node_client_device ORDER BY smsid").fetchall()
    assert rows == [("GUID-1", "WS01", "7@PS1", False)]
