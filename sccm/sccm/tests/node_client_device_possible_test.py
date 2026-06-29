# src/openhound_sccm/node_client_device_possible_test.py
import duckdb
from openhound_sccm.transforms import transforms


def _seed(con, disable):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(f"CREATE TABLE sccm.collection_settings AS "
                f"SELECT {str(disable).lower()} AS disable_possible_edges, false AS enable_bad_opsec")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
                "'S-1-5-21-1-2-3-1104' AS object_sid, 'WS09' AS name")


def test_possible_client_emitted_when_enabled():
    con = duckdb.connect(":memory:"); _seed(con, disable=False); transforms(con)
    rows = con.execute("SELECT smsid, is_confirmed_active_client, ad_domain_sid, root_site_code "
                       "FROM sccm.node_client_device WHERE NOT is_confirmed_active_client").fetchall()
    assert rows == [("S-1-5-21-1-2-3-1104@CAS", False, "S-1-5-21-1-2-3-1104", "CAS")]
    # C2's HasClient picks it up automatically (start = root site)
    hc = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                     "WHERE kind='SCCM_HasClient' AND end_id='S-1-5-21-1-2-3-1104@CAS'").fetchall()
    assert hc == [("CAS", "S-1-5-21-1-2-3-1104@CAS")]


def test_possible_client_suppressed_when_disabled():
    con = duckdb.connect(":memory:"); _seed(con, disable=True); transforms(con)
    cnt = con.execute("SELECT count(*) FROM sccm.node_client_device WHERE NOT is_confirmed_active_client").fetchone()[0]
    assert cnt == 0
