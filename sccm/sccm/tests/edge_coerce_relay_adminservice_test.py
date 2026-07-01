import duckdb

from openhound_sccm.transforms import _graph_edges_init, _edge_coerce_relay_adminservice


def _seed(con, provider_ntlm):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.site_hierarchy AS SELECT 'PS1' AS site_code, 2 AS site_type "
        "UNION ALL SELECT 'SEC' AS site_code, 1 AS site_type"
    )
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT * FROM (VALUES "
        # provider: SMS Provider@PS1 with given NTLM value
        "('S-1-5-21-1-2-3-1001','PROV01.mayyhem.com',['SMS Provider@PS1'], ?), "
        # site server: SMS Site Server@PS1, NTLM unknown
        "('S-1-5-21-1-2-3-1002','SS01.mayyhem.com',['SMS Site Server@PS1'], NULL), "
        # a secondary-site system, must be ignored
        "('S-1-5-21-1-2-3-1003','SEC01.mayyhem.com',['SMS Site Server@SEC'], NULL)"
        ") AS t(sid, dnshostname, site_system_roles, restrict_receiving_ntlm_traffic)",
        [provider_ntlm],
    )
    _graph_edges_init(con, "sccm")


def test_adminservice_relay_default_emits_with_null_ntlm():
    con = duckdb.connect()
    _seed(con, None)  # provider NTLM unknown -> assume vulnerable (default)
    _edge_coerce_relay_adminservice(con, "sccm", disable_possible=False)
    rows = con.execute(
        "SELECT start_id, end_id, kind, collection_source, "
        "coercion_victim_and_relay_target_pairs FROM sccm.graph_edges"
    ).fetchall()
    assert len(rows) == 1
    start, end, kind, csrc, pairs = rows[0]
    assert start == "MAYYHEM.COM-S-1-5-11"
    assert end == "PS1"          # non-secondary site code (raw case)
    assert kind == "CoerceAndRelayToAdminService"
    assert csrc == ["Post-processing"]
    assert pairs == ["Coerce SS01.mayyhem.com, relay to PROV01.mayyhem.com"]


def test_adminservice_relay_flag_drops_null_ntlm():
    con = duckdb.connect()
    _seed(con, None)
    _edge_coerce_relay_adminservice(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0


def test_adminservice_relay_flag_keeps_confirmed_off():
    con = duckdb.connect()
    _seed(con, "Off")  # explicitly confirmed not-restricting NTLM
    _edge_coerce_relay_adminservice(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 1
