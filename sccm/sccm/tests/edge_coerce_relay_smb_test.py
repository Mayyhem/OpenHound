import duckdb

from openhound_sccm.transforms import _graph_edges_init, _edge_coerce_relay_smb


def _seed(con, target_ntlm):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(
        "CREATE TABLE sccm.site_hierarchy AS SELECT 'PS1' AS site_code, 2 AS site_type"
    )
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT * FROM (VALUES "
        # vulnerable target: a DP@PS1 with signing not required + given NTLM
        "('S-1-5-21-1-2-3-7001','DP01.mayyhem.com',['SMS Distribution Point@PS1'],"
        " false, ['SMB-Negotiate'], ?), "
        # coerced site server
        "('S-1-5-21-1-2-3-1002','SS01.mayyhem.com',['SMS Site Server@PS1'],"
        " true, [], NULL)"
        ") AS t(sid, dnshostname, site_system_roles, smb_signing_required, "
        "smb_signing_source, restrict_receiving_ntlm_traffic)",
        [target_ntlm],
    )
    _graph_edges_init(con, "sccm")


def test_smb_relay_default_emits():
    con = duckdb.connect()
    _seed(con, target_ntlm=None)  # NTLM unknown -> assume vulnerable
    _edge_coerce_relay_smb(con, "sccm", disable_possible=False)
    rows = con.execute(
        "SELECT start_id, end_id, kind, collection_source, coercion_victim_hostnames "
        "FROM sccm.graph_edges"
    ).fetchall()
    assert len(rows) == 1
    start, end, kind, csrc, victims = rows[0]
    assert start == "MAYYHEM.COM-S-1-5-11"
    assert end == "S-1-5-21-1-2-3-7001"          # the vulnerable site system
    assert kind == "CoerceAndRelayToSMB"
    assert csrc == ["SMB-Negotiate"]
    assert victims == ["SS01.mayyhem.com"]        # the coerced site server


def test_smb_relay_flag_drops_null_ntlm():
    con = duckdb.connect()
    _seed(con, target_ntlm=None)
    _edge_coerce_relay_smb(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0


def test_smb_relay_flag_keeps_confirmed():
    con = duckdb.connect()
    _seed(con, target_ntlm="Off")  # confirmed NTLM not restricted + signing off
    _edge_coerce_relay_smb(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 1
