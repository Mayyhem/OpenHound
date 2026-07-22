import duckdb

from openhound_sccm.transforms import _graph_edges_init, _edge_coerce_relay_mssql


def _seed(con, host_ntlm, epa):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # SQL host computer (the site DB server) + the sysadmin victim computer.
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT * FROM (VALUES "
        "('S-1-5-21-1-2-3-5001','SQL01.mayyhem.com', ?), "       # host (site DB)
        "('S-1-5-21-1-2-3-1002','SS01.mayyhem.com', NULL)"        # sysadmin victim
        ") AS t(sid, dnshostname, restrict_receiving_ntlm_traffic)",
        [host_ntlm],
    )
    con.execute(
        "CREATE TABLE sccm.node_mssql_server AS SELECT "
        "'S-1-5-21-1-2-3-5001:1433' AS server_id, 'SQL01.mayyhem.com' AS dns_host_name, "
        "'SQL01.mayyhem.com' AS name, '1433' AS port, ? AS extended_protection, "
        "['MSSQL-ScanForEPA','SCCM_Add-MSSQLServerNodesAndEdges'] AS collection_source",
        [epa],
    )
    con.execute(
        "CREATE TABLE sccm.node_mssql_login AS SELECT "
        "'MAYYHEM\\SS01$@S-1-5-21-1-2-3-5001:1433' AS login_id, "
        "'S-1-5-21-1-2-3-5001:1433' AS server_id, 'S-1-5-21-1-2-3-5001' AS host_sid, "
        "'S-1-5-21-1-2-3-1002' AS sysadmin_computer_sid"
    )
    _graph_edges_init(con, "sccm")


def test_mssql_relay_default_emits_when_epa_null():
    con = duckdb.connect()
    _seed(con, host_ntlm=None, epa=None)  # both unknown -> assume vulnerable
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=False)
    rows = con.execute(
        "SELECT start_id, end_id, kind, collection_source, "
        "coercion_victim_and_relay_target_pairs FROM sccm.graph_edges"
    ).fetchall()
    assert len(rows) == 1
    start, end, kind, csrc, pairs = rows[0]
    assert start == "MAYYHEM.COM-S-1-5-11"
    assert end == "MAYYHEM\\SS01$@S-1-5-21-1-2-3-5001:1433"
    assert kind == "MSSQL_CoerceAndRelayToMSSQL"
    assert csrc == ["MSSQL-ScanForEPA"]  # EPA sources only
    assert pairs == ["Coerce SS01.mayyhem.com, relay to SQL01.mayyhem.com:1433"]


def test_mssql_relay_skips_when_epa_enabled():
    con = duckdb.connect()
    _seed(con, host_ntlm="Off", epa="Required")  # EPA on -> never a relay target
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=False)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0


def test_mssql_relay_flag_drops_assumed_epa():
    con = duckdb.connect()
    _seed(con, host_ntlm="Off", epa=None)  # EPA unknown -> dropped under the flag
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0


def test_mssql_relay_flag_keeps_null_ntlm_with_confirmed_epa():
    # New semantics: host NTLM unset = Windows default (allow all inbound NTLM) = vulnerable, so
    # with EPA explicitly 'Off' (the confirmed gate) the edge survives --disable-possible-edges.
    # NTLM is flag-independent; only EPA must be explicit 'Off' under the flag. Matches CMBP.
    con = duckdb.connect()
    _seed(con, host_ntlm=None, epa="Off")  # EPA explicit Off (confirmed), host NTLM unset (default-vulnerable)
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 1


def test_mssql_relay_drops_explicit_ntlm_restricted():
    # Explicitly restricted host NTLM (not 'Off') -> the relayed NTLM is refused -> no edge, even
    # with EPA off and even without the flag.
    con = duckdb.connect()
    _seed(con, host_ntlm="DenyAll", epa="Off")
    _edge_coerce_relay_mssql(con, "sccm", disable_possible=True)
    assert con.execute("SELECT count(*) FROM sccm.graph_edges").fetchone()[0] == 0
