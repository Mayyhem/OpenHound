# src/openhound_sccm/convert_pipeline_test.py
import json
import duckdb
from openhound_sccm.lookup import SCCMLookup
from openhound_sccm.convert_pipeline import emit_graph_from_duckdb


def _db(tmp_path):
    path = tmp_path / "lookup.duckdb"
    con = duckdb.connect(str(path))
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.node_spike AS SELECT 'SPIKE-1' AS id, 'spike' AS name")
    con.execute("CREATE TABLE sccm.graph_edges AS "
                "SELECT 'SPIKE-1' AS start_id, 'SPIKE-1' AS end_id, 'SCCM_Spike' AS kind")
    con.close()
    return str(path)


def test_emit_writes_one_node_and_one_edge(tmp_path):
    client = duckdb.connect(_db(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    out = tmp_path / "graph"
    emit_graph_from_duckdb(lookup, out, "Kind", node_tables=["node_spike"])

    nodes, edges = [], []
    for f in out.glob("*.json"):
        doc = json.loads(f.read_text())
        nodes += doc["graph"]["nodes"]
        edges += doc["graph"]["edges"]
    assert [n["id"] for n in nodes] == ["SPIKE-1"]
    assert [e["kind"] for e in edges] == ["SCCM_Spike"]
