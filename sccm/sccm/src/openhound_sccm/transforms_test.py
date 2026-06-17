import duckdb
from openhound_sccm.transforms import transforms


def test_transforms_builds_spike_tables():
    con = duckdb.connect(":memory:")
    transforms(con, schema="sccm")
    nodes = con.execute("SELECT id, name FROM sccm.node_spike").fetchall()
    edges = con.execute("SELECT start_id, end_id, kind FROM sccm.graph_edges").fetchall()
    assert nodes == [("SPIKE-1", "spike")]
    assert edges == [("SPIKE-1", "SPIKE-1", "SCCM_Spike")]
