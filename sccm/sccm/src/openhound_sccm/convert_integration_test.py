# src/openhound_sccm/convert_integration_test.py
import gzip
import json
import subprocess
import sys
from pathlib import Path


def _seed_raw(raw: Path):
    """Minimal raw tree: one row in one real table dir. The Stage-0 transformer ignores
    inputs and builds literal spike tables, so any nonempty raw tree is enough for
    preprocess to run."""
    d = raw / "sccm" / "adminservice_r_system"
    d.mkdir(parents=True)
    with gzip.open(d / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(json.dumps({"sid": "S-1-5-21-1-1-1-1104", "name": "DESKTOP-CHRIS"}) + "\n")


def test_preprocess_then_convert_emits_spike(tmp_path):
    raw = tmp_path / "raw"
    _seed_raw(raw)
    db = tmp_path / "lookup.duckdb"
    graph = tmp_path / "graph"

    def run(*args):
        return subprocess.run([sys.executable, "-m", "openhound", *args],
                              capture_output=True, text=True)

    pre = run("preprocess", "sccm", str(raw), str(db))
    assert pre.returncode == 0, pre.stderr
    conv = run("convert", "sccm", str(raw / "sccm"), str(graph), "--lookup-file", str(db))
    assert conv.returncode == 0, conv.stderr

    nodes, edges = [], []
    for f in graph.glob("*.json"):
        doc = json.loads(f.read_text())
        nodes += doc["graph"]["nodes"]
        edges += doc["graph"]["edges"]
    assert "SPIKE-1" in [n["id"] for n in nodes]
    assert "SCCM_Spike" in [e["kind"] for e in edges]
