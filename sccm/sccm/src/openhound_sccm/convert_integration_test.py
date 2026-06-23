# src/openhound_sccm/convert_integration_test.py
"""End-to-end integration test: preprocess then convert, asserting real nodes.

Seeds a minimal real raw tree:
  - one adminservice_r_system row (a domain SID + name) → becomes a Computer node
  - two adminservice_site_definitions rows (a CAS + a Primary) → become SCCM_Site
    nodes and an SCCM_AdminsReplicatedTo edge

Runs preprocess then convert as subprocesses (matching real user invocation),
then reads the output graph files and asserts:
  - a Computer node with the seeded SID appears
  - a SCCM_Site node with the seeded site code appears
  - SPIKE-1 and SCCM_Spike are absent
"""
import gzip
import json
import subprocess
import sys
from pathlib import Path

# Seeded values used in assertions below.
_COMPUTER_SID = "S-1-5-21-10-20-30-1104"
_SITE_CODE_CAS = "CAS"
_SITE_CODE_PRIMARY = "PS1"


def _seed_raw(raw: Path) -> None:
    """Write a minimal real raw tree that preprocess can consume.

    Column names are the clean snake_case names the post-Task-3 collectors emit.
    Each table dir gets one gzipped JSONL file with one data row.
    """
    # --- adminservice_r_system: one computer with a real domain SID ---
    r_sys_dir = raw / "sccm" / "adminservice_r_system"
    r_sys_dir.mkdir(parents=True)
    with gzip.open(r_sys_dir / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        fh.write(
            json.dumps({
                "sid": _COMPUTER_SID,
                "name": "DESKTOP-SEED",
                "obsolete": False,
                "resource_id": 42,
                "source_site_code": _SITE_CODE_PRIMARY,
                "system_roles": "SMS Provider",
                "sms_unique_identifier": "GUID:seed-test",
            }) + "\n"
        )

    # --- adminservice_site_definitions: CAS + Primary so hierarchy + nodes fire ---
    site_def_dir = raw / "sccm" / "adminservice_site_definitions"
    site_def_dir.mkdir(parents=True)
    with gzip.open(site_def_dir / "data.jsonl.gz", "wt", encoding="utf-8") as fh:
        # DLT skips null-valued fields when inferring schema — use placeholder
        # non-null strings so it creates site_guid/sql_server_name/sql_database_name
        # columns in DuckDB. Without them the _node_site INSERT fails silently via
        # _safe() (BinderException on the missing column reference), leaving node_site
        # empty and producing no SCCM_Site nodes in convert.
        # CAS has no parent; Primary's parent is CAS.
        fh.write(json.dumps({
            "site_code": _SITE_CODE_CAS,
            "parent_site_code": None,
            "site_type": 4,
            "site_guid": "00000000-0000-0000-0000-000000000000",
            "sql_server_name": "SQLSRV",
            "sql_database_name": "CM_CAS",
        }) + "\n")
        fh.write(json.dumps({
            "site_code": _SITE_CODE_PRIMARY,
            "parent_site_code": _SITE_CODE_CAS,
            "site_type": 2,
            "site_guid": "11111111-1111-1111-1111-111111111111",
            "sql_server_name": "SQLSRV",
            "sql_database_name": "CM_PS1",
        }) + "\n")


def test_preprocess_then_convert_emits_real_nodes(tmp_path):
    """Preprocess + convert on real seeded data must emit Computer + SCCM_Site nodes
    and must NOT emit the Stage-0 spike (SPIKE-1 / SCCM_Spike)."""
    raw = tmp_path / "raw"
    _seed_raw(raw)
    db = tmp_path / "lookup.duckdb"
    graph = tmp_path / "graph"

    def run(*args):
        return subprocess.run(
            [sys.executable, "-m", "openhound", *args],
            capture_output=True,
            text=True,
        )

    # --- preprocess ---
    pre = run("preprocess", "sccm", str(raw), str(db))
    assert pre.returncode == 0, (
        f"preprocess failed (rc={pre.returncode}):\n{pre.stderr}"
    )

    # --- convert ---
    conv = run("convert", "sccm", str(raw / "sccm"), str(graph), "--lookup-file", str(db))
    assert conv.returncode == 0, (
        f"convert failed (rc={conv.returncode}):\n{conv.stderr}"
    )

    # --- collect all graph output ---
    nodes, edges = [], []
    for f in graph.glob("*.json"):
        doc = json.loads(f.read_text())
        nodes += doc["graph"]["nodes"]
        edges += doc["graph"]["edges"]

    node_ids = [n["id"] for n in nodes]
    node_kinds = [kind for n in nodes for kind in n.get("kinds", [])]
    edge_kinds = [e["kind"] for e in edges]

    # Computer node from the seeded adminservice_r_system row must appear.
    assert _COMPUTER_SID in node_ids, (
        f"Expected Computer node {_COMPUTER_SID!r} in output; got node ids: {node_ids}"
    )

    # SCCM_Site node for at least the CAS must appear (site definitions were seeded).
    assert _SITE_CODE_CAS in node_ids, (
        f"Expected SCCM_Site node {_SITE_CODE_CAS!r} in output; got node ids: {node_ids}"
    )

    # Kinds sanity checks.
    assert "Computer" in node_kinds, f"No Computer kind in output; kinds seen: {node_kinds}"
    assert "SCCM_Site" in node_kinds, f"No SCCM_Site kind in output; kinds seen: {node_kinds}"

    # The Stage-0 spike must be gone.
    assert "SPIKE-1" not in node_ids, "Stage-0 spike node SPIKE-1 is still present in output"
    assert "SCCM_Spike" not in edge_kinds, "Stage-0 spike edge SCCM_Spike is still present in output"
