import zipfile
from pathlib import Path

from openhound_collector_common.bloodhound.zip_bundle import bundle_graph_dir


def test_bundles_only_json_files(tmp_path):
    gdir = tmp_path / "graph"
    gdir.mkdir()
    (gdir / "sccm_nodes-1.json").write_text('{"graph": {}}')
    (gdir / "sccm_edges-1.json").write_text('{"graph": {}}')
    (gdir / "notes.txt").write_text("ignore me")

    out = bundle_graph_dir(gdir, tmp_path / "out.zip")
    assert out is not None and out.exists()
    with zipfile.ZipFile(out) as zf:
        names = sorted(zf.namelist())
    assert names == ["sccm_edges-1.json", "sccm_nodes-1.json"]


def test_returns_none_when_no_json(tmp_path):
    gdir = tmp_path / "graph"
    gdir.mkdir()
    (gdir / "notes.txt").write_text("x")
    assert bundle_graph_dir(gdir, tmp_path / "out.zip") is None


def test_returns_none_when_dir_missing(tmp_path):
    assert bundle_graph_dir(tmp_path / "nope", tmp_path / "out.zip") is None
