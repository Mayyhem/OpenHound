"""Unit tests for the MSSQLHound output adapter (`openhound_mssql.output_adapter`).

These exercise the pure-Python bridge that reshapes OpenHound's convert output
into the MSSQLHound envelope the existing validators read (design spec D6, §7):

* the envelope carries the right ``$schema`` and ``metadata.source_kind``,
* nodes and edges survive the merge with their property bags intact (D11),
* each edge endpoint is normalized from our ``{"match_by":"id","value":X}`` down to
  Go's ``{"value":X}`` (writer.go ``EdgeEndpoint`` has only ``value``),
* duplicate edges are collapsed like ``StreamingWriter.WriteEdge``,
* the ``.zip`` form contains the JSON for the PS1 ``-InputFile`` validator.

A final test, run only when the real convert output produced by a live pipeline
exists, adapts that file and checks node count + a couple of exact property names.
It copies the file into its own tmp dir first so it never touches the shared
working directory another agent may be using.
"""
from __future__ import annotations

import json
import shutil
import zipfile
from pathlib import Path

import pytest

from openhound_mssql import output_adapter
from openhound_mssql.output_adapter import (
    SCHEMA_URL,
    to_mssqlhound_json,
    to_mssqlhound_zip,
)

# The real convert output an earlier live run produced (read-only here).
_REAL_CONVERT_FILE = Path(
    r"C:/Users/domainadmin/AppData/Local/Temp/oh-mssql-work/out/mssql_nodes-1.json"
)


def _write_graph_file(directory: Path, name: str, nodes: list, edges: list) -> Path:
    """Write a synthetic ``{graph:{nodes,edges}}`` convert file and return its path."""
    path = directory / name
    path.write_text(
        json.dumps({"graph": {"nodes": nodes, "edges": edges}}),
        encoding="utf-8",
    )
    return path


def _synthetic_dir(tmp_path: Path) -> Path:
    """Create a convert output dir with one nodes file and one edges file.

    Edge endpoints intentionally use the two shapes our convert output produces:
    ``start`` as the full ``{"match_by":"id","value":...}`` and ``end`` as a bare
    ``{"value":...}`` — both must normalize to ``{"value":...}``.
    """
    out = tmp_path / "out"
    out.mkdir()
    _write_graph_file(
        out,
        "mssql_nodes-1.json",
        nodes=[
            {
                "id": "A",
                "kinds": ["MSSQL_Server"],
                "properties": {"name": "srvA", "isMixedModeAuthEnabled": True},
                "icon": {"type": "font-awesome", "name": "server", "color": "#42b9f5"},
            },
            {
                "id": "B",
                "kinds": ["MSSQL_Login"],
                "properties": {"name": "loginB", "principalId": 5},
            },
        ],
        edges=[],
    )
    _write_graph_file(
        out,
        "mssql_edges-1.json",
        nodes=[],
        edges=[
            {
                "kind": "MSSQL_HasLogin",
                "start": {"match_by": "id", "value": "A"},
                "end": {"value": "B"},
                "properties": {"traversable": True, "general": "has login"},
            }
        ],
    )
    return out


def test_envelope_schema_and_metadata(tmp_path: Path) -> None:
    out = _synthetic_dir(tmp_path)
    envelope = to_mssqlhound_json(out)

    assert envelope["$schema"] == SCHEMA_URL
    assert envelope["metadata"] == {"source_kind": "MSSQL_Base"}
    assert set(envelope["graph"].keys()) == {"nodes", "edges"}


def test_custom_source_kind(tmp_path: Path) -> None:
    out = _synthetic_dir(tmp_path)
    envelope = to_mssqlhound_json(out, source_kind="MSSQL_Custom")
    assert envelope["metadata"]["source_kind"] == "MSSQL_Custom"


def test_nodes_preserved_with_properties(tmp_path: Path) -> None:
    out = _synthetic_dir(tmp_path)
    nodes = to_mssqlhound_json(out)["graph"]["nodes"]

    assert len(nodes) == 2
    by_id = {n["id"]: n for n in nodes}
    assert by_id["A"]["kinds"] == ["MSSQL_Server"]
    # Property names are passed through verbatim (D11 — no renaming).
    assert by_id["A"]["properties"]["isMixedModeAuthEnabled"] is True
    assert by_id["B"]["properties"]["principalId"] == 5
    # Icon (an optional node field) survives.
    assert by_id["A"]["icon"]["name"] == "server"


def test_edge_endpoints_normalized_to_value_only(tmp_path: Path) -> None:
    out = _synthetic_dir(tmp_path)
    edges = to_mssqlhound_json(out)["graph"]["edges"]

    assert len(edges) == 1
    edge = edges[0]
    # start was {"match_by":"id","value":"A"} -> must drop match_by.
    assert edge["start"] == {"value": "A"}
    assert "match_by" not in edge["start"]
    # end was already {"value":"B"} -> unchanged.
    assert edge["end"] == {"value": "B"}
    # kind + properties preserved verbatim.
    assert edge["kind"] == "MSSQL_HasLogin"
    assert edge["properties"]["general"] == "has login"
    assert edge["properties"]["traversable"] is True


def test_edges_merged_across_files(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write_graph_file(
        out,
        "mssql_edges-1.json",
        nodes=[],
        edges=[{"kind": "MSSQL_Owns", "start": {"value": "A"}, "end": {"value": "B"}}],
    )
    _write_graph_file(
        out,
        "mssql_edges-2.json",
        nodes=[],
        edges=[{"kind": "MSSQL_MemberOf", "start": {"value": "B"}, "end": {"value": "C"}}],
    )
    edges = to_mssqlhound_json(out)["graph"]["edges"]
    kinds = sorted(e["kind"] for e in edges)
    assert kinds == ["MSSQL_MemberOf", "MSSQL_Owns"]


def test_duplicate_edges_deduped(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    # Same edge in two files, plus a differing-properties variant that must survive
    # (mirrors LinkedTo edges that share start/end/kind but differ in properties).
    dup = {
        "kind": "MSSQL_LinkedTo",
        "start": {"match_by": "id", "value": "A"},
        "end": {"value": "B"},
        "properties": {"localLogin": "sa"},
    }
    variant = {
        "kind": "MSSQL_LinkedTo",
        "start": {"value": "A"},
        "end": {"value": "B"},
        "properties": {"localLogin": "other"},
    }
    _write_graph_file(out, "mssql_edges-1.json", nodes=[], edges=[dup, variant])
    _write_graph_file(out, "mssql_edges-2.json", nodes=[], edges=[dict(dup)])

    edges = to_mssqlhound_json(out)["graph"]["edges"]
    # The two identical copies of `dup` collapse to one; the property variant stays.
    assert len(edges) == 2
    logins = sorted(e["properties"]["localLogin"] for e in edges)
    assert logins == ["other", "sa"]


def test_non_graph_files_ignored(tmp_path: Path) -> None:
    out = _synthetic_dir(tmp_path)
    # A stray JSON without a graph object must not break the merge.
    (out / "schema.json").write_text(json.dumps({"relationship_kinds": []}), encoding="utf-8")
    envelope = to_mssqlhound_json(out)
    assert len(envelope["graph"]["nodes"]) == 2


def test_empty_dir_yields_empty_graph(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    envelope = to_mssqlhound_json(out)
    assert envelope["graph"]["nodes"] == []
    assert envelope["graph"]["edges"] == []
    assert envelope["metadata"]["source_kind"] == "MSSQL_Base"


def test_zip_contains_json_envelope(tmp_path: Path) -> None:
    out = _synthetic_dir(tmp_path)
    zip_path = tmp_path / "mssql-bloodhound-20260629.zip"

    returned = to_mssqlhound_zip(out, zip_path, file_name="mssql-graph.json")
    assert returned == zip_path
    assert zip_path.exists()

    with zipfile.ZipFile(zip_path) as zf:
        names = zf.namelist()
        # The graph envelope plus the seed_data.json kind-registration file Go also
        # writes into every zip (collector.go createZipFile).
        assert names == ["mssql-graph.json", "seed_data.json"]
        envelope = json.loads(zf.read("mssql-graph.json"))
        seed = json.loads(zf.read("seed_data.json"))

    # The zipped JSON is the same envelope the Go reader would parse.
    assert envelope["$schema"] == SCHEMA_URL
    assert envelope["metadata"]["source_kind"] == "MSSQL_Base"
    assert len(envelope["graph"]["nodes"]) == 2
    assert envelope["graph"]["edges"][0]["start"] == {"value": "A"}

    # Seed data: identical to MSSQLHound's embedded file (1 IgnoreMe node + 37 edges
    # registering every MSSQL_* edge kind). Matches Go's per-zip node/edge totals.
    assert seed["metadata"]["source_kind"] == "MSSQL"
    assert len(seed["graph"]["nodes"]) == 1
    assert seed["graph"]["nodes"][0]["kinds"] == ["IgnoreMe"]
    assert len(seed["graph"]["edges"]) == 37


def test_zip_creates_parent_dir(tmp_path: Path) -> None:
    out = _synthetic_dir(tmp_path)
    nested = tmp_path / "does" / "not" / "exist" / "out.zip"
    to_mssqlhound_zip(out, nested)
    assert nested.exists()


def test_bare_string_endpoint_wrapped(tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    _write_graph_file(
        out,
        "mssql_edges-1.json",
        nodes=[],
        edges=[{"kind": "MSSQL_Owns", "start": "A", "end": "B"}],
    )
    edge = to_mssqlhound_json(out)["graph"]["edges"][0]
    assert edge["start"] == {"value": "A"}
    assert edge["end"] == {"value": "B"}


@pytest.mark.skipif(
    not _REAL_CONVERT_FILE.exists(),
    reason="real convert output not present (live pipeline not run in this env)",
)
def test_adapts_real_convert_output(tmp_path: Path) -> None:
    """Adapt the real convert output from a live run.

    Copies the file into a private tmp dir first so we never touch the shared
    working directory another agent may be using.
    """
    out = tmp_path / "out"
    out.mkdir()
    shutil.copy(_REAL_CONVERT_FILE, out / _REAL_CONVERT_FILE.name)

    envelope = to_mssqlhound_json(out)
    nodes = envelope["graph"]["nodes"]

    assert len(nodes) > 0, "real convert output should contain nodes"
    kinds = {k for n in nodes for k in n.get("kinds", [])}
    assert "MSSQL_Server" in kinds

    # Exact MSSQLHound property names survive verbatim, including the hyphenated CVE
    # key that isn't a valid Python identifier (D11 / §7 hyphen caveat).
    server = next(n for n in nodes if "MSSQL_Server" in n.get("kinds", []))
    props = server["properties"]
    assert "isMixedModeAuthEnabled" in props
    assert "isVulnerableToCVE-2025-49758" in props

    # Envelope shape is still correct for the validators.
    assert envelope["$schema"] == SCHEMA_URL
    assert envelope["metadata"]["source_kind"] == "MSSQL_Base"


def test_module_logs_use_module_logger() -> None:
    # Sanity: the module exposes a logger named for itself (project logging rule).
    assert output_adapter.logger.name == "openhound_mssql.output_adapter"
