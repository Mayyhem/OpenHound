# src/openhound_sccm/convert_pipeline_test.py
"""Tests for emit_graph_from_duckdb with the Stage 1 node_specs/edge_specs signature.

Seeds a node_computer row in DuckDB, runs the pipeline through ComputerNode,
and asserts a Computer node comes out the other end. This replaces the Stage-0
spike-based test now that the convert pipeline drives typed models.
"""
import json
import duckdb
from openhound_sccm.lookup import SCCMLookup
from openhound_sccm.convert_pipeline import emit_graph_from_duckdb
from openhound_sccm.models.computer import ComputerNode


def _db_with_computer(tmp_path):
    """Create a lookup DuckDB pre-seeded with one node_computer row."""
    path = tmp_path / "lookup.duckdb"
    con = duckdb.connect(str(path))
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # A minimal node_computer row — only the columns ComputerNode cares about.
    con.execute(
        "CREATE TABLE sccm.node_computer AS SELECT "
        "'S-1-5-21-1-2-3-1104' AS sid, "
        "'HOST1' AS name, "
        "'host1.lab' AS dnshostname, "
        "'HOST1$' AS sam_account_name, "
        "['SMS Provider'] AS site_system_roles, "
        "['7@PS1'] AS resource_ids, "
        "true AS sccm_infra, "
        "'GUID:abc' AS sms_unique_identifier, "
        "true AS smb_signing_required, "
        "false AS sccm_has_client_remote_control_spn, "
        "false AS network_boot_server, "
        "NULL AS disable_loopback_check, "
        "NULL AS restrict_receiving_ntlm_traffic, "
        "NULL AS sccm_client_certificate_required, "
        "NULL AS sccm_hosts_content_library, "
        "NULL AS sccm_is_pxe_support_enabled"
    )
    con.close()
    return str(path)


def test_emit_writes_computer_node(tmp_path):
    """The pipeline must emit one Computer node for the seeded node_computer row."""
    client = duckdb.connect(_db_with_computer(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    out = tmp_path / "graph"

    emit_graph_from_duckdb(
        lookup,
        out,
        "Kind",
        node_specs=[("node_computer", ComputerNode)],
        edge_specs=[],
    )

    nodes, edges = [], []
    for f in out.glob("*.json"):
        doc = json.loads(f.read_text())
        nodes += doc["graph"]["nodes"]
        edges += doc["graph"]["edges"]

    assert len(nodes) == 1, f"Expected 1 node, got {len(nodes)}: {nodes}"
    node = nodes[0]
    assert node["id"] == "S-1-5-21-1-2-3-1104"
    assert "Computer" in node["kinds"]
    assert "Base" in node["kinds"]
    assert node["properties"]["environmentid"] == "S-1-5-21-1-2-3"
    # No edges emitted — ComputerNode.edges is always empty in Stage 1.
    assert edges == []


def test_emit_omits_null_properties(tmp_path):
    """Properties with no value must be omitted, not written as JSON null.

    BloodHound's OpenGraph property schema is an anyOf over string/number/boolean/array
    and rejects null, so a single null-valued property fails the whole file's schema
    validation on ingest. The seeded node_computer row leaves disable_loopback_check,
    restrict_receiving_ntlm_traffic, sccm_client_certificate_required, etc. NULL — those
    optional attributes must be absent from the emitted properties, never present as null.
    """
    client = duckdb.connect(_db_with_computer(tmp_path), read_only=True)
    lookup = SCCMLookup(client)
    out = tmp_path / "graph"

    emit_graph_from_duckdb(
        lookup,
        out,
        "Kind",
        node_specs=[("node_computer", ComputerNode)],
        edge_specs=[],
    )

    props = None
    for f in out.glob("*.json"):
        doc = json.loads(f.read_text())
        for node in doc["graph"]["nodes"]:
            props = node["properties"]

    assert props is not None, "expected one emitted node"
    null_keys = [k for k, v in props.items() if v is None]
    assert null_keys == [], f"null-valued properties must be omitted, found: {null_keys}"
    # The known-absent (NULL) columns must not appear as keys at all.
    assert "disableLoopbackCheck" not in props
    assert "SCCMClientCertificateRequired" not in props
    # A present value is still emitted.
    assert props["SMBSigningRequired"] is True


def test_emit_empty_specs_produces_no_nodes(tmp_path):
    """Empty node_specs/edge_specs should run without error and produce no graph content."""
    # DB with no tables needed — empty specs skip all table reads.
    path = tmp_path / "empty.duckdb"
    con = duckdb.connect(str(path))
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.close()

    client = duckdb.connect(str(path), read_only=True)
    lookup = SCCMLookup(client)
    out = tmp_path / "graph_empty"

    emit_graph_from_duckdb(lookup, out, "Kind", node_specs=[], edge_specs=[])

    nodes, edges = [], []
    for f in out.glob("*.json"):
        doc = json.loads(f.read_text())
        nodes += doc["graph"]["nodes"]
        edges += doc["graph"]["edges"]

    assert nodes == []
    assert edges == []
