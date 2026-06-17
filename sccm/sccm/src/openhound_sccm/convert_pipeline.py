# src/openhound_sccm/convert_pipeline.py
"""Convert-time pipeline (Convert2-Read-DB): read node_* tables and graph_edges from the preproc
DuckDB and emit them as OpenGraph nodes/edges.

The framework's built-in convert reader only globs JSONL from the bucket, so a
coalesced DuckDB table can't be iterated by it. We run our own dlt pipeline that reads
DuckDB directly via the open lookup connection -> opengraph_file. See
docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md §4.
"""
import logging
from pathlib import Path

import dlt
from openhound.destinations.opengraph.destination import opengraph_file

from .lookup import SCCMLookup

logger = logging.getLogger(__name__)


def _spike_node(row: dict) -> dict:
    """Stage-0 raw node shape (Stage 1+ replaces with a typed model's as_node)."""
    name = row.get("name") or row["id"]
    return {
        "id": row["id"],
        "kinds": ["SCCM_Spike", "Base"],
        "properties": {"name": name, "displayname": name, "environmentid": "sccm-spike"},
    }


def _spike_edge(row: dict) -> dict:
    """Stage-0 raw edge shape (Stage 1+ replaces with a typed model's edges)."""
    return {
        "kind": row["kind"],
        "start": {"match_by": "id", "value": row["start_id"]},
        "end": {"match_by": "id", "value": row["end_id"]},
        "properties": {"composed": False},
    }


def emit_graph_from_duckdb(
    lookup: SCCMLookup,
    output_path,
    source_kind: str,
    node_tables: list[str] | None = None,
    edge_table: str = "graph_edges",
) -> None:
    """Read node/edge tables from the lookup DuckDB and write OpenGraph JSON to output_path."""
    out = Path(output_path)
    # The opengraph_file destination opens files without creating the dir, and this runs
    # before the framework would create output_path — so make it ourselves.
    out.mkdir(parents=True, exist_ok=True)
    node_tables = node_tables or ["node_spike"]

    @dlt.resource(name="sccm_nodes")
    def nodes():
        for table in node_tables:
            for row in lookup.table_rows(table):
                yield {"graph": {"entity_type": "node", "content": _spike_node(row)}}

    @dlt.resource(name="sccm_edges")
    def edges():
        for row in lookup.table_rows(edge_table):
            # Edge content is a LIST: the destination does edges.extend(content).
            yield {"graph": {"entity_type": "edge", "content": [_spike_edge(row)]}}

    pipeline = dlt.pipeline(
        pipeline_name="sccm_convert_graph",
        dataset_name="sccm",
        destination=opengraph_file(output_path=str(out), source_kind=source_kind),
    )
    pipeline.run([nodes(), edges()])
    logger.info("Convert2-Read-DB convert pipeline wrote OpenGraph files to %s", out)
