# src/openhound_sccm/convert_pipeline.py
"""Convert-time pipeline (Convert2-Read-DB): read node_* tables and graph_edges from the preproc
DuckDB and emit them as OpenGraph nodes/edges.

The framework's built-in convert reader only globs JSONL from the bucket, so a
coalesced DuckDB table can't be iterated by it. We run our own dlt pipeline that reads
DuckDB directly via the open lookup connection -> opengraph_file. See
docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md §4.

Stage 1+ replaces the Stage-0 spike shapers with typed models driven by node_specs
and edge_specs. Each spec is a (table_name, ModelClass) pair; for every row the model
is instantiated, the lookup is injected, and as_node / edges produce the OpenGraph
content.
"""
import logging
from dataclasses import asdict
from pathlib import Path

import dlt
from openhound.destinations.opengraph.destination import opengraph_file

from .lookup import SCCMLookup

logger = logging.getLogger(__name__)


def _without_null_properties(content: dict) -> dict:
    """Drop keys whose value is None from the content's `properties` dict, in place.

    BloodHound's OpenGraph schema accepts a property value of string/number/boolean/array
    but NOT null, so an absent attribute must be omitted entirely rather than emitted as
    JSON null (missing != null is the BloodHound convention). Our models default optional
    attributes to None, and the dataclasses.asdict() + json.dumps path the destination uses
    keeps those as null — unlike the framework's Pydantic exclude_none path — so we prune
    here, the single point every node and edge flows through before being written.
    """
    props = content.get("properties")
    if isinstance(props, dict):
        dropped = [k for k, v in props.items() if v is None]
        if dropped:
            content["properties"] = {k: v for k, v in props.items() if v is not None}
            logger.debug("Omitted null-valued properties before emit: %s", dropped)
    return content


def emit_graph_from_duckdb(
    lookup: SCCMLookup,
    output_path,
    source_kind: str,
    node_specs: list[tuple[str, type]] | None = None,
    edge_specs: list[tuple[str, type]] | None = None,
) -> None:
    """Read node/edge tables from the lookup DuckDB and write OpenGraph JSON to output_path.

    node_specs and edge_specs are lists of (table_name, ModelClass) pairs. For each
    row in each table, the model is instantiated with the row dict, given access to the
    lookup, and its as_node / edges properties are called to produce OpenGraph content.

    Passing empty lists for both specs produces an empty but valid OpenGraph output
    (useful for testing the pipeline plumbing without real data).
    """
    out = Path(output_path)
    # The opengraph_file destination opens files without creating the dir, and this runs
    # before the framework would create output_path — so make it ourselves.
    out.mkdir(parents=True, exist_ok=True)

    # Default to empty specs so the pipeline always runs cleanly.
    node_specs = node_specs or []
    edge_specs = edge_specs or []

    @dlt.resource(name="sccm_nodes")
    def nodes():
        for table, model in node_specs:
            for row in lookup.table_rows(table):
                obj = model(**row)
                obj._lookup = lookup
                node = obj.as_node
                if node is not None:
                    content = _without_null_properties(asdict(node))
                    yield {"graph": {"entity_type": "node", "content": content}}
                else:
                    # as_node returns None for rows that can't be keyed (no SID, etc.).
                    # The model logs a warning internally; nothing to emit here.
                    logger.debug(
                        "emit_graph_from_duckdb: %s row produced no node (table=%r)",
                        model.__name__,
                        table,
                    )

    @dlt.resource(name="sccm_edges")
    def edges():
        for table, model in edge_specs:
            for row in lookup.table_rows(table):
                obj = model(**row)
                obj._lookup = lookup
                # Edge content is a LIST: the destination does edges.extend(content).
                parts = [_without_null_properties(asdict(e)) for e in obj.edges]
                if parts:
                    yield {"graph": {"entity_type": "edge", "content": parts}}
                else:
                    logger.debug(
                        "emit_graph_from_duckdb: %s row produced no edges (table=%r)",
                        model.__name__,
                        table,
                    )

    pipeline = dlt.pipeline(
        pipeline_name="sccm_convert_graph",
        dataset_name="sccm",
        destination=opengraph_file(output_path=str(out), source_kind=source_kind),
    )
    pipeline.run([nodes(), edges()])
    logger.info("Convert2-Read-DB convert pipeline wrote OpenGraph files to %s", out)
