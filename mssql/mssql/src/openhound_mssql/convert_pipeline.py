"""Convert-time pipeline (convert-reads-DuckDB): read the raw tables from the
preproc DuckDB and emit them as OpenGraph nodes/edges.

The framework's built-in convert reader (``openhound.sources.opengraph.source``)
only globs raw JSONL out of the collection bucket, so it cannot iterate the
*derived* lookup tables ``transforms.py`` built in preproc. MSSQL nodes need those
derived tables for enrichment (effective high-priv, role closures, principal
maps), so — exactly like the SCCM extension — we run our own ``dlt`` pipeline that
reads DuckDB directly through the open lookup connection and writes via
``opengraph_file``. ``@app.convert`` (main.py) then hands the framework a no-op
source so ``Converter.run`` finds no models and does nothing. ``opengraph_file``
appends uniquely-numbered files, so the two pipelines never collide.

Each *spec* is a ``(table_name, AssetClass)`` pair. For every row of the raw table
the asset model is instantiated (``AssetClass(**row)``), the read-only
:class:`~openhound_mssql.lookup.MSSQLLookup` is injected as ``_lookup`` so
``as_node`` / ``edges`` can enrich from the derived tables, and its ``as_node`` /
``edges`` produce the OpenGraph content. Mirrors
``sccm/sccm/src/openhound_sccm/convert_pipeline.py``.
"""
from __future__ import annotations

import logging
from collections.abc import Callable, Iterable
from dataclasses import asdict
from pathlib import Path

import dlt
from openhound.destinations.opengraph.destination import opengraph_file

from .lookup import MSSQLLookup

logger = logging.getLogger(__name__)


def emit_graph_from_duckdb(
    lookup: MSSQLLookup,
    output_path,
    source_kind: str,
    node_specs: list[tuple[str, type]] | None = None,
    edge_specs: list[tuple[str, type]] | None = None,
    edge_emitter: Callable[[MSSQLLookup], Iterable] | None = None,
) -> None:
    """Read node/edge rows from the lookup DuckDB and write OpenGraph JSON.

    *node_specs* / *edge_specs* are lists of ``(table_name, AssetClass)`` pairs.
    For each row in each table the asset is instantiated with the row dict, given
    the lookup, and its ``as_node`` / ``edges`` are read to produce content.

    *edge_emitter* is an optional standalone edge producer: a callable taking the
    *lookup* and returning an iterable of framework ``Edge`` objects. Unlike the
    per-row *edge_specs* models, it derives edges by cross-referencing many tables
    at once (Stage 6's :func:`openhound_mssql.edges.derive_edges`, the port of Go
    ``createEdges``). Its edges are serialized into the same edge stream.

    Passing empty/None for all three produces a valid-but-empty OpenGraph output
    (useful for plumbing tests).
    """
    out = Path(output_path)
    # opengraph_file opens files without creating the directory, and this runs
    # before the framework would create output_path — so create it ourselves.
    out.mkdir(parents=True, exist_ok=True)

    node_specs = node_specs or []
    edge_specs = edge_specs or []

    @dlt.resource(name="mssql_nodes")
    def nodes():
        for table, model in node_specs:
            emitted = 0
            # A model may declare PROPERTY_KEY_REMAP to rename specific serialized
            # property keys at emit time. This is how the MSSQL_Server node emits
            # the CVE-2025-49758 keys with HYPHENS (`isVulnerableToCVE-2025-49758`,
            # `CVE-2025-49758_patchKB`, ...) even though graph.py must declare them
            # with underscores (hyphens aren't valid Python identifiers) — D11
            # caveat, spec §7.
            remap: dict[str, str] = getattr(model, "PROPERTY_KEY_REMAP", {})
            for row in lookup.table_rows(table):
                obj = model(**row)
                obj._lookup = lookup
                node = obj.as_node
                if node is not None:
                    emitted += 1
                    content = asdict(node)
                    if remap:
                        _remap_property_keys(content, remap)
                    yield {"graph": {"entity_type": "node", "content": content}}
                else:
                    # as_node returns None for rows that can't be keyed (no id,
                    # no server context, ...); the model logs internally.
                    logger.debug(
                        "emit_graph_from_duckdb: %s row produced no node (table=%r)",
                        model.__name__, table,
                    )
            logger.info("convert: emitted %d node(s) from %s via %s", emitted, table, model.__name__)

    @dlt.resource(name="mssql_edges")
    def edges():
        # Per-row edge models (none in Stage 6; reserved for future per-table edges).
        for table, model in edge_specs:
            for row in lookup.table_rows(table):
                obj = model(**row)
                obj._lookup = lookup
                # Edge content is a LIST: the destination does edges.extend(content).
                parts = [asdict(e) for e in obj.edges]
                if parts:
                    yield {"graph": {"entity_type": "edge", "content": parts}}
                else:
                    logger.debug(
                        "emit_graph_from_duckdb: %s row produced no edges (table=%r)",
                        model.__name__, table,
                    )

        # Standalone edge emitter (Stage 6: server/database edge derivation). Each
        # yielded Edge is wrapped individually so the destination's edges.extend
        # appends one edge at a time — the per-edge JSON is what downstream dedup
        # keys on (spec §7).
        if edge_emitter is not None:
            emitted = 0
            for edge in edge_emitter(lookup):
                emitted += 1
                yield {"graph": {"entity_type": "edge", "content": [asdict(edge)]}}
            logger.info("convert: emitted %d edge(s) via %s", emitted,
                        getattr(edge_emitter, "__name__", repr(edge_emitter)))

    pipeline = dlt.pipeline(
        pipeline_name="mssql_convert_graph",
        dataset_name="mssql",
        destination=opengraph_file(output_path=str(out), source_kind=source_kind),
    )
    pipeline.run([nodes(), edges()])
    logger.info("convert: convert-reads-DuckDB pipeline wrote OpenGraph files to %s", out)


def _remap_property_keys(node_content: dict, remap: dict[str, str]) -> None:
    """Rename keys inside ``node_content["properties"]`` per *remap* (in place).

    Used for the CVE-2025-49758 hyphenated-key fixup on the server node (see the
    call site). Each ``old -> new`` entry moves the value from the underscore key
    to the hyphenated key. A missing old key is skipped silently (the property may
    legitimately be absent for a given row).
    """
    props = node_content.get("properties")
    if not isinstance(props, dict):
        # Defensive: properties should always be a dict after asdict.
        logger.warning("_remap_property_keys: node properties missing/not a dict; skipping remap")
        return
    for old_key, new_key in remap.items():
        if old_key in props:
            props[new_key] = props.pop(old_key)


__all__ = ["emit_graph_from_duckdb"]
