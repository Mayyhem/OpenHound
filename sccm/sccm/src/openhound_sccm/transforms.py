# src/openhound_sccm/transforms.py
"""DuckDB transforms for the SCCM collector's preproc phase.

Stage 0: a self-contained spike that proves the preproc -> convert (Convert2-Read-DB) path end to
end. Builds one node row and one edge row from literal SQL (no dependency on collected
data) so `convert` can read them back from DuckDB. Real coalescing SQL (node_* tables,
the full graph_edges UNION) is added in Stage 1+.
See docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md
"""
import logging

import duckdb

logger = logging.getLogger(__name__)


def _build_spike(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Create one node row and one edge row so the Convert2-Read-DB pipeline has something to emit."""
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_spike AS "
        "SELECT 'SPIKE-1' AS id, 'spike' AS name"
    )
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges AS "
        "SELECT 'SPIKE-1' AS start_id, 'SPIKE-1' AS end_id, 'SCCM_Spike' AS kind"
    )
    logger.info("Stage-0 spike tables built in schema %r", schema)


def transforms(con: duckdb.DuckDBPyConnection, schema: str = "sccm") -> None:
    """Top-level transform entrypoint (registered via @app.preproc(transformer=transforms))."""
    _build_spike(con, schema)
