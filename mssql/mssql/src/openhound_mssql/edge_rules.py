"""Preproc edge derivation: build the ``graph_edges`` DuckDB table.

This is the preproc-side entry point for Stage 6. It runs inside ``transforms()``
(after the principal maps / role closures / effective-high-priv / fixed-role
tables are built) and reproduces Go ``createEdges`` + ``createFixedRoleEdges`` +
``createServerPermissionEdges`` + ``createDatabasePermissionEdges`` for every
in-scope edge kind, writing one row per edge into ``{schema}.graph_edges``.

Why derive in preproc (not convert): the SCCM extension proved this pattern —
edges live in a derived DuckDB table that convert reads back through the shared
:class:`~openhound_collector_common.graph.graph_edge.GraphEdge` model (one
``("graph_edges", GraphEdge)`` entry in ``EDGE_SPECS``). Moving the per-edge work
to preproc keeps convert a thin read-and-emit pass and keeps the edge set in one
queryable place (project rule: move work to preprocess where it improves
scalability).

The actual per-permission / per-role security logic is NOT re-implemented here:
it already lives, faithfully ported and unit-tested, in
:func:`openhound_mssql.edges.derive.derive_edges`, which yields framework ``Edge``
objects with the full :class:`~openhound_mssql.graph.MSSQLEdgeProperties` bag. We
reuse it verbatim by wrapping the DuckDB connection in a tiny lookup adapter
(:class:`_ConnLookup`) exposing exactly the two methods ``derive_edges`` reads
(``table_rows`` + ``high_priv_principals``), then flatten each yielded ``Edge``
into a ``graph_edges`` row. This guarantees the preproc table and the original
convert-time emitter agree edge-for-edge.

Traversability gating (Go ``createEdge``):

* The base ``traversable`` is the kind's static partition (``kinds/edges.py``,
  which mirrors Go ``IsTraversableEdge``).
* ``--disable-possible-edges`` flips the six possible kinds to non-traversable.
* ``--disable-nontraversable-edges`` DROPS non-traversable edges entirely.

Both flags default OFF (every producible edge is written, carrying its correct
``traversable`` flag) and are read from the ``SOURCES__MSSQL__DISABLE_*`` env the
collect CLI sets — matching how the rest of the extension reads its config.
"""
from __future__ import annotations

import logging
import os
from typing import Iterable, Iterator

import duckdb

from openhound_collector_common.logging import log_context  # noqa: F401  (registers logger.verbose)

from .edges.derive import derive_edges
from .edges.derive_ad import derive_ad_edges
from .kinds import edges as ek

logger = logging.getLogger(__name__)


# graph_edges column schema. start_id/end_id/kind/traversable/collection_source
# are the shared GraphEdge contract; the remaining columns are the MSSQL property
# bag (snake_case in DuckDB per the two-layer rule — the model maps them to the
# CMBP-cased MSSQLEdgeProperties keys at emit). Declared explicitly so the table
# always binds even when no edges are produced. The Stage-7b columns
# (credential_id/proxy_id + the linked-server property bag) are nullable and only
# set on the AD/linked/credential edges.
_GRAPH_EDGES_COLUMNS: list[tuple[str, str]] = [
    ("start_id", "VARCHAR"),
    ("end_id", "VARCHAR"),
    ("kind", "VARCHAR"),
    ("traversable", "BOOLEAN"),
    ("collection_source", "VARCHAR[]"),
    ("general", "VARCHAR"),
    ("windows_abuse", "VARCHAR"),
    ("linux_abuse", "VARCHAR"),
    ("opsec", "VARCHAR"),
    ("references", "VARCHAR"),
    ("composition", "VARCHAR"),
    ("with_grant", "BOOLEAN"),
    ("owner_principal_id", "VARCHAR"),
    # Stage-7b typed props.
    ("credential_id", "VARCHAR"),
    ("proxy_id", "VARCHAR"),
    # Stage-7b linked-server property bag (MSSQL_LinkedTo / MSSQL_LinkedAsAdmin).
    ("local_login", "VARCHAR"),
    ("remote_login", "VARCHAR"),
    ("remote_current_login", "VARCHAR"),
    ("data_source", "VARCHAR"),
    ("link_path", "VARCHAR"),
    ("product", "VARCHAR"),
    ("provider", "VARCHAR"),
    ("data_access", "BOOLEAN"),
    ("rpc_out", "BOOLEAN"),
    ("uses_impersonation", "BOOLEAN"),
    ("remote_is_sysadmin", "BOOLEAN"),
    ("remote_is_security_admin", "BOOLEAN"),
    ("remote_has_control_server", "BOOLEAN"),
    ("remote_has_impersonate_any_login", "BOOLEAN"),
    ("remote_is_mixed_mode", "BOOLEAN"),
]

# The single collection-source tag stamped on every MSSQL edge (provenance the
# entity panel shows; mirrors the SCCM ['SCCM_Invoke-PostProcessing'] tag).
_COLLECTION_SOURCE = ["MSSQL-createEdges"]


# ---------------------------------------------------------------------------
# Entry point (called from transforms())
# ---------------------------------------------------------------------------
def build_graph_edges(con: duckdb.DuckDBPyConnection, schema: str = "mssql") -> None:
    """Derive every in-scope Stage-6 edge and write it into ``{schema}.graph_edges``.

    Always (re)creates the table — even with no source data — so convert's
    ``EDGE_SPECS`` read always binds. Reuses the convert-time
    :func:`openhound_mssql.edges.derive.derive_edges` over a DuckDB-backed lookup
    adapter, applies the ``--disable-*`` gating, and bulk-inserts the rows.

    Args:
        con: DuckDB connection holding the raw + derived tables.
        schema: Schema the tables live in (``mssql``).
    """
    _create_graph_edges_table(con, schema)

    disable_nontraversable = _env_bool("DISABLE_NONTRAVERSABLE_EDGES")
    disable_possible = _env_bool("DISABLE_POSSIBLE_EDGES")
    logger.info(
        "build_graph_edges: disable_nontraversable=%s disable_possible=%s",
        disable_nontraversable, disable_possible,
    )

    lookup = _ConnLookup(con, schema)
    rows = list(_edge_rows(lookup, disable_nontraversable, disable_possible))
    if not rows:
        logger.warning("build_graph_edges: no edges derived (no server data?)")
        return

    placeholders = ", ".join(["?"] * len(_GRAPH_EDGES_COLUMNS))
    con.executemany(
        f"INSERT INTO {schema}.graph_edges VALUES ({placeholders})", rows
    )
    logger.info("build_graph_edges: wrote %d edge row(s) into %s.graph_edges", len(rows), schema)


def _edge_rows(
    lookup: "_ConnLookup",
    disable_nontraversable: bool,
    disable_possible: bool,
) -> Iterator[tuple]:
    """Yield one ``graph_edges`` row tuple per derived edge, after gating.

    Both derivation passes (Stage-6 ``derive_edges`` + Stage-7b
    ``derive_ad_edges``) already stamped each edge's static ``traversable`` flag
    (kind partition). Here we apply the two CLI toggles exactly like Go
    ``createEdge``: possible kinds become non-traversable under
    ``--disable-possible-edges``; non-traversable edges are dropped under
    ``--disable-nontraversable-edges``.
    """
    by_kind: dict[str, int] = {}
    for edge in _chain(derive_edges(lookup), derive_ad_edges(lookup)):
        kind = edge.kind
        props = edge.properties

        traversable = bool(getattr(props, "traversable", False))
        # --disable-possible-edges: possible kinds are flipped non-traversable.
        if disable_possible and kind in ek.POSSIBLE_EDGE_KINDS:
            traversable = False
        # --disable-nontraversable-edges: drop the edge entirely.
        if disable_nontraversable and not traversable:
            continue

        by_kind[kind] = by_kind.get(kind, 0) + 1
        yield (
            edge.start.value,
            edge.end.value,
            kind,
            traversable,
            list(_COLLECTION_SOURCE),
            getattr(props, "general", None),
            getattr(props, "windowsAbuse", None),
            getattr(props, "linuxAbuse", None),
            getattr(props, "opsec", None),
            getattr(props, "references", None),
            getattr(props, "composition", None),
            getattr(props, "withGrant", None),
            getattr(props, "ownerPrincipalID", None),
            # Stage-7b typed props.
            getattr(props, "credentialId", None),
            getattr(props, "proxyId", None),
            # Stage-7b linked-server property bag.
            getattr(props, "localLogin", None),
            getattr(props, "remoteLogin", None),
            getattr(props, "remoteCurrentLogin", None),
            getattr(props, "dataSource", None),
            getattr(props, "path", None),
            getattr(props, "product", None),
            getattr(props, "provider", None),
            getattr(props, "dataAccess", None),
            getattr(props, "rpcOut", None),
            getattr(props, "usesImpersonation", None),
            getattr(props, "remoteIsSysadmin", None),
            getattr(props, "remoteIsSecurityAdmin", None),
            getattr(props, "remoteHasControlServer", None),
            getattr(props, "remoteHasImpersonateAnyLogin", None),
            getattr(props, "remoteIsMixedMode", None),
        )
    if by_kind:
        logger.verbose("build_graph_edges: edge counts by kind: %s",
                       ", ".join(f"{k}={v}" for k, v in sorted(by_kind.items())))


def _chain(*iterables) -> Iterator:
    """Yield from each iterable in turn (Stage-6 then Stage-7b edges)."""
    for it in iterables:
        yield from it


def _create_graph_edges_table(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """(Re)create the empty ``graph_edges`` table with the explicit column shape."""
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    coldefs = ", ".join(f'"{name}" {sqltype}' for name, sqltype in _GRAPH_EDGES_COLUMNS)
    con.execute(f"CREATE OR REPLACE TABLE {schema}.graph_edges ({coldefs})")


# ---------------------------------------------------------------------------
# DuckDB-backed lookup adapter (the two methods derive_edges / _ServerData read)
# ---------------------------------------------------------------------------
class _ConnLookup:
    """Minimal :class:`MSSQLLookup`-shaped view over a DuckDB connection.

    ``derive_edges`` (and the ``_ServerData`` it builds) only ever call two lookup
    methods: ``table_rows(table)`` to stream a raw/derived table and
    ``high_priv_principals(server_oid)`` for the per-principal effective high-priv
    flags. Providing just these keeps the preproc port reusing the exact, tested
    convert-side logic without dragging in the full lookup/cursor machinery.
    """

    def __init__(self, con: duckdb.DuckDBPyConnection, schema: str) -> None:
        self._con = con
        self._schema = schema

    def table_rows(self, table: str) -> Iterable[dict]:
        """Yield each row of ``{schema}.{table}`` as a column-named dict.

        A missing/unreadable table logs and yields nothing so a not-yet-built
        table can't crash the derivation (mirrors ``MSSQLLookup.table_rows``).
        """
        try:
            cur = self._con.cursor()
            cur.execute(f"SELECT * FROM {self._schema}.{table}")
        except duckdb.Error as err:
            logger.warning("edge_rules: table_rows(%r) failed: %s", table, err)
            return
        cols = [c[0] for c in cur.description]
        for row in cur.fetchall():
            yield dict(zip(cols, row))

    def high_priv_principals(self, server_oid: str) -> list[dict]:
        """Per-principal effective-high-priv rows for *server_oid*.

        Reads the ``effective_high_priv`` table transforms built. Empty list when
        the table is missing or the server has no high-priv principals.
        """
        try:
            cur = self._con.cursor()
            cur.execute(
                f"SELECT * FROM {self._schema}.effective_high_priv WHERE server_oid = ?",
                [server_oid],
            )
        except duckdb.Error as err:
            logger.warning("edge_rules: high_priv_principals failed: %s", err)
            return []
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row)) for row in cur.fetchall()]


def _env_bool(suffix: str) -> bool:
    """Read a ``SOURCES__MSSQL__<suffix>`` boolean env var (default False).

    The collect CLI maps ``--disable-*`` flags to these env vars. Edge derivation
    moved to preproc, but the toggles still come from the same env so a run that
    set them at collect time honours them here. Anything other than a truthy
    string is treated as False (flag not set).
    """
    value = os.environ.get(f"SOURCES__MSSQL__{suffix}")
    if value is None:
        return False
    return value.strip().lower() in ("1", "true", "t", "yes", "y")


__all__ = ["build_graph_edges"]
