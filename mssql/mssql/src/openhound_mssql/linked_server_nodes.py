"""Preproc-derived ``linked_server_targets`` table (Stage 7b) — the foreign
linked-server *stub* ``MSSQL_Server`` nodes the LinkedTo/LinkedAsAdmin edges point
at, plus the self-reference flags the primary server node carries.

When a SQL Server has a linked server pointing at a DIFFERENT host (e.g. ps1-db's
real ``CAS-DB.MAYYHEM.COM`` link), Go emits a minimal stub ``MSSQL_Server`` node
for that foreign target so the LinkedTo edge connects two server *nodes* rather
than dangling at a bare hostname (``collector.generateOutput`` linked-node loop,
``collector.go`` lines 2488-2527). The stub carries only ``name`` (the data source
truncated at the first ``\\``/``,``/``:``), ``isLinkedServerTarget=true`` and
``hasLinksFromServers=[<localServerOID>]``, plus the server icon. The foreign id is
the ``<computerSID>:<port>`` we resolved at collect time
(``collection/ad_resolve.resolve_data_source_to_sid``).

``build_linked_server_targets(con, schema, server_oid)`` scans the
``linked_server_flags`` table (already carries the collect-resolved
``resolved_target`` / ``resolved_source`` ids) and writes one deduped row per
foreign endpoint that is NOT this server's own OID. The convert asset
(``models/linked_server_node.py``) then emits each row as a stub node.

Self-reference (Go ``createServerNode`` lines 2698-2711): when a link's
``resolved_target`` is the server's OWN OID (the loopback links), the PRIMARY
server node — not a stub — gets ``isLinkedServerTarget=true`` +
``hasLinksFromServers=[<serverOID>]``. We surface that as a one-row
``server_link_self`` table the ``MSSQLServer`` asset reads via ``self._lookup``.
"""
from __future__ import annotations

import logging
from typing import Optional

import duckdb

from .kinds import nodes as nk

logger = logging.getLogger(__name__)

# Columns for the per-stub-node table (id + the three stub properties).
_TARGET_COLUMNS = [
    ("id", "VARCHAR"),
    ("name", "VARCHAR"),
    ("hasLinksFromServers", "VARCHAR[]"),
    ("isLinkedServerTarget", "BOOLEAN"),
]


def _link_node_name(data_source: str) -> str:
    """Stub node display name: the data source up to the first ``\\``/``,``/``:``.

    Mirrors Go ``generateOutput`` (``strings.IndexAny(name, "\\,:")``): a bare host
    keeps its full name (e.g. ``CAS-DB.MAYYHEM.COM``); ``HOST\\INSTANCE`` /
    ``HOST,1433`` are truncated to ``HOST``.
    """
    for i, ch in enumerate(data_source):
        if ch in "\\,:" and i > 0:
            return data_source[:i]
    return data_source


def build_linked_server_targets(
    con: duckdb.DuckDBPyConnection, schema: str, server_oid: Optional[str]
) -> None:
    """Build the ``linked_server_targets`` + ``server_link_self`` derived tables.

    Reads ``linked_server_flags``; for each distinct resolved endpoint id (target
    OR chained source) that is NOT this server's own OID, emits one deduped stub
    row. Also records whether ANY link resolves back to this server (the primary
    node's self-reference flag). Always (re)creates both tables — empty when there
    are no linked servers — so the convert asset's read always binds.
    """
    target_rows: list[tuple] = []
    seen: set[str] = set()
    self_referenced = False

    if not _table_exists(con, schema, "linked_server_flags"):
        logger.warning("linked_server_targets: no linked_server_flags table; building empty")
        _create_target_table(con, schema, target_rows)
        _create_self_table(con, schema, self_referenced, server_oid)
        return

    rows = _fetch_all(
        con,
        f"SELECT resolved_target, resolved_source, data_source, source_server "
        f"FROM {schema}.linked_server_flags",
    )
    server_oid = server_oid or ""
    for r in rows:
        target = (r.get("resolved_target") or "").strip()
        source = (r.get("resolved_source") or "").strip()
        data_source = r.get("data_source") or ""
        source_server = r.get("source_server") or ""

        # A target that is THIS server's own OID is the loopback self-reference: it
        # belongs on the primary node, not a stub (Go createServerNode merge).
        if target == server_oid:
            self_referenced = True
        elif target:
            _add_stub(target_rows, seen, target, _link_node_name(data_source), server_oid)

        # A chained source that is a DIFFERENT, resolved SQL Server also needs a stub
        # node (it is the source of the reverse LinkedTo edge). Skip the server's own
        # OID and any unresolved "LinkedServer:" fallback (not a real node id).
        if source and source != server_oid and not source.startswith("LinkedServer:"):
            _add_stub(target_rows, seen, source, _link_node_name(source_server), server_oid)

    _create_target_table(con, schema, target_rows)
    _create_self_table(con, schema, self_referenced, server_oid)
    logger.info(
        "transforms: linked_server_targets built (%d stub node(s), self_referenced=%s) for server_oid=%s",
        len(target_rows), self_referenced, server_oid,
    )


def _add_stub(rows: list[tuple], seen: set[str], node_id: str, name: str, server_oid: str) -> None:
    """Append one stub-node row, deduped by id (first writer wins, like Go)."""
    if not node_id or node_id in seen:
        return
    seen.add(node_id)
    rows.append((node_id, name, [server_oid] if server_oid else [], True))


# ---------------------------------------------------------------------------
# Table writers
# ---------------------------------------------------------------------------
def _create_target_table(con: duckdb.DuckDBPyConnection, schema: str, rows: list[tuple]) -> None:
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    coldefs = ", ".join(f'"{n}" {t}' for n, t in _TARGET_COLUMNS)
    con.execute(f"CREATE OR REPLACE TABLE {schema}.linked_server_targets ({coldefs})")
    if rows:
        ph = ", ".join(["?"] * len(_TARGET_COLUMNS))
        con.executemany(f"INSERT INTO {schema}.linked_server_targets VALUES ({ph})", rows)


def _create_self_table(
    con: duckdb.DuckDBPyConnection, schema: str, self_referenced: bool, server_oid: Optional[str]
) -> None:
    """One-row table the MSSQLServer asset reads for the self-reference flag."""
    con.execute(f"CREATE SCHEMA IF NOT EXISTS {schema}")
    con.execute(
        f'CREATE OR REPLACE TABLE {schema}.server_link_self '
        f'("server_oid" VARCHAR, "isLinkedServerTarget" BOOLEAN, "hasLinksFromServers" VARCHAR[])'
    )
    if self_referenced and server_oid:
        con.execute(
            f"INSERT INTO {schema}.server_link_self VALUES (?, ?, ?)",
            [server_oid, True, [server_oid]],
        )


# ---------------------------------------------------------------------------
# Helpers (kept standalone, mirroring ad_nodes.py)
# ---------------------------------------------------------------------------
def _table_exists(con: duckdb.DuckDBPyConnection, schema: str, table: str) -> bool:
    try:
        n = con.execute(
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = ? AND table_name = ?",
            [schema, table],
        ).fetchone()
        return bool(n and n[0])
    except duckdb.Error:
        return False


def _fetch_all(con: duckdb.DuckDBPyConnection, sql: str) -> list[dict]:
    try:
        cur = con.execute(sql)
    except duckdb.Error as err:
        logger.warning("linked_server_targets query failed: %s", err)
        return []
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


__all__ = ["build_linked_server_targets", "ICON"]

# The server icon Go stamps on the stub node (collector.go createServerNode /
# the linked-node loop): font-awesome "server" #42b9f5.
ICON = nk.ICONS[nk.SERVER]
