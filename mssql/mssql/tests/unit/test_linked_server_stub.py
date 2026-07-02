"""Unit tests for the Stage-7b foreign linked-server *stub* node derivation
(`openhound_mssql.linked_server_nodes`).

When a SQL Server has a linked server pointing at a DIFFERENT host (e.g. ps1-db's
real `CAS-DB.MAYYHEM.COM` link), the Go binary emits a minimal stub `MSSQL_Server`
node for that foreign target so the LinkedTo edge connects two server *nodes*. A
linked server that resolves back to the server's OWN OID (the manufactured loopback
links) is instead recorded as a self-reference flag on the PRIMARY server node.
These tests pin both behaviors over an in-memory DuckDB, mirroring the other
`transforms`/`ad_nodes` unit tests.
"""
from __future__ import annotations

import duckdb
import pytest

from openhound_mssql.linked_server_nodes import (
    _link_node_name,
    build_linked_server_targets,
)

SCHEMA = "mssql"
SERVER_OID = "S-1-5-21-1-2-3-1109:1433"          # the collected (primary) server
CASDB_OID = "S-1-5-21-1-2-3-1108:1433"           # a foreign linked-server target


def _con_with_flags(rows: list[dict]) -> duckdb.DuckDBPyConnection:
    """In-memory DuckDB with a `mssql.linked_server_flags` table holding `rows`.

    Only the four columns `build_linked_server_targets` reads are created.
    """
    con = duckdb.connect(":memory:")
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(
        f"CREATE TABLE {SCHEMA}.linked_server_flags "
        f"(resolved_target VARCHAR, resolved_source VARCHAR, "
        f" data_source VARCHAR, source_server VARCHAR)"
    )
    for r in rows:
        con.execute(
            f"INSERT INTO {SCHEMA}.linked_server_flags VALUES (?, ?, ?, ?)",
            [r.get("resolved_target"), r.get("resolved_source"),
             r.get("data_source"), r.get("source_server")],
        )
    return con


def _targets(con) -> list[dict]:
    cur = con.execute(
        f"SELECT id, name, \"hasLinksFromServers\", \"isLinkedServerTarget\" "
        f"FROM {SCHEMA}.linked_server_targets ORDER BY id"
    )
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


def _self_rows(con) -> list[dict]:
    cur = con.execute(f"SELECT * FROM {SCHEMA}.server_link_self")
    cols = [c[0] for c in cur.description]
    return [dict(zip(cols, row)) for row in cur.fetchall()]


# ---------------------------------------------------------------------------
# _link_node_name truncation (Go strings.IndexAny(name, "\\,:"))
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "data_source, expected",
    [
        ("CAS-DB.MAYYHEM.COM", "CAS-DB.MAYYHEM.COM"),  # '.' is not a separator -> kept whole
        ("HOST\\INSTANCE", "HOST"),
        ("HOST,1433", "HOST"),
        ("HOST:1433", "HOST"),
        ("CAS-DB.MAYYHEM.COM\\SQLEXPRESS", "CAS-DB.MAYYHEM.COM"),
        ("", ""),
    ],
)
def test_link_node_name_truncation(data_source, expected):
    assert _link_node_name(data_source) == expected


# ---------------------------------------------------------------------------
# Foreign target -> a stub node row
# ---------------------------------------------------------------------------
def test_foreign_target_becomes_stub():
    con = _con_with_flags([
        {"resolved_target": CASDB_OID, "resolved_source": SERVER_OID,
         "data_source": "CAS-DB.MAYYHEM.COM", "source_server": "ps1-db"},
    ])
    build_linked_server_targets(con, SCHEMA, SERVER_OID)

    targets = _targets(con)
    assert len(targets) == 1
    stub = targets[0]
    assert stub["id"] == CASDB_OID
    assert stub["name"] == "CAS-DB.MAYYHEM.COM"
    assert stub["isLinkedServerTarget"] is True
    assert list(stub["hasLinksFromServers"]) == [SERVER_OID]
    # A foreign target is NOT a self-reference.
    assert _self_rows(con) == []


# ---------------------------------------------------------------------------
# Loopback target == own OID -> self-reference flag, NOT a stub
# ---------------------------------------------------------------------------
def test_loopback_target_sets_self_reference_not_stub():
    con = _con_with_flags([
        {"resolved_target": SERVER_OID, "resolved_source": SERVER_OID,
         "data_source": "ps1-db", "source_server": "ps1-db"},
    ])
    build_linked_server_targets(con, SCHEMA, SERVER_OID)

    # Loopback produces no foreign stub...
    assert _targets(con) == []
    # ...but flags the primary node as a linked-server target.
    self_rows = _self_rows(con)
    assert len(self_rows) == 1
    assert self_rows[0]["server_oid"] == SERVER_OID
    assert self_rows[0]["isLinkedServerTarget"] is True
    assert list(self_rows[0]["hasLinksFromServers"]) == [SERVER_OID]


# ---------------------------------------------------------------------------
# Chained reverse-link source -> its own stub; "LinkedServer:" fallback skipped
# ---------------------------------------------------------------------------
def test_chained_source_stub_and_unresolved_skipped():
    other_oid = "S-1-5-21-1-2-3-2222:1433"
    con = _con_with_flags([
        # A chained reverse link whose source is a different resolved server.
        {"resolved_target": SERVER_OID, "resolved_source": other_oid,
         "data_source": "ps1-db", "source_server": "OTHER-SRV"},
        # An unresolved source must NOT become a node id.
        {"resolved_target": CASDB_OID, "resolved_source": "LinkedServer:nope",
         "data_source": "CAS-DB", "source_server": ""},
    ])
    build_linked_server_targets(con, SCHEMA, SERVER_OID)

    ids = {t["id"] for t in _targets(con)}
    assert other_oid in ids          # chained source got a stub
    assert CASDB_OID in ids          # foreign target got a stub
    assert SERVER_OID not in ids     # own OID is never a stub (loopback target)
    assert not any(i.startswith("LinkedServer:") for i in ids)


# ---------------------------------------------------------------------------
# Dedupe: same target on two rows -> one stub
# ---------------------------------------------------------------------------
def test_duplicate_targets_deduped():
    con = _con_with_flags([
        {"resolved_target": CASDB_OID, "resolved_source": SERVER_OID,
         "data_source": "CAS-DB.MAYYHEM.COM", "source_server": "ps1-db"},
        {"resolved_target": CASDB_OID, "resolved_source": SERVER_OID,
         "data_source": "CAS-DB.MAYYHEM.COM", "source_server": "ps1-db"},
    ])
    build_linked_server_targets(con, SCHEMA, SERVER_OID)
    assert len(_targets(con)) == 1


# ---------------------------------------------------------------------------
# No linked_server_flags table at all -> empty (binds, no error)
# ---------------------------------------------------------------------------
def test_missing_flags_table_builds_empty():
    con = duckdb.connect(":memory:")
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    build_linked_server_targets(con, SCHEMA, SERVER_OID)
    assert _targets(con) == []
    assert _self_rows(con) == []
