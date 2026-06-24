# Task C0: Generalise the edge model (`GraphEdge`) + edge-kind constants + traversable allow-list

The Stage 1 edge model `ReplicationEdge` already reads `(start_id, end_id, kind)` from `graph_edges` and emits a generic `Edge` — it isn't really replication-specific. Rename it `GraphEdge`, give it the CMBP traversable flag, add all Stage 2 edge-kind constants, and split the `_graph_edges` builder into an initialiser + a replication-edge builder so later tasks can `INSERT` more kinds into the same table.

**DESIGN NOTE (important):** `graph_edges` stays **3 columns** `(start_id, end_id, kind)` — do NOT add a `properties`/JSON column (DuckDB returns JSON as a string, which would break model validation; edge `collection_source` is deferred/unused). Every edge builder (this task and later) inserts exactly `start_id, end_id, kind`. The only edge property we set is `traversable`, computed by the model from the kind.

**Files:**
- Rename: `models/replication_edge.py` → `models/graph_edge.py` (class `ReplicationEdge` → `GraphEdge`)
- Rename: `models/replication_edge_test.py` → `models/graph_edge_test.py` (replace contents per below)
- Modify: `kinds/edges.py` (add Stage 2 edge-kind constants + `TRAVERSABLE_EDGE_KINDS`)
- Modify: `graph.py` (add `SCCMEdgeProperties`)
- Modify: `transforms.py` (split `_graph_edges` → `_graph_edges_init` + `_edge_replication`; update the `transforms()` call site)
- Modify: `main.py` (`EDGE_SPECS = [("graph_edges", GraphEdge)]`; import `GraphEdge` not `ReplicationEdge`)
- Modify: `models/__init__.py` (export `GraphEdge`, remove `ReplicationEdge`)
- **Grep the repo for any other `ReplicationEdge` references and update them.**

**Interfaces — Produces:** `graph_edges(start_id, end_id, kind)` (unchanged 3-col, now populated by `_edge_replication` + later builders); `GraphEdge(BaseAsset)` whose `edges` yields `Edge(kind, start, end, properties=SCCMEdgeProperties(traversable=kind in TRAVERSABLE_EDGE_KINDS))`.

## Step 1: Add edge-kind constants + traversable set to `kinds/edges.py`
Append (the existing `SCCM_ADMINS_REPLICATED_TO` stays):
```python
# Stage 2 edge kinds
SCCM_IS_MAPPED_TO = "SCCM_IsMappedTo"
SCCM_IS_ASSIGNED = "SCCM_IsAssigned"
SCCM_HAS_MEMBER = "SCCM_HasMember"
SCCM_HAS_CLIENT = "SCCM_HasClient"
SCCM_HAS_PRIMARY_USER = "SCCM_HasPrimaryUser"
SCCM_HAS_CURRENT_USER = "SCCM_HasCurrentUser"
SCCM_HAS_AD_LAST_LOGON_USER = "SCCM_HasADLastLogonUser"
SCCM_HAS_STORED_ACCOUNT = "SCCM_HasStoredAccount"
MEMBER_OF = "MemberOf"
HAS_SESSION = "HasSession"

# CMBP traversable allow-list (ConfigManBearPig.ps1:2216-2249, uncommented entries only).
# Edges whose kind is in this set get properties.traversable = True. Includes future
# (Stage 3-6) kinds so later stages reuse this one source of truth.
TRAVERSABLE_EDGE_KINDS = frozenset({
    "AdminTo", "LocalAdminRequired",
    "CoerceAndRelayToAdminService", "CoerceAndRelayToMSSQL", "CoerceAndRelayNTLMtoSMB",
    "HasSession",
    "MSSQL_Contains", "MSSQL_ControlDB", "MSSQL_ControlServer", "MSSQL_ExecuteOnHost",
    "MSSQL_GetAdminTGS", "MSSQL_GetTGS", "MSSQL_HasLogin", "MSSQL_HostFor",
    "MSSQL_IsMappedTo", "MSSQL_MemberOf",
    "SameHostAs",
    "SCCM_AdminsReplicatedTo", "SCCM_AllPermissions", "SCCM_ApplicationAdministrator",
    "SCCM_AssignAllPermissions", "SCCM_Contains", "SCCM_FullAdministrator",
    "SCCM_HasADLastLogonUser", "SCCM_HasClient", "SCCM_HasCurrentUser",
    "SCCM_HasPrimaryUser", "SCCM_IsMappedTo",
})
```

## Step 2: `SCCMEdgeProperties` in `graph.py`
Add (and add `EdgeProperties` to the existing `from openhound.core.models.entries_dataclass import ...` line — it currently imports `Node, NodeProperties`):
```python
@dataclass
class SCCMEdgeProperties(EdgeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
```

## Step 3: Replace the test file — create `models/graph_edge_test.py` (and delete `models/replication_edge_test.py`)
```python
from openhound_sccm.models.graph_edge import GraphEdge


def test_graph_edge_sets_traversable_from_allowlist():
    e = list(GraphEdge(start_id="A", end_id="B", kind="SCCM_HasClient").edges)[0]
    assert e.kind == "SCCM_HasClient"
    assert e.start.value == "A" and e.end.value == "B"
    assert e.properties.traversable is True


def test_graph_edge_non_traversable_kind():
    e = list(GraphEdge(start_id="A", end_id="B", kind="SCCM_HasMember").edges)[0]
    assert e.properties.traversable is False


def test_graph_edge_drops_incomplete_row():
    assert list(GraphEdge(start_id="A", end_id=None, kind="MemberOf").edges) == []
```

## Step 4: Run — expect failure.
`pytest .../models/graph_edge_test.py -v`

## Step 5: Implement `models/graph_edge.py` (renamed from replication_edge.py)
```python
# src/openhound_sccm/models/graph_edge.py
import logging
from typing import Iterator

from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import Edge, EdgePath
from pydantic import ConfigDict

from ..graph import SCCMEdgeProperties
from ..kinds.edges import TRAVERSABLE_EDGE_KINDS

logger = logging.getLogger(__name__)


class GraphEdge(BaseAsset):
    """One graph_edges row -> one OpenGraph edge of any kind. Endpoints matched by id;
    `traversable` is set from the CMBP allow-list. Never produces a node."""

    model_config = ConfigDict(populate_by_name=True, extra="ignore")

    start_id: str | None = None
    end_id: str | None = None
    kind: str | None = None

    @property
    def as_node(self) -> None:
        return None

    @property
    def edges(self) -> Iterator[Edge]:
        if not self.start_id or not self.end_id or not self.kind:
            logger.warning(
                "GraphEdge: dropping incomplete row (start=%r end=%r kind=%r)",
                self.start_id, self.end_id, self.kind,
            )
            return
        yield Edge(
            kind=self.kind,
            start=EdgePath(match_by="id", value=self.start_id),
            end=EdgePath(match_by="id", value=self.end_id),
            properties=SCCMEdgeProperties(traversable=self.kind in TRAVERSABLE_EDGE_KINDS),
        )
```

## Step 6: Split `_graph_edges` in `transforms.py`
Replace the existing `_graph_edges(con, schema)` function with these two, and update its call site in `transforms()`:
```python
def _graph_edges_init(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Create the empty graph_edges table that every edge builder INSERTs into.
    Always runs (even with no site/edge data) so convert can read the table."""
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.graph_edges "
        f"(start_id VARCHAR, end_id VARCHAR, kind VARCHAR)"
    )


def _edge_replication(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Append SCCM_AdminsReplicatedTo edges from the site_hierarchy self-join
    (CMBP ps1:1604-1624): CAS(4)<->Primary(2) bidirectional; Primary(2)->Secondary(1)
    one-way. _safe() skips+logs if site_hierarchy is missing."""
    from .kinds.edges import SCCM_ADMINS_REPLICATED_TO
    _safe(
        con, "edge_replication",
        f"INSERT INTO {schema}.graph_edges BY NAME "
        f"SELECT child.site_code AS start_id, parent.site_code AS end_id, "
        f"'{SCCM_ADMINS_REPLICATED_TO}' AS kind "
        f"FROM {schema}.site_hierarchy child JOIN {schema}.site_hierarchy parent "
        f"  ON child.parent_site_code = parent.site_code "
        f"WHERE child.site_type = 2 AND parent.site_type = 4 "
        f"UNION ALL "
        f"SELECT parent.site_code, child.site_code, '{SCCM_ADMINS_REPLICATED_TO}' "
        f"FROM {schema}.site_hierarchy child JOIN {schema}.site_hierarchy parent "
        f"  ON child.parent_site_code = parent.site_code "
        f"WHERE child.site_type = 2 AND parent.site_type = 4 "
        f"UNION ALL "
        f"SELECT parent.site_code, child.site_code, '{SCCM_ADMINS_REPLICATED_TO}' "
        f"FROM {schema}.site_hierarchy child JOIN {schema}.site_hierarchy parent "
        f"  ON child.parent_site_code = parent.site_code "
        f"WHERE child.site_type = 1 AND parent.site_type = 2"
    )
```
In `transforms()`, where it currently calls `_graph_edges(con, schema)` (last), replace with:
```python
    _graph_edges_init(con, schema)
    _edge_replication(con, schema)
```
Keep these AFTER all the `_node_*` calls (later edge tasks will add their builder calls between `_graph_edges_init` and the end). `_graph_edges_init` MUST precede `_edge_replication` and all future edge builders.

## Step 7: Update `main.py` + `models/__init__.py`
- `main.py`: change the import from `ReplicationEdge` to `GraphEdge` and set `EDGE_SPECS = [("graph_edges", GraphEdge)]`.
- `models/__init__.py`: replace the `ReplicationEdge` import/export with `GraphEdge`.
- Grep the whole `sccm/sccm` tree for `ReplicationEdge` and fix any remaining references.

## Step 8: Run — expect PASS:
- `models/graph_edge_test.py` (3 tests).
- The Stage 1 `graph_edges_test.py` (transforms-level — the replication rows must still be produced; now via `_edge_replication`). It must stay green.
- A quick import check: `python -c "import openhound_sccm.main"`.
```
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/models/graph_edge_test.py C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/graph_edges_test.py -v
```

## Step 9: Checkpoint — `git add` (stage only, NO commit). Also `git rm`/stage the deletion of `models/replication_edge.py` and `models/replication_edge_test.py` (use `git add -A sccm/sccm/src/openhound_sccm/models` so the renames/deletions are staged).
