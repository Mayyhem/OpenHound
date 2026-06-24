# Task B1: `node_collection` coalesce + `SCCMCollection` model

First SCCM-native entity node. Follows the established Stage 1 coalesce pattern in `transforms.py` (typed staging table → `_ensure_columns` for optional source cols → per-source `INSERT … BY NAME` via `_safe` → final `GROUP BY` collapse). Helpers `_safe`, `_ensure_columns`, `_arr` already exist in `transforms.py`; the Stage 1 coalesces `_node_computer`/`_node_user`/`_node_site` are your reference for style. The model mirrors `models/sccm_site.py`.

**Node id:** `SCCM_Collection` id = `upper(collection_id) || '@' || root_site_code`, minted final. `environmentid` = `root_site_code`. There is one hierarchy root (single-hierarchy assumption); get it via the shared `_root_code` helper below.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_root_code` helper + `_node_collection`; call `_node_collection` from `transforms()` after `_node_site`, before the edge builders)
- Modify: `sccm/sccm/src/openhound_sccm/graph.py` (add `SCCMCollectionProperties`)
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (add `("node_collection", SCCMCollection)` to `NODE_SPECS`)
- Modify: `sccm/sccm/src/openhound_sccm/models/__init__.py` (export `SCCMCollection`)
- Create: `sccm/sccm/src/openhound_sccm/models/sccm_collection.py`
- Create (tests): `sccm/sccm/src/openhound_sccm/node_collection_test.py`, `sccm/sccm/src/openhound_sccm/models/sccm_collection_test.py`

**Interfaces — Produces:**
- `node_collection(collection_id, name, collection_type, member_count, comment, is_built_in, limit_to_collection_id, limit_to_collection_name, collection_variables_count, root_site_code)` — one row per `upper(collection_id)`.
- `SCCMCollection(BaseAsset).as_node -> SCCMNode | None` (id = `collection_id@root`).
- `_root_code(con, schema) -> str | None` (shared; later tasks B2/B3/E2 will reuse it — define it ONCE here).

## Step 1: Write the failing tests

```python
# src/openhound_sccm/node_collection_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_node_collection_one_row_per_id_with_root():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4), ('PS1','CAS',2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT "
                "'PS100016' AS collection_id, 'All Systems' AS name, 2 AS collection_type, "
                "42 AS member_count, false AS is_built_in, 'PS1' AS source_site_code")
    transforms(con)
    rows = con.execute("SELECT collection_id, name, member_count, root_site_code FROM sccm.node_collection").fetchall()
    assert rows == [("PS100016", "All Systems", 42, "CAS")]
```
```python
# src/openhound_sccm/models/sccm_collection_test.py
from openhound_sccm.models.sccm_collection import SCCMCollection

def test_collection_as_node():
    n = SCCMCollection(collection_id="PS100016", name="All Systems", collection_type=2,
                       member_count=42, root_site_code="CAS").as_node
    assert n.id == "PS100016@CAS"
    assert n.kinds == ["SCCM_Collection"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.sccm_collection_id == "PS100016"

def test_collection_no_id_returns_none():
    assert SCCMCollection(collection_id=None, root_site_code="CAS").as_node is None
```

## Step 2: Run — expect failure.
Test cmd (isolated env): `pytest .../node_collection_test.py .../models/sccm_collection_test.py -v`

## Step 3a: `_root_code` helper + `_node_collection` in `transforms.py`

```python
def _root_code(con: duckdb.DuckDBPyConnection, schema: str) -> str | None:
    """The single hierarchy root_site_code (built by _site_hierarchy). Used to mint
    SCCM-native ids final. None if no site data was collected."""
    try:
        row = con.execute(f"SELECT any_value(root_site_code) FROM {schema}.site_hierarchy").fetchone()
        return row[0] if row else None
    except duckdb.CatalogException:
        logger.warning("_root_code: site_hierarchy missing; SCCM-native ids will lack a root scope")
        return None


def _node_collection(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One row per collection_id, coalesced from adminservice/wmi collections."""
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_collection ("
        "collection_id VARCHAR, name VARCHAR, collection_type INTEGER, member_count BIGINT, "
        "comment VARCHAR, is_built_in BOOLEAN, limit_to_collection_id VARCHAR, "
        "limit_to_collection_name VARCHAR, collection_variables_count BIGINT)"
    )
    _optional = {"name": "VARCHAR", "collection_type": "INTEGER", "member_count": "BIGINT",
                 "comment": "VARCHAR", "is_built_in": "BOOLEAN", "limit_to_collection_id": "VARCHAR",
                 "limit_to_collection_name": "VARCHAR", "collection_variables_count": "BIGINT"}
    for _src in ("adminservice_collections", "wmi_collections"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(con, f"node_collection<-{_src}",
              f"INSERT INTO {schema}.node_collection BY NAME "
              f"SELECT upper(collection_id) AS collection_id, name, "
              f"TRY_CAST(collection_type AS INTEGER) AS collection_type, "
              f"TRY_CAST(member_count AS BIGINT) AS member_count, comment, "
              f"is_built_in, limit_to_collection_id, limit_to_collection_name, "
              f"TRY_CAST(collection_variables_count AS BIGINT) AS collection_variables_count "
              f"FROM {schema}.{_src} WHERE collection_id IS NOT NULL")
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_collection AS SELECT collection_id, "
        f"any_value(name) AS name, max(collection_type) AS collection_type, "
        f"max(member_count) AS member_count, any_value(comment) AS comment, "
        f"bool_or(is_built_in) AS is_built_in, any_value(limit_to_collection_id) AS limit_to_collection_id, "
        f"any_value(limit_to_collection_name) AS limit_to_collection_name, "
        f"max(collection_variables_count) AS collection_variables_count, ? AS root_site_code "
        f"FROM {schema}.node_collection GROUP BY collection_id", [root])
    logger.info("node_collection built in schema %r", schema)
```
Call `_node_collection(con, schema)` inside `transforms()` after `_node_site(...)` and before the `_graph_edges` / edge calls. (If `transforms()` currently ends with `_graph_edges`, insert the call immediately before it.)

> **Pattern reference:** the `_safe`, `_ensure_columns`, `_arr` helpers and the `INSERT … BY NAME` + `GROUP BY` collapse are exactly as used by the existing `_node_site`/`_node_computer` in the same file — read those for the idiom. The `_ensure_columns(con, schema, src, coldefs)` call pre-creates optional columns so a source missing one still binds.

## Step 3b: `SCCMCollectionProperties` in `graph.py`
Add alongside the existing `*Properties` dataclasses (all extend core `NodeProperties`, fields are `kw_only=True`):
```python
@dataclass
class SCCMCollectionProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_collection_id: str | None = field(default=None, kw_only=True)
    sccm_collection_type: str | None = field(default=None, kw_only=True)   # "Device"/"User"
    member_count: int | None = field(default=None, kw_only=True)
    comment: str | None = field(default=None, kw_only=True)
    is_built_in: bool | None = field(default=None, kw_only=True)
    limit_to_collection_id: str | None = field(default=None, kw_only=True)
    limit_to_collection_name: str | None = field(default=None, kw_only=True)
    root_site_code: str | None = field(default=None, kw_only=True)
    sccm_infra: bool = field(default=True, kw_only=True)
```

## Step 3c: `models/sccm_collection.py`

```python
# src/openhound_sccm/models/sccm_collection.py
import logging
from openhound.core.asset import BaseAsset
from pydantic import ConfigDict
from ..graph import SCCMNode, SCCMCollectionProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)
_COLLECTION_TYPE = {0: "Device", 1: "User"}


class SCCMCollection(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    collection_id: str | None = None
    name: str | None = None
    collection_type: int | None = None
    member_count: int | None = None
    comment: str | None = None
    is_built_in: bool | None = None
    limit_to_collection_id: str | None = None
    limit_to_collection_name: str | None = None
    root_site_code: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        cid = (self.collection_id or "").upper() or None
        if not cid:
            logger.warning("SCCMCollection: dropping row with no collection_id")
            return None
        root = self.root_site_code or ""
        node_id = f"{cid}@{root}" if root else cid
        display = f"{self.name}@{root}" if (self.name and root) else (self.name or node_id)
        return SCCMNode(
            id=node_id, kinds=[nk.SCCM_COLLECTION],
            properties=SCCMCollectionProperties(
                name=self.name or node_id, displayname=display, environmentid=root or cid,
                sccm_collection_id=cid,
                sccm_collection_type=_COLLECTION_TYPE.get(self.collection_type),
                member_count=self.member_count, comment=self.comment, is_built_in=self.is_built_in,
                limit_to_collection_id=self.limit_to_collection_id,
                limit_to_collection_name=self.limit_to_collection_name,
                root_site_code=self.root_site_code,
            ),
        )

    @property
    def edges(self):
        return iter(())
```
> Confirm `nk.SCCM_COLLECTION` exists in `kinds/nodes.py` (it does: `SCCM_COLLECTION = "SCCM_Collection"`).

## Step 3d: Register
- In `main.py`, add `("node_collection", SCCMCollection)` to the `NODE_SPECS` list (and import `SCCMCollection`). Follow how the Stage 1 node specs are imported/listed.
- In `models/__init__.py`, add `from .sccm_collection import SCCMCollection` and add `SCCMCollection` to `__all__` (match the existing export style).

## Step 4: Run — expect PASS (3 tests across the two test files).
## Step 5: Checkpoint — `git add` (stage only, NO commit) all changed/created files.
