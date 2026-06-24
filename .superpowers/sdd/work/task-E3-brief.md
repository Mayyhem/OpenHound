# Task E3: `node_backfill` — synthesize bare nodes for edge endpoints with no node

After ALL nodes and edges are built, find edge END endpoints (for the kinds whose end is a SID/smsid) that aren't in any SID/smsid-keyed node table, and emit a bare stub node with the kind inferred from the edge position + a logged warning. (Locked decision 2026-06-23: synthesize stub + warn, rather than drop.) Runs LAST in `transforms()`.

**Which endpoints:** only the END of `Has*User`/`HasSession`/`MemberOf`/`HasMember`/`HasStoredAccount` — those ends are user/group SIDs (or a device smsid for HasMember). Their start endpoints (sites/devices/admins) and the `@root`-suffixed Collection/Role/AdminUser ids always have nodes from their own tables, so they aren't backfilled. The ambiguous ends (`SCCM_HasMember`, `SCCM_HasStoredAccount` = user OR group) get kind `Base` only.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/graph.py` (add `BACKFILL_END_KIND`)
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_node_backfill`; call from `transforms()` LAST, after `_edge_has_stored_account`)
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (`("node_backfill", StubNode)` in `NODE_SPECS`, LAST; import)
- Modify: `sccm/sccm/src/openhound_sccm/models/__init__.py` (export `StubNode`)
- Create: `sccm/sccm/src/openhound_sccm/models/stub_node.py`
- Create (tests): `sccm/sccm/src/openhound_sccm/node_backfill_test.py`, `sccm/sccm/src/openhound_sccm/models/stub_node_test.py`

**Interfaces — Produces:** `node_backfill(id, kind)` (one row per missing endpoint id); `StubNode(BaseAsset).as_node -> SCCMNode | None`; `BACKFILL_END_KIND: dict[str,str]`.

## Step 1: Write the failing tests
```python
# src/openhound_sccm/node_backfill_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_node_backfill_synthesizes_missing_endpoint():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    # device whose primary_user resolves (via principal_by_name) to a SID that is in NO node table
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete, "
                "'MAYYHEM\\ghost' AS primary_user")
    # user_group feeds principal_by_name['MAYYHEM\\ghost']=9999 but, being unreferenced by any
    # security_group_name, does NOT become a node_group -> the HasPrimaryUser end is nodeless.
    con.execute("CREATE TABLE sccm.adminservice_user_group AS SELECT 'S-1-5-21-1-2-3-9999' AS sid, "
                "'MAYYHEM\\ghost' AS unique_usergroup_name, 'ghost' AS usergroup_name, 50 AS resource_id")
    transforms(con)
    rows = con.execute("SELECT id, kind FROM sccm.node_backfill WHERE id='S-1-5-21-1-2-3-9999'").fetchall()
    assert rows == [("S-1-5-21-1-2-3-9999", "User")]   # kind inferred from HasPrimaryUser end
    # it really was nodeless:
    assert con.execute("SELECT count(*) FROM sccm.node_group WHERE sid='S-1-5-21-1-2-3-9999'").fetchone()[0] == 0
    assert con.execute("SELECT count(*) FROM sccm.node_user WHERE sid='S-1-5-21-1-2-3-9999'").fetchone()[0] == 0
```
```python
# src/openhound_sccm/models/stub_node_test.py
from openhound_sccm.models.stub_node import StubNode

def test_stub_node_user_gets_base_and_domain_env():
    n = StubNode(id="S-1-5-21-1-2-3-9999", kind="User").as_node
    assert n.id == "S-1-5-21-1-2-3-9999"
    assert n.kinds == ["User", "Base"]
    assert n.properties.environmentid == "S-1-5-21-1-2-3"

def test_stub_node_base_only_falls_back_to_id_env():
    n = StubNode(id="SOMEID", kind="Base").as_node
    assert n.kinds == ["Base"]
    assert n.properties.environmentid == "SOMEID"

def test_stub_node_missing_returns_none():
    assert StubNode(id=None, kind="User").as_node is None
```
> Backslash rule (B3): `\\` = one backslash.

## Step 2: Run — expect failure.
`pytest .../node_backfill_test.py .../models/stub_node_test.py -v`

## Step 3a: `BACKFILL_END_KIND` in `graph.py`
```python
# Edge kind -> the kind to give a synthesised stub when the edge's END id has no node.
# Only edges whose end is a user/group SID (or a device smsid) appear here; ambiguous
# ends (user OR group) get "Base". See Stage 2 graph-integrity decision (2026-06-23).
BACKFILL_END_KIND: dict[str, str] = {
    "SCCM_HasPrimaryUser": "User",
    "SCCM_HasCurrentUser": "User",
    "SCCM_HasADLastLogonUser": "User",
    "HasSession": "User",
    "MemberOf": "Group",
    "SCCM_HasMember": "Base",
    "SCCM_HasStoredAccount": "Base",
}
```

## Step 3b: `_node_backfill` in `transforms.py`
```python
def _node_backfill(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Synthesise bare nodes for edge END endpoints that resolved to a SID/smsid with no
    node (graph-integrity decision 2026-06-23). Kind is inferred from the edge position
    (BACKFILL_END_KIND); ambiguous ends get 'Base'. Logs a warning count. Runs LAST."""
    from .graph import BACKFILL_END_KIND
    con.execute(
        f"CREATE OR REPLACE TEMP TABLE _existing_ids AS "
        f"SELECT sid AS id FROM {schema}.node_computer WHERE sid IS NOT NULL "
        f"UNION SELECT sid FROM {schema}.node_user WHERE sid IS NOT NULL "
        f"UNION SELECT sid FROM {schema}.node_group WHERE sid IS NOT NULL "
        f"UNION SELECT smsid FROM {schema}.node_client_device WHERE smsid IS NOT NULL"
    )
    map_values = ", ".join(f"('{k}', '{v}')" for k, v in BACKFILL_END_KIND.items())
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_backfill AS "
        f"SELECT DISTINCT ge.end_id AS id, m.kind AS kind "
        f"FROM {schema}.graph_edges ge "
        f"JOIN (VALUES {map_values}) AS m(edge_kind, kind) ON ge.kind = m.edge_kind "
        f"WHERE ge.end_id IS NOT NULL "
        f"  AND ge.end_id NOT IN (SELECT id FROM _existing_ids)"
    )
    cnt = con.execute(f"SELECT count(*) FROM {schema}.node_backfill").fetchone()[0]
    if cnt:
        logger.warning("node_backfill: synthesised %d stub node(s) for edge endpoints with no node", cnt)
    else:
        logger.debug("node_backfill: every edge endpoint has a node")
```
Call `_node_backfill(con, schema)` in `transforms()` as the VERY LAST step (after `_edge_has_stored_account`). All node tables exist by then (each `_node_*` does CREATE OR REPLACE even when empty), so the `_existing_ids` UNION is safe.

## Step 3c: `models/stub_node.py`
```python
# src/openhound_sccm/models/stub_node.py
import logging
from openhound.core.asset import BaseAsset
from openhound.core.models.entries_dataclass import NodeProperties
from pydantic import ConfigDict
from ..graph import SCCMNode, domain_environment_id

logger = logging.getLogger(__name__)
_AD_KINDS = {"User", "Group", "Computer"}


class StubNode(BaseAsset):
    """A bare backfilled node (node_backfill row): id + an inferred kind. AD-principal
    kinds also get 'Base'; environmentid is the domain SID when id is a SID, else the id."""
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    id: str | None = None
    kind: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        if not self.id or not self.kind:
            logger.warning("StubNode: dropping row with missing id/kind (id=%r kind=%r)", self.id, self.kind)
            return None
        kinds = [self.kind, "Base"] if self.kind in _AD_KINDS else [self.kind]
        env = domain_environment_id(self.id) or self.id
        return SCCMNode(
            id=self.id, kinds=kinds,
            properties=NodeProperties(name=self.id, displayname=self.id, environmentid=env),
        )

    @property
    def edges(self):
        return iter(())
```

## Step 3d: Register
- `main.py`: import `StubNode`, append `("node_backfill", StubNode)` to `NODE_SPECS` as the LAST entry (real nodes win on any id overlap via opengraph append semantics).
- `models/__init__.py`: `from .stub_node import StubNode` + add to `__all__`.

## Step 4: Run — expect PASS (4 tests). ## Step 5: Checkpoint — `git add` (stage only).
