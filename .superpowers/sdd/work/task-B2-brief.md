# Task B2: `node_security_role` coalesce + `SCCMSecurityRole` model

Second SCCM-native entity node. Structurally identical to Task B1 (`node_collection`): typed staging table → `_ensure_columns` → per-source `INSERT … BY NAME` via `_safe` → `GROUP BY upper(role_id)` collapse → stamp `root_site_code` from the shared `_root_code` helper (already added in B1). The model mirrors `SCCMCollection`. Complete code is below — transcribe it, then make the tests pass.

**Node id:** `SCCM_SecurityRole` id = `upper(role_id) || '@' || root_site_code`. `environmentid` = `root_site_code`.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_node_security_role`; call it from `transforms()` immediately after `_node_collection`)
- Modify: `sccm/sccm/src/openhound_sccm/graph.py` (add `SCCMSecurityRoleProperties`)
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (`("node_security_role", SCCMSecurityRole)` in `NODE_SPECS` + import)
- Modify: `sccm/sccm/src/openhound_sccm/models/__init__.py` (export `SCCMSecurityRole`)
- Create: `sccm/sccm/src/openhound_sccm/models/sccm_security_role.py`
- Create (tests): `sccm/sccm/src/openhound_sccm/node_security_role_test.py`, `sccm/sccm/src/openhound_sccm/models/sccm_security_role_test.py`

**Interfaces — Produces:** `node_security_role(role_id, role_name, role_description, is_built_in, is_sec_admin_role, copied_from_id, number_of_admins, operations, root_site_code)` one row per `upper(role_id)`; `SCCMSecurityRole(BaseAsset).as_node -> SCCMNode | None`.

## Step 1: Write the failing tests

```python
# src/openhound_sccm/node_security_role_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_node_security_role_one_row_per_id():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS000AR' AS role_id, "
                "'Full Administrator' AS role_name, 'desc' AS role_description, true AS is_built_in, "
                "false AS is_sec_admin_role")
    transforms(con)
    r = con.execute("SELECT role_id, role_name, root_site_code FROM sccm.node_security_role").fetchone()
    assert r == ("SMS000AR", "Full Administrator", "CAS")
```
```python
# src/openhound_sccm/models/sccm_security_role_test.py
from openhound_sccm.models.sccm_security_role import SCCMSecurityRole

def test_security_role_as_node():
    n = SCCMSecurityRole(role_id="SMS000AR", role_name="Full Administrator",
                         root_site_code="CAS", is_built_in=True).as_node
    assert n.id == "SMS000AR@CAS"
    assert n.kinds == ["SCCM_SecurityRole"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.sccm_role_name == "Full Administrator"

def test_security_role_no_id_returns_none():
    assert SCCMSecurityRole(role_id=None, root_site_code="CAS").as_node is None
```

## Step 2: Run — expect failure.
`pytest .../node_security_role_test.py .../models/sccm_security_role_test.py -v`

## Step 3a: `_node_security_role` in `transforms.py`

```python
def _node_security_role(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One row per role_id, coalesced from adminservice/wmi security_roles."""
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_security_role ("
        "role_id VARCHAR, role_name VARCHAR, role_description VARCHAR, is_built_in BOOLEAN, "
        "is_sec_admin_role BOOLEAN, copied_from_id VARCHAR, number_of_admins BIGINT, operations VARCHAR[])"
    )
    _optional = {"role_name": "VARCHAR", "role_description": "VARCHAR", "is_built_in": "BOOLEAN",
                 "is_sec_admin_role": "BOOLEAN", "copied_from_id": "VARCHAR",
                 "number_of_admins": "BIGINT", "operations": "VARCHAR"}
    for _src in ("adminservice_security_roles", "wmi_security_roles"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(con, f"node_security_role<-{_src}",
              f"INSERT INTO {schema}.node_security_role BY NAME "
              f"SELECT upper(role_id) AS role_id, role_name, role_description, is_built_in, "
              f"is_sec_admin_role, copied_from_id, TRY_CAST(number_of_admins AS BIGINT) AS number_of_admins, "
              f"{_arr('operations')} AS operations "
              f"FROM {schema}.{_src} WHERE role_id IS NOT NULL")
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_security_role AS SELECT role_id, "
        f"any_value(role_name) AS role_name, any_value(role_description) AS role_description, "
        f"bool_or(is_built_in) AS is_built_in, bool_or(is_sec_admin_role) AS is_sec_admin_role, "
        f"any_value(copied_from_id) AS copied_from_id, max(number_of_admins) AS number_of_admins, "
        f"list_distinct(list_filter(flatten(list(operations)), x -> x IS NOT NULL AND trim(x) != '')) AS operations, "
        f"? AS root_site_code "
        f"FROM {schema}.node_security_role GROUP BY role_id", [root])
    logger.info("node_security_role built in schema %r", schema)
```
Call `_node_security_role(con, schema)` in `transforms()` immediately after `_node_collection(con, schema)`.

> `operations` shape varies in real data (array of strings/ints, or comma text); `_arr` already normalises string/list/JSON-text to `VARCHAR[]` and degrades malformed to `[]`. The test doesn't seed `operations` (so it's `[]`), so it won't break the test; real-data robustness is best-effort. If a real run errors on `operations`, simplify per the observed shape and note it.

## Step 3b: `SCCMSecurityRoleProperties` in `graph.py`

```python
@dataclass
class SCCMSecurityRoleProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_role_id: str | None = field(default=None, kw_only=True)
    sccm_role_name: str | None = field(default=None, kw_only=True)
    role_description: str | None = field(default=None, kw_only=True)
    is_built_in: bool | None = field(default=None, kw_only=True)
    is_sec_admin_role: bool | None = field(default=None, kw_only=True)
    copied_from_id: str | None = field(default=None, kw_only=True)
    number_of_admins: int | None = field(default=None, kw_only=True)
    operations: list[str] = field(default_factory=list, kw_only=True)
    root_site_code: str | None = field(default=None, kw_only=True)
    sccm_infra: bool = field(default=True, kw_only=True)
```

## Step 3c: `models/sccm_security_role.py`

```python
# src/openhound_sccm/models/sccm_security_role.py
import logging
from openhound.core.asset import BaseAsset
from pydantic import ConfigDict
from ..graph import SCCMNode, SCCMSecurityRoleProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class SCCMSecurityRole(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    role_id: str | None = None
    role_name: str | None = None
    role_description: str | None = None
    is_built_in: bool | None = None
    is_sec_admin_role: bool | None = None
    copied_from_id: str | None = None
    number_of_admins: int | None = None
    operations: list[str] = []
    root_site_code: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        rid = (self.role_id or "").upper() or None
        if not rid:
            logger.warning("SCCMSecurityRole: dropping row with no role_id")
            return None
        root = self.root_site_code or ""
        node_id = f"{rid}@{root}" if root else rid
        display = f"{self.role_name}@{root}" if (self.role_name and root) else (self.role_name or node_id)
        return SCCMNode(
            id=node_id, kinds=[nk.SCCM_SECURITY_ROLE],
            properties=SCCMSecurityRoleProperties(
                name=self.role_name or node_id, displayname=display, environmentid=root or rid,
                sccm_role_id=rid, sccm_role_name=self.role_name, role_description=self.role_description,
                is_built_in=self.is_built_in, is_sec_admin_role=self.is_sec_admin_role,
                copied_from_id=self.copied_from_id, number_of_admins=self.number_of_admins,
                operations=list(self.operations or []), root_site_code=self.root_site_code,
            ),
        )

    @property
    def edges(self):
        return iter(())
```
> `nk.SCCM_SECURITY_ROLE` exists in `kinds/nodes.py` (`SCCM_SECURITY_ROLE = "SCCM_SecurityRole"`).

## Step 3d: Register
- `main.py`: import `SCCMSecurityRole`, add `("node_security_role", SCCMSecurityRole)` to `NODE_SPECS`.
- `models/__init__.py`: `from .sccm_security_role import SCCMSecurityRole` + add to `__all__`.

## Step 4: Run — expect PASS (3 tests). ## Step 5: Checkpoint — `git add` (stage only, NO commit).
