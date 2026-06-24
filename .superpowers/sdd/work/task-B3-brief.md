# Task B3: `node_admin_user` coalesce + `SCCMAdminUser` model

Third SCCM-native entity node. Same coalesce/model shape as B1/B2. The SCCM `SCCM_AdminUser` node is the RBAC *admin object* (distinct from the AD principal behind it, which Stage 1 already emitted as a User/Group from the same `admins` table). Keyed by `upper(logon_name)@root_site_code`.

**Important casing rule:** dedup on `upper(logon_name)` but STORE the original-case `logon_name` (for the display/name). The model uppercases `logon_name` when building the id, so the node id is `upper(logon_name)@root` while `properties.name` keeps the original case. (The C4/C5 edge tasks compute `upper(logon_name)@root` from the raw admins rows, so they match the node id.)

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_node_admin_user`; call from `transforms()` immediately after `_node_security_role`)
- Modify: `sccm/sccm/src/openhound_sccm/graph.py` (add `SCCMAdminUserProperties`)
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (`("node_admin_user", SCCMAdminUser)` in `NODE_SPECS` + import)
- Modify: `sccm/sccm/src/openhound_sccm/models/__init__.py` (export `SCCMAdminUser`)
- Create: `sccm/sccm/src/openhound_sccm/models/sccm_admin_user.py`
- Create (tests): `sccm/sccm/src/openhound_sccm/node_admin_user_test.py`, `sccm/sccm/src/openhound_sccm/models/sccm_admin_user_test.py`

**Interfaces — Produces:** `node_admin_user(logon_name, admin_id, admin_sid, display_name, distinguished_name, is_group, account_type, root_site_code)` one row per `upper(logon_name)` (logon_name stored original-case); `SCCMAdminUser(BaseAsset).as_node -> SCCMNode | None` (id = `upper(logon_name)@root`).

## Step 1: Write the failing tests

```python
# src/openhound_sccm/node_admin_user_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_node_admin_user_one_row_per_logon():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    # same admin replicated from two sites -> one node (dedup on upper(logon_name))
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT * FROM (VALUES "
                "('MAYYHEM\\\\sccmadmin','S-1-5-21-1-2-3-1110','adm', false, 1), "
                "('MAYYHEM\\\\sccmadmin','S-1-5-21-1-2-3-1110','adm', false, 1)) "
                "AS t(logon_name, admin_sid, display_name, is_group, account_type)")
    transforms(con)
    rows = con.execute("SELECT logon_name, admin_sid, root_site_code FROM sccm.node_admin_user").fetchall()
    assert rows == [("MAYYHEM\\sccmadmin", "S-1-5-21-1-2-3-1110", "CAS")]
```
```python
# src/openhound_sccm/models/sccm_admin_user_test.py
from openhound_sccm.models.sccm_admin_user import SCCMAdminUser

def test_admin_user_as_node():
    n = SCCMAdminUser(logon_name="MAYYHEM\\sccmadmin", admin_sid="S-1-5-21-1-2-3-1110",
                      is_group=False, root_site_code="CAS").as_node
    assert n.id == "MAYYHEM\\SCCMADMIN@CAS"      # id uppercases logon_name
    assert n.kinds == ["SCCM_AdminUser"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.is_group is False

def test_admin_user_no_logon_returns_none():
    assert SCCMAdminUser(logon_name=None, root_site_code="CAS").as_node is None
```

## Step 2: Run — expect failure.
`pytest .../node_admin_user_test.py .../models/sccm_admin_user_test.py -v`

## Step 3a: `_node_admin_user` in `transforms.py`

```python
def _node_admin_user(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One row per upper(logon_name), coalesced from adminservice/wmi admins.
    logon_name stored original-case; dedup key is upper(logon_name)."""
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_admin_user ("
        "logon_name VARCHAR, admin_id VARCHAR, admin_sid VARCHAR, display_name VARCHAR, "
        "distinguished_name VARCHAR, is_group BOOLEAN, account_type INTEGER)"
    )
    _optional = {"admin_id": "VARCHAR", "admin_sid": "VARCHAR", "display_name": "VARCHAR",
                 "distinguished_name": "VARCHAR", "is_group": "BOOLEAN", "account_type": "INTEGER"}
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(con, f"node_admin_user<-{_src}",
              f"INSERT INTO {schema}.node_admin_user BY NAME "
              f"SELECT logon_name, CAST(admin_id AS VARCHAR) AS admin_id, upper(admin_sid) AS admin_sid, "
              f"display_name, distinguished_name, is_group, TRY_CAST(account_type AS INTEGER) AS account_type "
              f"FROM {schema}.{_src} WHERE logon_name IS NOT NULL")
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_admin_user AS SELECT "
        f"any_value(logon_name) AS logon_name, any_value(admin_id) AS admin_id, "
        f"any_value(admin_sid) AS admin_sid, any_value(display_name) AS display_name, "
        f"any_value(distinguished_name) AS distinguished_name, bool_or(is_group) AS is_group, "
        f"max(account_type) AS account_type, ? AS root_site_code "
        f"FROM {schema}.node_admin_user GROUP BY upper(logon_name)", [root])
    logger.info("node_admin_user built in schema %r", schema)
```
Call `_node_admin_user(con, schema)` in `transforms()` immediately after `_node_security_role(con, schema)`.

## Step 3b: `SCCMAdminUserProperties` in `graph.py`

```python
@dataclass
class SCCMAdminUserProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    sccm_admin_id: str | None = field(default=None, kw_only=True)
    admin_sid: str | None = field(default=None, kw_only=True)
    distinguished_name: str | None = field(default=None, kw_only=True)
    is_group: bool | None = field(default=None, kw_only=True)
    account_type: int | None = field(default=None, kw_only=True)
    root_site_code: str | None = field(default=None, kw_only=True)
    sccm_infra: bool = field(default=True, kw_only=True)
```

## Step 3c: `models/sccm_admin_user.py`

```python
# src/openhound_sccm/models/sccm_admin_user.py
import logging
from openhound.core.asset import BaseAsset
from pydantic import ConfigDict
from ..graph import SCCMNode, SCCMAdminUserProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class SCCMAdminUser(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    logon_name: str | None = None
    admin_id: str | None = None
    admin_sid: str | None = None
    display_name: str | None = None
    distinguished_name: str | None = None
    is_group: bool | None = None
    account_type: int | None = None
    root_site_code: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        logon = self.logon_name or ""
        key = logon.upper() or None
        if not key:
            logger.warning("SCCMAdminUser: dropping row with no logon_name")
            return None
        root = self.root_site_code or ""
        node_id = f"{key}@{root}" if root else key
        display = self.display_name or logon or node_id
        return SCCMNode(
            id=node_id, kinds=[nk.SCCM_ADMIN_USER],
            properties=SCCMAdminUserProperties(
                name=logon or node_id, displayname=display, environmentid=root or key,
                sccm_admin_id=self.admin_id, admin_sid=self.admin_sid,
                distinguished_name=self.distinguished_name, is_group=self.is_group,
                account_type=self.account_type, root_site_code=self.root_site_code,
            ),
        )

    @property
    def edges(self):
        return iter(())
```
> `nk.SCCM_ADMIN_USER` exists in `kinds/nodes.py` (`SCCM_ADMIN_USER = "SCCM_AdminUser"`).

## Step 3d: Register
- `main.py`: import `SCCMAdminUser`, add `("node_admin_user", SCCMAdminUser)` to `NODE_SPECS`.
- `models/__init__.py`: `from .sccm_admin_user import SCCMAdminUser` + add to `__all__`.

## Step 4: Run — expect PASS (3 tests). ## Step 5: Checkpoint — `git add` (stage only, NO commit).
