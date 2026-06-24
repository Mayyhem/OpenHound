# Task B4: `node_client_device` coalesce (real clients) + `SCCMClientDevice` model

Last SCCM-native entity node. REAL AdminService/WMI client devices only — the inferred "possible-client" rows are added later (Task E2), which is why `node_client_device` carries `possible` and `ad_domain_sid` columns now (set to `false`/`NULL` here). Same coalesce/model idiom as B1–B3. Keyed by `upper(smsid)` (no site suffix — smsid is a hierarchy-unique GUID).

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_node_client_device`; call from `transforms()` immediately after `_node_admin_user`)
- Modify: `sccm/sccm/src/openhound_sccm/graph.py` (add `SCCMClientDeviceProperties`)
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (`("node_client_device", SCCMClientDevice)` in `NODE_SPECS` + import)
- Modify: `sccm/sccm/src/openhound_sccm/models/__init__.py` (export `SCCMClientDevice`)
- Create: `sccm/sccm/src/openhound_sccm/models/sccm_client_device.py`
- Create (tests): `sccm/sccm/src/openhound_sccm/node_client_device_test.py`, `sccm/sccm/src/openhound_sccm/models/sccm_client_device_test.py`

**Interfaces — Produces:** `node_client_device(smsid, name, site_code, resource_id_str, device_os, device_os_build, is_virtual_machine, co_managed, aad_device_id, aad_tenant_id, last_mp_server_name, primary_user_name, current_logon_user_name, ad_last_logon_user_name, possible, ad_domain_sid, root_site_code)` one row per `upper(smsid)`; `SCCMClientDevice(BaseAsset).as_node -> SCCMNode | None` (id = `upper(smsid)`). The three `*_user_name` columns are name-only here; SID-resolved `Has*User` edges come in Task D1.

## Step 1: Write the failing tests

```python
# src/openhound_sccm/node_client_device_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_node_client_device_filters_and_keys_on_smsid():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT * FROM (VALUES "
                "('GUID-1','WS01', 7, 'PS1', true,  false, 'MAYYHEM\\alice','MAYYHEM\\bob','MAYYHEM\\carol'), "
                "('GUID-2','WS02', 8, 'PS1', false, false, NULL, NULL, NULL), "       # not a client -> dropped
                "('GUID-3','WS03', 9, 'PS1', true,  true,  NULL, NULL, NULL)) "        # obsolete -> dropped
                "AS t(smsid, name, resource_id, site_code, is_client, is_obsolete, primary_user, current_logon_user, user_name)")
    transforms(con)
    rows = con.execute("SELECT smsid, name, resource_id_str, possible FROM sccm.node_client_device ORDER BY smsid").fetchall()
    assert rows == [("GUID-1", "WS01", "7@PS1", False)]
```
```python
# src/openhound_sccm/models/sccm_client_device_test.py
from openhound_sccm.models.sccm_client_device import SCCMClientDevice

def test_client_device_as_node():
    n = SCCMClientDevice(smsid="GUID-1", name="WS01", site_code="PS1", root_site_code="CAS",
                         resource_id_str="7@PS1").as_node
    assert n.id == "GUID-1"
    assert n.kinds == ["SCCM_ClientDevice"]
    assert n.properties.environmentid == "CAS"
    assert n.properties.smsid == "GUID-1"

def test_client_device_no_smsid_returns_none():
    assert SCCMClientDevice(smsid=None, name="x").as_node is None
```
> Backslash note (from Task B3): in Python test strings use `\\` (ONE backslash stored) for `DOMAIN\user` values. Those user columns aren't asserted here, but keep it consistent.

## Step 2: Run — expect failure.
`pytest .../node_client_device_test.py .../models/sccm_client_device_test.py -v`

## Step 3a: `_node_client_device` in `transforms.py`

```python
def _node_client_device(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """One row per smsid from adminservice/wmi client_devices (real clients only:
    is_client AND NOT is_obsolete). possible/ad_domain_sid are placeholders for the
    possible-client rows added in Task E2."""
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_client_device ("
        "smsid VARCHAR, name VARCHAR, site_code VARCHAR, resource_id_str VARCHAR, "
        "device_os VARCHAR, device_os_build VARCHAR, is_virtual_machine BOOLEAN, co_managed BOOLEAN, "
        "aad_device_id VARCHAR, aad_tenant_id VARCHAR, last_mp_server_name VARCHAR, "
        "primary_user_name VARCHAR, current_logon_user_name VARCHAR, ad_last_logon_user_name VARCHAR, "
        "possible BOOLEAN, ad_domain_sid VARCHAR)"
    )
    _optional = {"name": "VARCHAR", "site_code": "VARCHAR", "resource_id": "BIGINT",
                 "device_os": "VARCHAR", "device_os_build": "VARCHAR", "is_virtual_machine": "BOOLEAN",
                 "co_managed": "BOOLEAN", "aad_device_id": "VARCHAR", "aad_tenant_id": "VARCHAR",
                 "last_mp_server_name": "VARCHAR", "primary_user": "VARCHAR",
                 "current_logon_user": "VARCHAR", "user_name": "VARCHAR",
                 "is_client": "BOOLEAN", "is_obsolete": "BOOLEAN"}
    for _src in ("adminservice_client_devices", "wmi_client_devices"):
        _ensure_columns(con, schema, _src, _optional)
        _safe(con, f"node_client_device<-{_src}",
              f"INSERT INTO {schema}.node_client_device BY NAME "
              f"SELECT upper(smsid) AS smsid, name, site_code, "
              f"CASE WHEN resource_id IS NULL THEN NULL "
              f"     ELSE CAST(resource_id AS VARCHAR) || '@' || CAST(site_code AS VARCHAR) END AS resource_id_str, "
              f"device_os, device_os_build, is_virtual_machine, co_managed, aad_device_id, aad_tenant_id, "
              f"last_mp_server_name, primary_user AS primary_user_name, "
              f"current_logon_user AS current_logon_user_name, user_name AS ad_last_logon_user_name, "
              f"false AS possible, NULL AS ad_domain_sid "
              f"FROM {schema}.{_src} "
              f"WHERE smsid IS NOT NULL AND coalesce(is_client, false) AND NOT coalesce(is_obsolete, false)")
    root = _root_code(con, schema)
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.node_client_device AS SELECT smsid, "
        f"any_value(name) AS name, any_value(site_code) AS site_code, "
        f"any_value(resource_id_str) AS resource_id_str, any_value(device_os) AS device_os, "
        f"any_value(device_os_build) AS device_os_build, bool_or(is_virtual_machine) AS is_virtual_machine, "
        f"bool_or(co_managed) AS co_managed, any_value(aad_device_id) AS aad_device_id, "
        f"any_value(aad_tenant_id) AS aad_tenant_id, any_value(last_mp_server_name) AS last_mp_server_name, "
        f"any_value(primary_user_name) AS primary_user_name, "
        f"any_value(current_logon_user_name) AS current_logon_user_name, "
        f"any_value(ad_last_logon_user_name) AS ad_last_logon_user_name, "
        f"bool_or(possible) AS possible, any_value(ad_domain_sid) AS ad_domain_sid, ? AS root_site_code "
        f"FROM {schema}.node_client_device GROUP BY smsid", [root])
    logger.info("node_client_device built in schema %r", schema)
```
Call `_node_client_device(con, schema)` in `transforms()` immediately after `_node_admin_user(con, schema)`.

## Step 3b: `SCCMClientDeviceProperties` in `graph.py`

```python
@dataclass
class SCCMClientDeviceProperties(NodeProperties):
    collection_source: list[str] = field(default_factory=list, kw_only=True)
    smsid: str | None = field(default=None, kw_only=True)
    sccm_resource_id: str | None = field(default=None, kw_only=True)
    site_code: str | None = field(default=None, kw_only=True)
    device_os: str | None = field(default=None, kw_only=True)
    device_os_build: str | None = field(default=None, kw_only=True)
    is_virtual_machine: bool | None = field(default=None, kw_only=True)
    co_managed: bool | None = field(default=None, kw_only=True)
    aad_device_id: str | None = field(default=None, kw_only=True)
    aad_tenant_id: str | None = field(default=None, kw_only=True)
    last_reported_mp_server_name: str | None = field(default=None, kw_only=True)
    primary_user: str | None = field(default=None, kw_only=True)
    current_logon_user: str | None = field(default=None, kw_only=True)
    ad_last_logon_user: str | None = field(default=None, kw_only=True)
    root_site_code: str | None = field(default=None, kw_only=True)
    possible: bool = field(default=False, kw_only=True)
    sccm_ad_domain_sid: str | None = field(default=None, kw_only=True)
    sccm_infra: bool = field(default=False, kw_only=True)
```

## Step 3c: `models/sccm_client_device.py`

```python
# src/openhound_sccm/models/sccm_client_device.py
import logging
from openhound.core.asset import BaseAsset
from pydantic import ConfigDict
from ..graph import SCCMNode, SCCMClientDeviceProperties
from ..kinds import nodes as nk

logger = logging.getLogger(__name__)


class SCCMClientDevice(BaseAsset):
    model_config = ConfigDict(populate_by_name=True, extra="ignore")
    smsid: str | None = None
    name: str | None = None
    site_code: str | None = None
    resource_id_str: str | None = None
    device_os: str | None = None
    device_os_build: str | None = None
    is_virtual_machine: bool | None = None
    co_managed: bool | None = None
    aad_device_id: str | None = None
    aad_tenant_id: str | None = None
    last_mp_server_name: str | None = None
    primary_user_name: str | None = None
    current_logon_user_name: str | None = None
    ad_last_logon_user_name: str | None = None
    root_site_code: str | None = None
    possible: bool = False
    ad_domain_sid: str | None = None

    @property
    def as_node(self) -> SCCMNode | None:
        sid = (self.smsid or "").upper() or None
        if not sid:
            logger.warning("SCCMClientDevice: dropping row with no smsid")
            return None
        root = self.root_site_code or ""
        display = f"{self.name}@{self.site_code}" if (self.name and self.site_code) else (self.name or sid)
        return SCCMNode(
            id=sid, kinds=[nk.SCCM_CLIENT_DEVICE],
            properties=SCCMClientDeviceProperties(
                name=self.name or sid, displayname=display, environmentid=root or sid,
                smsid=sid, sccm_resource_id=self.resource_id_str, site_code=self.site_code,
                device_os=self.device_os, device_os_build=self.device_os_build,
                is_virtual_machine=self.is_virtual_machine, co_managed=self.co_managed,
                aad_device_id=self.aad_device_id, aad_tenant_id=self.aad_tenant_id,
                last_reported_mp_server_name=self.last_mp_server_name,
                primary_user=self.primary_user_name, current_logon_user=self.current_logon_user_name,
                ad_last_logon_user=self.ad_last_logon_user_name, root_site_code=self.root_site_code,
                possible=self.possible, sccm_ad_domain_sid=self.ad_domain_sid,
            ),
        )

    @property
    def edges(self):
        return iter(())
```
> `nk.SCCM_CLIENT_DEVICE` exists in `kinds/nodes.py` (`SCCM_CLIENT_DEVICE = "SCCM_ClientDevice"`).

## Step 3d: Register
- `main.py`: import `SCCMClientDevice`, add `("node_client_device", SCCMClientDevice)` to `NODE_SPECS`.
- `models/__init__.py`: `from .sccm_client_device import SCCMClientDevice` + add to `__all__`.

## Step 4: Run — expect PASS (3 tests). ## Step 5: Checkpoint — `git add` (stage only, NO commit).
