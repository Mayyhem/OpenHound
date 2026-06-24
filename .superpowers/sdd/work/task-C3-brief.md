# Task C3: `SCCM_HasMember` edge (Collection → device/user/group)

For each collection membership, emit `Collection → member`. Member resolution: a device member → `device_by_resourceid` (the ClientDevice `smsid`); a user/group member → `resource_to_sid` (the SID). Built-in pseudo-resources are skipped.

**Key/casing notes:**
- Collection node id = `upper(collection_id)@root` (matches the B1 model). Since `_safe` does NOT accept SQL params, inline the root as a literal suffix (site codes are 3 alphanumerics — safe). Build the start expression in Python to match the model exactly: `upper(collection_id)@root` when root present, else `upper(collection_id)`.
- Member key = `<resource_id>@<site_code>` (matches the `resource_to_sid`/`device_by_resourceid` keys built in C1).
- Prefer the device (smsid) over the SID via `coalesce(d.smsid, r.sid)` so device members map to the ClientDevice node (CMBP behaviour).
- Built-in member resource_ids to skip (CMBP ps1:7639-7647): `2046820352`, `2046820353`, and anything `LIKE '203004%'` (provisioning).

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_edge_has_member`; call from `transforms()` immediately after `_edge_has_client`)
- Create (test): `sccm/sccm/src/openhound_sccm/edge_has_member_test.py`

**Interfaces — Consumes:** `device_by_resourceid`, `resource_to_sid` (C1), `adminservice_collection_members`/`wmi_collection_members`, `_root_code`. **Produces:** `SCCM_HasMember` rows in `graph_edges`.

## Step 1: Write the failing test

```python
# src/openhound_sccm/edge_has_member_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_edge_has_member_device_and_user_skip_builtin():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # single primary PS1 -> root resolves to PS1
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    # a device resource (-> ClientDevice smsid) and a user resource (-> user SID)
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'alice' AS name, "
                "'S-1-5-21-1-2-3-1106' AS sid, 9 AS resource_id, 'PS1' AS source_site_code")
    # memberships: device (7), user (9), and a built-in pseudo-resource (skipped)
    con.execute("CREATE TABLE sccm.adminservice_collection_members AS SELECT * FROM (VALUES "
                "('PS100016', 7, 'PS1'), ('PS100016', 9, 'PS1'), ('PS100016', 2046820352, 'PS1')) "
                "AS t(collection_id, resource_id, site_code)")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='SCCM_HasMember' ORDER BY end_id").fetchall()
    assert rows == [("PS100016@PS1", "GUID-1"), ("PS100016@PS1", "S-1-5-21-1-2-3-1106")]
```

## Step 2: Run — expect failure.
`pytest .../edge_has_member_test.py -v`

## Step 3: `_edge_has_member` in `transforms.py`

```python
def _edge_has_member(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Collection -> member (CMBP ps1:7617-7647). Device member -> ClientDevice smsid;
    user/group member -> SID. Built-in pseudo-resources skipped. Collection start id
    is upper(collection_id)@root (matches the SCCMCollection node id)."""
    from .kinds.edges import SCCM_HAS_MEMBER
    root_lit = _root_code(con, schema) or ""
    start_expr = (f"upper(cm.collection_id) || '@{root_lit}'" if root_lit
                  else "upper(cm.collection_id)")
    for _src in ("adminservice_collection_members", "wmi_collection_members"):
        _ensure_columns(con, schema, _src, {"collection_id": "VARCHAR", "resource_id": "BIGINT", "site_code": "VARCHAR"})
        _safe(con, f"edge_has_member<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT {start_expr} AS start_id, coalesce(d.smsid, r.sid) AS end_id, "
              f"'{SCCM_HAS_MEMBER}' AS kind "
              f"FROM {schema}.{_src} cm "
              f"LEFT JOIN {schema}.device_by_resourceid d "
              f"  ON d.resource_key = CAST(cm.resource_id AS VARCHAR) || '@' || CAST(cm.site_code AS VARCHAR) "
              f"LEFT JOIN {schema}.resource_to_sid r "
              f"  ON r.resource_key = CAST(cm.resource_id AS VARCHAR) || '@' || CAST(cm.site_code AS VARCHAR) "
              f"WHERE cm.collection_id IS NOT NULL "
              f"  AND coalesce(d.smsid, r.sid) IS NOT NULL "
              f"  AND CAST(cm.resource_id AS VARCHAR) NOT IN ('2046820352', '2046820353') "
              f"  AND CAST(cm.resource_id AS VARCHAR) NOT LIKE '203004%'")
```
Call `_edge_has_member(con, schema)` in `transforms()` immediately after `_edge_has_client(con, schema)`.

## Step 4: Run — expect PASS. ## Step 5: Checkpoint — `git add` (stage only).
