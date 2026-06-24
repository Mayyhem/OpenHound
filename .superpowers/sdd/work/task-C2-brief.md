# Task C2: `SCCM_HasClient` edge (Site → ClientDevice)

Append `SCCM_HasClient` edges to `graph_edges` (start = the site that has the client; end = the client's smsid). Reads `node_client_device` (built in B4). Real clients carry `site_code`; possible-clients (added later in E2) carry `site_code = root`, so they get HasClient automatically.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_edge_has_client`; call from `transforms()` immediately after `_edge_replication`)
- Create (test): `sccm/sccm/src/openhound_sccm/edge_has_client_test.py`

**Interfaces — Consumes:** `node_client_device(smsid, site_code, …)`, `graph_edges(start_id, end_id, kind)`. **Produces:** `SCCM_HasClient` rows in `graph_edges`.

## Step 1: Write the failing test

```python
# src/openhound_sccm/edge_has_client_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_edge_has_client():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id, kind FROM sccm.graph_edges "
                       "WHERE kind='SCCM_HasClient' ORDER BY end_id").fetchall()
    assert rows == [("PS1", "GUID-1", "SCCM_HasClient")]
```

## Step 2: Run — expect failure.
`pytest .../edge_has_client_test.py -v`

## Step 3: `_edge_has_client` in `transforms.py`

```python
def _edge_has_client(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Site -> ClientDevice (CMBP ps1:7257/7394). start = device.site_code, end = smsid."""
    from .kinds.edges import SCCM_HAS_CLIENT
    _safe(con, "edge_has_client",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT site_code AS start_id, smsid AS end_id, '{SCCM_HAS_CLIENT}' AS kind "
          f"FROM {schema}.node_client_device WHERE site_code IS NOT NULL AND smsid IS NOT NULL")
```
Call `_edge_has_client(con, schema)` in `transforms()` immediately after `_edge_replication(con, schema)`.

## Step 4: Run — expect PASS. ## Step 5: Checkpoint — `git add` (stage only).
