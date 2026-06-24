# Task E2: Possible-client `SCCM_ClientDevice` nodes (deterministic id, gated)

Append inferred "possible-client" rows to `node_client_device` from `ldap_cmrc_devices` (computers with the CmRcService SPN). Deterministic id `upper(object_sid)@root` (same `@root` convention as the other SCCM-native nodes; distinct from the Computer node's raw-SID id and from real client GUIDs). `ad_domain_sid = upper(object_sid)` carries the raw SID for Stage 4 SameHostAs. Gated by `--disable-possible-edges` (via `_read_disable_possible`, E1) AND on `root_site_code` being present (without a root the id would collapse to the bare SID and collide with the Computer node).

This task ALSO wires E1's gate reader into `transforms()`.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_node_client_device_possible`; in `transforms()`, immediately AFTER `_node_client_device(con, schema)`, add: `disable_possible = _read_disable_possible(con, schema)` then `_node_client_device_possible(con, schema, disable_possible)`)
- Create (test): `sccm/sccm/src/openhound_sccm/node_client_device_possible_test.py`

**Interfaces — Consumes:** `ldap_cmrc_devices` (`object_sid`, `name`), `_read_disable_possible` (E1), `_root_code`, `node_client_device` (B4, appends to it). **Produces:** possible-client rows in `node_client_device` (`possible=true`); and, via C2's `_edge_has_client` which reads `node_client_device`, their `SCCM_HasClient` edges.

## Step 1: Write the failing tests
```python
# src/openhound_sccm/node_client_device_possible_test.py
import duckdb
from openhound_sccm.transforms import transforms

def _seed(con, disable):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute(f"CREATE TABLE sccm.collection_settings AS "
                f"SELECT {str(disable).lower()} AS disable_possible_edges, false AS enable_bad_opsec")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.ldap_cmrc_devices AS SELECT "
                "'S-1-5-21-1-2-3-1104' AS object_sid, 'WS09' AS name")

def test_possible_client_emitted_when_enabled():
    con = duckdb.connect(":memory:"); _seed(con, disable=False); transforms(con)
    rows = con.execute("SELECT smsid, possible, ad_domain_sid, root_site_code "
                       "FROM sccm.node_client_device WHERE possible").fetchall()
    assert rows == [("S-1-5-21-1-2-3-1104@CAS", True, "S-1-5-21-1-2-3-1104", "CAS")]
    # C2's HasClient picks it up automatically (start = root site)
    hc = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                     "WHERE kind='SCCM_HasClient' AND end_id='S-1-5-21-1-2-3-1104@CAS'").fetchall()
    assert hc == [("CAS", "S-1-5-21-1-2-3-1104@CAS")]

def test_possible_client_suppressed_when_disabled():
    con = duckdb.connect(":memory:"); _seed(con, disable=True); transforms(con)
    cnt = con.execute("SELECT count(*) FROM sccm.node_client_device WHERE possible").fetchone()[0]
    assert cnt == 0
```

## Step 2: Run — expect failure.
`pytest .../node_client_device_possible_test.py -v`

## Step 3: `_node_client_device_possible` in `transforms.py`
```python
def _node_client_device_possible(con: duckdb.DuckDBPyConnection, schema: str, disable_possible: bool) -> None:
    """Append inferred possible-client SCCM_ClientDevice rows from ldap_cmrc_devices
    (CMBP ps1:3272, fixed to a deterministic id). id = upper(object_sid)@root — its own
    namespace, so it never merges with the Computer node (raw SID) and Stage 4 SameHostAs
    can later dedup it against a real client via ad_domain_sid. Gated by
    --disable-possible-edges and on a present root_site_code."""
    if disable_possible:
        logger.info("possible-client nodes disabled (--disable-possible-edges); skipping")
        return
    root = _root_code(con, schema)
    if not root:
        # Without a hierarchy root the id would collapse to the bare SID and collide
        # with the Computer node; a possible-client only makes sense inside a hierarchy.
        logger.warning("no root_site_code resolved; skipping possible-client nodes")
        return
    _ensure_columns(con, schema, "ldap_cmrc_devices", {"object_sid": "VARCHAR", "name": "VARCHAR"})
    _safe(con, "node_client_device_possible<-ldap_cmrc_devices",
          f"INSERT INTO {schema}.node_client_device BY NAME "
          f"SELECT upper(object_sid) || '@{root}' AS smsid, name, '{root}' AS site_code, "
          f"true AS possible, upper(object_sid) AS ad_domain_sid, '{root}' AS root_site_code "
          f"FROM {schema}.ldap_cmrc_devices WHERE object_sid IS NOT NULL")
```
`INSERT … BY NAME` with this column subset sets the other `node_client_device` columns (device_os, the `*_user_name` fields, etc.) to NULL for possible rows. In `transforms()`, immediately after `_node_client_device(con, schema)`:
```python
    disable_possible = _read_disable_possible(con, schema)
    _node_client_device_possible(con, schema, disable_possible)
```

## Step 4: Run — expect PASS (2 tests). ## Step 5: Checkpoint — `git add` (stage only).
