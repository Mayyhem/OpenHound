# Task D4: `SCCM_HasStoredAccount` edge (Site → User/Group)

From `adminservice_reserved_accounts`/`wmi_reserved_accounts`, emit `Site → stored account`. `start = site_code` (the SCCM_Site node id); `end = upper(object_sid)` (already AD-resolved at collection). `kind = SCCM_HasStoredAccount` (not traversable). Stage 1 already set the `stored_in_sccm_site` *property* on `node_user`; this task adds the *edge*.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_edge_has_stored_account`; call from `transforms()` immediately after `_edge_has_session`)
- Create (test): `sccm/sccm/src/openhound_sccm/edge_has_stored_account_test.py`

**Interfaces — Consumes:** `adminservice_reserved_accounts`/`wmi_reserved_accounts` (`site_code`, `object_sid`). **Produces:** `SCCM_HasStoredAccount` rows in `graph_edges`.

## Step 1: Write the failing test
```python
# src/openhound_sccm/edge_has_stored_account_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_edge_has_stored_account():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_reserved_accounts AS SELECT "
                "'S-1-5-21-1-2-3-1500' AS object_sid, 'PS1' AS site_code, 'naa' AS name")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='SCCM_HasStoredAccount' ORDER BY end_id").fetchall()
    assert rows == [("PS1", "S-1-5-21-1-2-3-1500")]
```

## Step 2: Run — expect failure.
`pytest .../edge_has_stored_account_test.py -v`

## Step 3: `_edge_has_stored_account` in `transforms.py`
```python
def _edge_has_stored_account(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Site -> stored User/Group account (CMBP ps1:7147). start = site_code (the
    SCCM_Site node id); end = the reserved account's AD object_sid (resolved at
    collection). The User/Group node property stored_in_sccm_site is set in Stage 1."""
    from .kinds.edges import SCCM_HAS_STORED_ACCOUNT
    for _src in ("adminservice_reserved_accounts", "wmi_reserved_accounts"):
        _ensure_columns(con, schema, _src, {"site_code": "VARCHAR", "object_sid": "VARCHAR"})
        _safe(con, f"edge_has_stored_account<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT site_code AS start_id, upper(object_sid) AS end_id, "
              f"'{SCCM_HAS_STORED_ACCOUNT}' AS kind "
              f"FROM {schema}.{_src} WHERE site_code IS NOT NULL AND object_sid IS NOT NULL")
```
Call `_edge_has_stored_account(con, schema)` in `transforms()` immediately after `_edge_has_session(con, schema)`.

## Step 4: Run — expect PASS. ## Step 5: Checkpoint — `git add` (stage only).
