# Task D1: `SCCM_HasPrimaryUser` / `HasCurrentUser` / `HasADLastLogonUser` (ClientDevice → User)

From `node_client_device`, resolve each name-only user field to a SID via `principal_by_name` (enriched in C1 so `DOMAIN\user` forms resolve). Emit `start = smsid`, `end = user SID`. Unresolved → dropped (the JOIN).

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_edge_has_user`; call from `transforms()` immediately after `_edge_is_assigned`)
- Create (test): `sccm/sccm/src/openhound_sccm/edge_has_user_test.py`

**Interfaces — Consumes:** `node_client_device` (B4: `primary_user_name`/`current_logon_user_name`/`ad_last_logon_user_name`), `principal_by_name`. **Produces:** the three `Has*User` kinds in `graph_edges`.

## Step 1: Write the failing test
```python
# src/openhound_sccm/edge_has_user_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_edge_has_user_three_kinds():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('PS1', NULL, 2)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete, "
                "'MAYYHEM\\alice' AS primary_user, 'MAYYHEM\\bob' AS current_logon_user, "
                "'MAYYHEM\\carol' AS user_name")
    # principal_by_name gets these via the C1 unique_user_name enrichment
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT * FROM (VALUES "
                "('alice','S-1-5-21-1-2-3-1201','MAYYHEM\\alice'), "
                "('bob',  'S-1-5-21-1-2-3-1202','MAYYHEM\\bob'), "
                "('carol','S-1-5-21-1-2-3-1203','MAYYHEM\\carol')) AS t(name, sid, unique_user_name)")
    transforms(con)
    rows = con.execute("SELECT kind, start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind LIKE 'SCCM_Has%User' ORDER BY kind").fetchall()
    assert rows == [
        ("SCCM_HasADLastLogonUser", "GUID-1", "S-1-5-21-1-2-3-1203"),
        ("SCCM_HasCurrentUser",     "GUID-1", "S-1-5-21-1-2-3-1202"),
        ("SCCM_HasPrimaryUser",     "GUID-1", "S-1-5-21-1-2-3-1201"),
    ]
```
> Backslash rule (B3): `\\` (one backslash) in Python VALUES.

## Step 2: Run — expect failure.
`pytest .../edge_has_user_test.py -v`

## Step 3: `_edge_has_user` in `transforms.py`
```python
def _edge_has_user(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """ClientDevice -> User for the three device user fields (CMBP ps1:7266/7275/7298).
    Each name-only field is resolved to a SID via principal_by_name; unresolved drops."""
    from .kinds.edges import (
        SCCM_HAS_PRIMARY_USER, SCCM_HAS_CURRENT_USER, SCCM_HAS_AD_LAST_LOGON_USER,
    )
    for col, kind in (
        ("primary_user_name", SCCM_HAS_PRIMARY_USER),
        ("current_logon_user_name", SCCM_HAS_CURRENT_USER),
        ("ad_last_logon_user_name", SCCM_HAS_AD_LAST_LOGON_USER),
    ):
        _safe(con, f"edge_has_user<-{kind}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT cd.smsid AS start_id, pbn.sid AS end_id, '{kind}' AS kind "
              f"FROM {schema}.node_client_device cd "
              f"JOIN {schema}.principal_by_name pbn ON upper(trim(cd.{col})) = upper(pbn.name) "
              f"WHERE cd.smsid IS NOT NULL AND cd.{col} IS NOT NULL AND trim(cd.{col}) != ''")
```
Call `_edge_has_user(con, schema)` in `transforms()` immediately after `_edge_is_assigned(con, schema)`.

## Step 4: Run — expect PASS. ## Step 5: Checkpoint — `git add` (stage only).
