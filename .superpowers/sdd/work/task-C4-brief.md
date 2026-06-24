# Task C4: `SCCM_IsMappedTo` edge (AD principal → SCCM_AdminUser)

For each admin, emit `AD principal SID → AdminUser`. Start = `upper(admin_sid)` if present, else the `logon_name` resolved via `principal_by_name`. End = the AdminUser node id `upper(logon_name)@root` (matches the B3 model). Drop (the `WHERE`) when no SID can be determined.

**Notes:** `_safe` takes no SQL params, so inline root as a literal suffix (build `end_expr` in Python, matching the B3 node id incl. the root-absent branch). Backslash rule (B3): in Python test VALUES use `\\` (ONE backslash stored) for `DOMAIN\user`.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_edge_is_mapped_to`; call from `transforms()` immediately after `_edge_has_member`)
- Create (test): `sccm/sccm/src/openhound_sccm/edge_is_mapped_to_test.py`

**Interfaces — Consumes:** `adminservice_admins`/`wmi_admins`, `principal_by_name`, `_root_code`. **Produces:** `SCCM_IsMappedTo` rows in `graph_edges`.

## Step 1: Write the failing test

```python
# src/openhound_sccm/edge_is_mapped_to_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_edge_is_mapped_to_direct_sid_and_name_resolution():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    # admin 1: has admin_sid directly. admin 2: name-only, resolved via principal_by_name.
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT * FROM (VALUES "
                "('MAYYHEM\\sccmadmin','S-1-5-21-1-2-3-1110', false), "
                "('MAYYHEM\\helpdesk', NULL,               true)) "
                "AS t(logon_name, admin_sid, is_group)")
    # provides (name, sid) for the name-only admin via principal_by_name unique_user_name enrichment
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'helpdesk' AS name, "
                "'S-1-5-21-1-2-3-1200' AS sid, 'MAYYHEM\\helpdesk' AS unique_user_name")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='SCCM_IsMappedTo' ORDER BY end_id").fetchall()
    assert rows == [
        ("S-1-5-21-1-2-3-1200", "MAYYHEM\\HELPDESK@CAS"),   # name-only -> resolved SID
        ("S-1-5-21-1-2-3-1110", "MAYYHEM\\SCCMADMIN@CAS"),   # direct admin_sid
    ]
```

## Step 2: Run — expect failure.
`pytest .../edge_is_mapped_to_test.py -v`

## Step 3: `_edge_is_mapped_to` in `transforms.py`

```python
def _edge_is_mapped_to(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """AD principal -> SCCM_AdminUser (CMBP ps1:7789-7807). start = upper(admin_sid)
    if present, else logon_name resolved via principal_by_name; end = upper(logon_name)@root."""
    from .kinds.edges import SCCM_IS_MAPPED_TO
    root_lit = _root_code(con, schema) or ""
    end_expr = (f"upper(a.logon_name) || '@{root_lit}'" if root_lit else "upper(a.logon_name)")
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src, {"admin_sid": "VARCHAR", "logon_name": "VARCHAR"})
        _safe(con, f"edge_is_mapped_to<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT coalesce(upper(a.admin_sid), pbn.sid) AS start_id, {end_expr} AS end_id, "
              f"'{SCCM_IS_MAPPED_TO}' AS kind "
              f"FROM {schema}.{_src} a "
              f"LEFT JOIN {schema}.principal_by_name pbn ON upper(trim(a.logon_name)) = upper(pbn.name) "
              f"WHERE a.logon_name IS NOT NULL AND coalesce(upper(a.admin_sid), pbn.sid) IS NOT NULL")
```
Call `_edge_is_mapped_to(con, schema)` in `transforms()` immediately after `_edge_has_member(con, schema)`.

> Fan-out note: when `admin_sid` is present, the `principal_by_name` join may still match (same SID) — `coalesce` keeps `admin_sid`, producing the same edge once. If a `logon_name` legitimately resolves to multiple SIDs in `principal_by_name`, multiple edges result (acceptable; BloodHound dedups identical edges). The test seeds one match per logon so no fan-out occurs.

## Step 4: Run — expect PASS. ## Step 5: Checkpoint — `git add` (stage only).
