# Task C5: `SCCM_IsAssigned` edge (AdminUser → Collection / SecurityRole)

From each admin row, `start = upper(logon_name)@root` (the AdminUser node id). Three arms:
- **→ Collection:** split `collection_names` (comma-separated names), resolve each via `collection_by_name` → `collection_id@root`.
- **→ SecurityRole (id arm):** `roles` is a role-id list → `role_id@root`.
- **→ SecurityRole (name fallback):** ONLY when `roles` is empty → split `role_names`, resolve via `role_by_name` → `role_id@root`.

**Notes:** `_safe` takes no SQL params → inline root via a Python helper `_id(col)` that builds `upper(col)@root` (or `upper(col)` when root absent), matching the B1/B2/B3 node ids so edges connect. Mirror the proven lateral-unnest pattern from `_node_group` (`FROM t a, unnest(...) AS x(col) JOIN lookup ...`). Backslash rule (B3): `\\` (one backslash) in Python test VALUES.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_edge_is_assigned`; call from `transforms()` immediately after `_edge_is_mapped_to`)
- Create (test): `sccm/sccm/src/openhound_sccm/edge_is_assigned_test.py`

**Interfaces — Consumes:** `adminservice_admins`/`wmi_admins`, `collection_by_name`, `role_by_name` (C1), `_arr`, `_root_code`. **Produces:** `SCCM_IsAssigned` rows in `graph_edges`.

## Step 1: Write the failing test

```python
# src/openhound_sccm/edge_is_assigned_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_edge_is_assigned_collection_and_role_with_name_fallback():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_site_definitions AS SELECT * FROM "
                "(VALUES ('CAS', NULL, 4)) AS t(site_code,parent_site_code,site_type)")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'PS100016' AS collection_id, 'All Systems' AS name")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT * FROM (VALUES "
                "('SMS000AR','Full Administrator'), ('SMS0001R','Read-only Analyst')) AS t(role_id, role_name)")
    # admin1: collection + role via the role-id list (roles populated, JSON-text form).
    # admin2: no roles list -> role assigned via role_names fallback.
    con.execute("CREATE TABLE sccm.adminservice_admins AS SELECT * FROM (VALUES "
                "('MAYYHEM\\a1', 'All Systems', '[\"SMS000AR\"]', 'Full Administrator'), "
                "('MAYYHEM\\a2', NULL,          NULL,            'Read-only Analyst')) "
                "AS t(logon_name, collection_names, roles, role_names)")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='SCCM_IsAssigned' ORDER BY start_id, end_id").fetchall()
    assert rows == [
        ("MAYYHEM\\A1@CAS", "PS100016@CAS"),   # collection
        ("MAYYHEM\\A1@CAS", "SMS000AR@CAS"),   # role via id list
        ("MAYYHEM\\A2@CAS", "SMS0001R@CAS"),   # role via name fallback (roles empty)
    ]
```

## Step 2: Run — expect failure.
`pytest .../edge_is_assigned_test.py -v`

## Step 3: `_edge_is_assigned` in `transforms.py`

```python
def _edge_is_assigned(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """AdminUser -> Collection / SecurityRole (CMBP ps1:7819/7841/7867).
    Collection by name; role by id-list (roles) with role_names fallback when empty.
    start/end ids are <upper(id)>@root to match the node ids."""
    from .kinds.edges import SCCM_IS_ASSIGNED
    root_lit = _root_code(con, schema) or ""

    def _id(col: str) -> str:
        return f"upper({col}) || '@{root_lit}'" if root_lit else f"upper({col})"

    start_expr = _id("a.logon_name")
    for _src in ("adminservice_admins", "wmi_admins"):
        _ensure_columns(con, schema, _src,
                        {"logon_name": "VARCHAR", "collection_names": "VARCHAR",
                         "role_names": "VARCHAR", "roles": "VARCHAR"})
        # --- AdminUser -> Collection (by name) ---
        _safe(con, f"edge_is_assigned_collection<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT {start_expr} AS start_id, {_id('cbn.collection_id')} AS end_id, "
              f"'{SCCM_IS_ASSIGNED}' AS kind "
              f"FROM {schema}.{_src} a, unnest(string_split(a.collection_names, ',')) AS t(cname) "
              f"JOIN {schema}.collection_by_name cbn ON upper(trim(t.cname)) = cbn.name "
              f"WHERE a.logon_name IS NOT NULL AND a.collection_names IS NOT NULL AND trim(t.cname) != ''")
        # --- AdminUser -> SecurityRole (role-id list) ---
        _safe(con, f"edge_is_assigned_role_id<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT {start_expr} AS start_id, {_id('t.rid')} AS end_id, "
              f"'{SCCM_IS_ASSIGNED}' AS kind "
              f"FROM {schema}.{_src} a, unnest({_arr('a.roles')}) AS t(rid) "
              f"WHERE a.logon_name IS NOT NULL AND t.rid IS NOT NULL AND trim(t.rid) != ''")
        # --- AdminUser -> SecurityRole (name fallback, only when roles empty) ---
        _safe(con, f"edge_is_assigned_role_name<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT {start_expr} AS start_id, {_id('rbn.role_id')} AS end_id, "
              f"'{SCCM_IS_ASSIGNED}' AS kind "
              f"FROM {schema}.{_src} a, unnest(string_split(a.role_names, ',')) AS t(rname) "
              f"JOIN {schema}.role_by_name rbn ON upper(trim(t.rname)) = rbn.name "
              f"WHERE a.logon_name IS NOT NULL AND a.role_names IS NOT NULL AND trim(t.rname) != '' "
              f"  AND len({_arr('a.roles')}) = 0")
```
Call `_edge_is_assigned(con, schema)` in `transforms()` immediately after `_edge_is_mapped_to(con, schema)`.

> `_id('cbn.collection_id')`/`_id('rbn.role_id')` double-upper an already-uppercased lookup value — harmless and keeps one code path. `collection_by_name`/`role_by_name` store `upper(...)` ids, so the ends equal the `SCCMCollection`/`SCCMSecurityRole` node ids (`upper(id)@root`). The `_arr`/`string_split` + lateral `unnest` mirrors `_node_group`.

## Step 4: Run — expect PASS. ## Step 5: Checkpoint — `git add` (stage only).
