# Task D2: `MemberOf` edge (Computer/User → Group)

Reuse the exact `security_group_name` unnest+resolve pattern that `_node_group` already uses, but emit the edge `(resource SID → group SID)` instead of a node. From `r_system`: `start = upper(sid)` (computer); from `r_user`: `start = upper(sid)` (user). `end = pbn.sid` (the group SID resolved via `principal_by_name`, which the C1 / ope-a88e work feeds from `adminservice_user_group`). `kind = MemberOf`.

**Scope (locked decision 2026-06-23):** principal→group ONLY. Do NOT attempt group→group nesting — it isn't in the collected data (`security_group_name` is direct-only; `adminservice_user_group` has no membership column). Group→group nesting is supplied by a merged SharpHound collection on the same SID-keyed Group nodes. `MemberOf` is intentionally NOT in `TRAVERSABLE_EDGE_KINDS` (BloodHound treats native MemberOf traversable via its own schema; we mirror CMBP).

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_edge_member_of`; call from `transforms()` immediately after `_edge_has_user`)
- Create (test): `sccm/sccm/src/openhound_sccm/edge_member_of_test.py`

**Interfaces — Consumes:** `adminservice_r_system`/`wmi_r_system`/`adminservice_r_user`/`wmi_r_user` (`sid`, `security_group_name`; r_system also `obsolete`), `principal_by_name`, `_arr`. **Produces:** `MemberOf` rows in `graph_edges`.

## Step 1: Write the failing test
```python
# src/openhound_sccm/edge_member_of_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_edge_member_of_computer_and_user():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # computer in a group
    con.execute("CREATE TABLE sccm.adminservice_r_system AS SELECT 'WS01' AS name, "
                "'S-1-5-21-1-2-3-1104' AS sid, ['MAYYHEM\\SCCMAdmins'] AS security_group_name, false AS obsolete")
    # user in the same group
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'alice' AS name, "
                "'S-1-5-21-1-2-3-1106' AS sid, ['MAYYHEM\\SCCMAdmins'] AS security_group_name")
    # the group's SID (feeds principal_by_name via unique_usergroup_name)
    con.execute("CREATE TABLE sccm.adminservice_user_group AS SELECT 'S-1-5-21-1-2-3-5001' AS sid, "
                "'MAYYHEM\\SCCMAdmins' AS unique_usergroup_name, 'SCCMAdmins' AS usergroup_name, 99 AS resource_id")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='MemberOf' ORDER BY start_id").fetchall()
    assert rows == [
        ("S-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-5001"),   # computer -> group
        ("S-1-5-21-1-2-3-1106", "S-1-5-21-1-2-3-5001"),   # user -> group
    ]
```
> Backslash rule (B3): `\\` = one backslash. `security_group_name` is seeded as a list literal; `_arr` normalises list/JSON-text/scalar to `VARCHAR[]`.

## Step 2: Run — expect failure.
`pytest .../edge_member_of_test.py -v`

## Step 3: `_edge_member_of` in `transforms.py`
Mirror the `_node_group` lateral-unnest + `principal_by_name` join (read `_node_group` for the exact idiom), but SELECT the edge tuple. r_system applies the obsolete filter; r_user does not.
```python
def _edge_member_of(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Computer/User -> Group (CMBP ps1:7375/7470). Reuses the security_group_name
    unnest+resolve from _node_group; principal->group only (group->group nesting comes
    from a merged SharpHound collection, per the 2026-06-23 decision)."""
    from .kinds.edges import MEMBER_OF
    sources = (
        ("adminservice_r_system", True),
        ("wmi_r_system", True),
        ("adminservice_r_user", False),
        ("wmi_r_user", False),
    )
    for _src, drop_obsolete in sources:
        _ensure_columns(con, schema, _src, {"sid": "VARCHAR", "security_group_name": "VARCHAR", "obsolete": "BOOLEAN"})
        obsolete_clause = " AND NOT coalesce(r.obsolete, false)" if drop_obsolete else ""
        _safe(con, f"edge_member_of<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT upper(r.sid) AS start_id, pbn.sid AS end_id, '{MEMBER_OF}' AS kind "
              f"FROM {schema}.{_src} r, unnest({_arr('r.security_group_name')}) AS t(gname) "
              f"JOIN {schema}.principal_by_name pbn ON upper(trim(t.gname)) = upper(pbn.name) "
              f"WHERE r.sid IS NOT NULL AND t.gname IS NOT NULL AND trim(t.gname) != ''{obsolete_clause}")
```
Call `_edge_member_of(con, schema)` in `transforms()` immediately after `_edge_has_user(con, schema)`.

## Step 4: Run — expect PASS. ## Step 5: Checkpoint — `git add` (stage only).
