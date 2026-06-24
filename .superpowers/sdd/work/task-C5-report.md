# Task C5 Report: SCCM_IsAssigned edge

## Status
PASS

## Files changed
- **Created:** `sccm/sccm/src/openhound_sccm/edge_is_assigned_test.py`
- **Modified:** `sccm/sccm/src/openhound_sccm/transforms.py`
  - Added `_edge_is_assigned()` (3 arms × 2 sources, ~50 lines)
  - Wired `_edge_is_assigned(con, schema)` into `transforms()` immediately after `_edge_is_mapped_to(con, schema)`

## Test run
```
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/edge_is_assigned_test.py -v
```
**Output:** `1 passed in 0.44s`

## SQL deviations from spec
None. The spec SQL was used verbatim:
- Arm 1 (collection by name): `unnest(string_split(a.collection_names, ',')) AS t(cname) JOIN collection_by_name cbn ON upper(trim(t.cname)) = cbn.name`
- Arm 2 (role id list): `unnest(_arr('a.roles')) AS t(rid)` — `_arr()` handles the JSON-text `["SMS000AR"]` shape from the test and all four physical shapes documented in `_arr()`'s docstring
- Arm 3 (name fallback): `len(_arr('a.roles')) = 0` predicate gates on empty/null roles list — the `_arr()` call returns `[]` for NULL so `len([]) = 0` is true, which correctly fires the fallback for admin2 in the test

## Concerns
None. The spec + existing lateral-unnest pattern in `_node_group` were sufficient. No edge cases diverged from the brief.
