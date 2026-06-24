# fix-isassigned-report

**Status:** DONE — staged, all tests green.

**Files changed:**
- `sccm/sccm/src/openhound_sccm/transforms.py` — Arm 1 `string_split(a.collection_names, ',')` → `_arr('a.collection_names')`; Arm 3 `string_split(a.role_names, ',')` → `_arr('a.role_names')`. Added inline comments explaining why.
- `sccm/sccm/src/openhound_sccm/edge_is_assigned_test.py` — Updated admin fixtures: `collection_names` and `role_names` now JSON-array text (`'["All Systems"]'`, `'["Full Administrator"]'`, `'["Read-only Analyst"]'`). Expected edge rows unchanged.

**IsAssigned test:** 1 passed (0.47 s).

**Full suite:** 130 passed (23.26 s).
