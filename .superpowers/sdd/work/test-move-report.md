# Test File Relocation Report

**Date:** 2026-06-24

## Summary

Moved all `*_test.py` files from `sccm/sccm/src/openhound_sccm/` (and subdirs) into `sccm/sccm/tests/`, flattened (no subdirectories). All moves staged with git (no commit). Three files required import fixes.

---

## Files Moved

**Total: 48 files** (46 tracked via `git mv`, 2 untracked via copy + `git add`)

| # | Source path (relative to repo root) | Destination basename |
|---|--------------------------------------|----------------------|
| 1 | `sccm/sccm/src/openhound_sccm/clients/ad_test.py` | `ad_test.py` |
| 2 | `sccm/sccm/src/openhound_sccm/collectors/collection_settings_test.py` | `collection_settings_test.py` |
| 3 | `sccm/sccm/src/openhound_sccm/collectors/privileged_test.py` | `privileged_test.py` |
| 4 | `sccm/sccm/src/openhound_sccm/collectors/registry_current_user_test.py` | `registry_current_user_test.py` |
| 5 | `sccm/sccm/src/openhound_sccm/collectors/registry_test.py` | `registry_test.py` |
| 6 | `sccm/sccm/src/openhound_sccm/convert_integration_test.py` | `convert_integration_test.py` |
| 7 | `sccm/sccm/src/openhound_sccm/convert_pipeline_test.py` | `convert_pipeline_test.py` |
| 8 | `sccm/sccm/src/openhound_sccm/edge_has_client_test.py` | `edge_has_client_test.py` |
| 9 | `sccm/sccm/src/openhound_sccm/edge_has_member_test.py` | `edge_has_member_test.py` |
| 10 | `sccm/sccm/src/openhound_sccm/edge_has_session_test.py` *(untracked)* | `edge_has_session_test.py` |
| 11 | `sccm/sccm/src/openhound_sccm/edge_has_stored_account_test.py` | `edge_has_stored_account_test.py` |
| 12 | `sccm/sccm/src/openhound_sccm/edge_has_user_test.py` *(untracked)* | `edge_has_user_test.py` |
| 13 | `sccm/sccm/src/openhound_sccm/edge_is_assigned_test.py` | `edge_is_assigned_test.py` |
| 14 | `sccm/sccm/src/openhound_sccm/edge_is_mapped_to_test.py` | `edge_is_mapped_to_test.py` |
| 15 | `sccm/sccm/src/openhound_sccm/edge_member_of_test.py` | `edge_member_of_test.py` |
| 16 | `sccm/sccm/src/openhound_sccm/graph_edges_dedup_test.py` | `graph_edges_dedup_test.py` |
| 17 | `sccm/sccm/src/openhound_sccm/graph_edges_test.py` | `graph_edges_test.py` |
| 18 | `sccm/sccm/src/openhound_sccm/graph_test.py` | `graph_test.py` |
| 19 | `sccm/sccm/src/openhound_sccm/lookup_test.py` | `lookup_test.py` |
| 20 | `sccm/sccm/src/openhound_sccm/models/__init___test.py` | `__init___test.py` |
| 21 | `sccm/sccm/src/openhound_sccm/models/computer_test.py` | `computer_test.py` |
| 22 | `sccm/sccm/src/openhound_sccm/models/graph_edge_test.py` | `graph_edge_test.py` |
| 23 | `sccm/sccm/src/openhound_sccm/models/group_test.py` | `group_test.py` |
| 24 | `sccm/sccm/src/openhound_sccm/models/sccm_admin_user_test.py` | `sccm_admin_user_test.py` |
| 25 | `sccm/sccm/src/openhound_sccm/models/sccm_client_device_test.py` | `sccm_client_device_test.py` |
| 26 | `sccm/sccm/src/openhound_sccm/models/sccm_collection_test.py` | `sccm_collection_test.py` |
| 27 | `sccm/sccm/src/openhound_sccm/models/sccm_security_role_test.py` | `sccm_security_role_test.py` |
| 28 | `sccm/sccm/src/openhound_sccm/models/sccm_site_test.py` | `sccm_site_test.py` |
| 29 | `sccm/sccm/src/openhound_sccm/models/stub_node_test.py` | `stub_node_test.py` |
| 30 | `sccm/sccm/src/openhound_sccm/models/user_test.py` | `user_test.py` |
| 31 | `sccm/sccm/src/openhound_sccm/node_admin_user_test.py` | `node_admin_user_test.py` |
| 32 | `sccm/sccm/src/openhound_sccm/node_backfill_test.py` | `node_backfill_test.py` |
| 33 | `sccm/sccm/src/openhound_sccm/node_client_device_possible_test.py` | `node_client_device_possible_test.py` |
| 34 | `sccm/sccm/src/openhound_sccm/node_client_device_test.py` | `node_client_device_test.py` |
| 35 | `sccm/sccm/src/openhound_sccm/node_collection_test.py` | `node_collection_test.py` |
| 36 | `sccm/sccm/src/openhound_sccm/node_computer_test.py` | `node_computer_test.py` |
| 37 | `sccm/sccm/src/openhound_sccm/node_group_test.py` | `node_group_test.py` |
| 38 | `sccm/sccm/src/openhound_sccm/node_security_role_test.py` | `node_security_role_test.py` |
| 39 | `sccm/sccm/src/openhound_sccm/node_site_test.py` | `node_site_test.py` |
| 40 | `sccm/sccm/src/openhound_sccm/node_user_test.py` | `node_user_test.py` |
| 41 | `sccm/sccm/src/openhound_sccm/per_host_phases_streams_test.py` | `per_host_phases_streams_test.py` |
| 42 | `sccm/sccm/src/openhound_sccm/per_host_phases_test.py` | `per_host_phases_test.py` |
| 43 | `sccm/sccm/src/openhound_sccm/preproc_map_test.py` | `preproc_map_test.py` |
| 44 | `sccm/sccm/src/openhound_sccm/transforms_hardening_test.py` | `transforms_hardening_test.py` |
| 45 | `sccm/sccm/src/openhound_sccm/transforms_lookups_test.py` | `transforms_lookups_test.py` |
| 46 | `sccm/sccm/src/openhound_sccm/transforms_principal_test.py` | `transforms_principal_test.py` |
| 47 | `sccm/sccm/src/openhound_sccm/transforms_settings_test.py` | `transforms_settings_test.py` |
| 48 | `sccm/sccm/src/openhound_sccm/transforms_test.py` | `transforms_test.py` |

---

## Files That Needed Edits

### 1. `sccm/sccm/tests/per_host_phases_test.py`

**What this file is:** Not a test file in the usual sense — it's a fixture/helper module that defines `PER_HOST_PHASES` and `all_table_names()` for use by two existing test files. It was embedded in the `openhound_sccm` package (which is why it used relative imports), and imported as `from openhound_sccm.per_host_phases_test import ...`.

**What changed:** Two relative imports converted to absolute:
```python
# Before
from .collectors import stubs
from .phased_pipeline import Phase

# After
from openhound_sccm.collectors import stubs
from openhound_sccm.phased_pipeline import Phase
```

### 2. `sccm/sccm/tests/test_per_host_phases.py`

**What changed:** Import updated to reference the new location:
```python
# Before
from openhound_sccm.per_host_phases_test import PER_HOST_PHASES, all_table_names

# After
from tests.per_host_phases_test import PER_HOST_PHASES, all_table_names
```

### 3. `sccm/sccm/tests/test_per_host_integration.py`

**What changed:** Same import fix as above.

---

## Test Results

### `tests/` directory
```
13 failed, 421 passed, 5 skipped, 145 warnings, 98 subtests passed
```

**The 13 failures are pre-existing** and unrelated to this move:
- 7 in `test_lookup_computer_site_system_roles.py`: `SCCMLookup` missing `computer_site_system_roles` attribute
- 6 in `test_transforms_computer_roles.py`: `site_types` table does not exist in DuckDB

Both failing test files existed in `tests/` before this move (confirmed via `git show HEAD`) and the failures reflect implementation gaps, not import errors.

### `src/` directory
```
no tests ran  (exit code 5)
```
Zero tests collected from src — confirmed clean.

---

## Concerns

1. **`per_host_phases_test.py` is a helper module, not a pure test file.** It defines shared fixtures (`PER_HOST_PHASES`) used by `test_per_host_phases.py` and `test_per_host_integration.py`. It has no test functions of its own. Keeping it named `*_test.py` is fine because pytest just collects it as a module, finds no test functions, and moves on. However, its role as a shared fixture means it might be better placed in a `conftest.py` or a separate `fixtures/` module in the future.

2. **`__init___test.py`** (note: three underscores): this tests the `models/__init__.py` module. The basename is slightly odd but unchanged from the original.

3. **No `pytest.ini` / `[tool.pytest.ini_options]`:** The project has no pytest configuration file. Pytest autodiscovery picks up both `test_*.py` and `*_test.py` patterns, so the mixed naming convention (`test_*.py` existing files + `*_test.py` moved files) works fine out of the box.
