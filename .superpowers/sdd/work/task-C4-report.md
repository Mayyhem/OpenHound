# Task C4 Report: `SCCM_IsMappedTo` edge

**Status:** COMPLETE

**Files changed:**
- `sccm/sccm/src/openhound_sccm/edge_is_mapped_to_test.py` (created)
- `sccm/sccm/src/openhound_sccm/transforms.py` (added `_edge_is_mapped_to`; wired into `transforms()` after `_edge_has_member`)

**Test summary:** 1 passed — `test_edge_is_mapped_to_direct_sid_and_name_resolution` covers direct `admin_sid` path and name-only resolution via `principal_by_name`.

**No concerns.**
