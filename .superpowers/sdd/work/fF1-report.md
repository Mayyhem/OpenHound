# Phase F1 Report

**Status:** COMPLETE — all 4 tests green.

**Files changed:**
- `sccm/sccm/tests/convert_integration_test.py` — extended seed + Stage 2 assertions
- `sccm/sccm/tests/preproc_map_test.py` — added `collection_settings` assertion

**Stage 2 kinds asserted in the integration test:**
- Node kind `SCCM_Collection` (id `SMS00001@CAS`) from seeded `adminservice_collections`
- Node kind `SCCM_AdminUser` (id `MAYYHEM\SCCM-ADMIN@CAS`) from seeded `adminservice_admins`
- Edge kind `SCCM_IsMappedTo` (admin_sid → SCCM_AdminUser node) from `_edge_is_mapped_to`
- Edge kind `SCCM_HasClient` (site_code → smsid) from seeded `adminservice_client_devices` via `_edge_has_client`

**Test result:** 4 passed in 27s (`convert_integration_test.py` + `preproc_map_test.py`).

**No concerns.**
