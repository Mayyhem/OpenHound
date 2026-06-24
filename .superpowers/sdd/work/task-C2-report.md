# Task C2 Report: SCCM_HasClient edge

**Status:** COMPLETE

**Files changed:**
- `sccm/sccm/src/openhound_sccm/transforms.py` — added `_edge_has_client` function; wired into `transforms()` immediately after `_edge_replication`
- `sccm/sccm/src/openhound_sccm/edge_has_client_test.py` — new test file (created)

**Test summary:** `test_edge_has_client` PASSED (1 passed in 1.92s)

**Staging:** both files staged via `git add`

**Notes:** None. Implementation is a straightforward `_safe` INSERT from `node_client_device` selecting `site_code AS start_id, smsid AS end_id` with `SCCM_HasClient` as kind. Possible-client rows (Task E2) will also produce HasClient edges automatically once they carry a non-null `site_code`.
