# Task D1 Report: HasPrimaryUser / HasCurrentUser / HasADLastLogonUser

**Status:** COMPLETE

**Files changed:**
- `sccm/sccm/src/openhound_sccm/edge_has_user_test.py` (created — test for all three edge kinds)
- `sccm/sccm/src/openhound_sccm/transforms.py` (added `_edge_has_user`; called from `transforms()` immediately after `_edge_is_assigned`)

**Test summary:** 1 passed — `test_edge_has_user_three_kinds` confirms all three Has*User edges emit correct (start_id=smsid, end_id=SID, kind) tuples via principal_by_name resolution.

**No concerns.**
