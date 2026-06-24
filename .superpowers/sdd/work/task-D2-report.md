# Task D2 Report: `MemberOf` edge (Computer/User → Group)

**Status:** COMPLETE — all tests pass.

**Files changed:**
- `sccm/sccm/src/openhound_sccm/edge_member_of_test.py` — created (new test)
- `sccm/sccm/src/openhound_sccm/transforms.py` — added `_edge_member_of`; wired into `transforms()` after `_edge_has_user`

**Test summary:** `1 passed` — `test_edge_member_of_computer_and_user` verifies both computer→group and user→group MemberOf edges are emitted with correct SIDs.

**Notes:**
- Mirrors the exact `_node_group` lateral-unnest + `principal_by_name` join idiom.
- `r_system` sources apply `NOT coalesce(r.obsolete, false)`; `r_user` sources do not (no obsolete flag).
- Group→group nesting is out of scope per the 2026-06-23 locked decision.
- `MemberOf` is intentionally absent from `TRAVERSABLE_EDGE_KINDS` (BloodHound handles native MemberOf traversal via its own schema).
