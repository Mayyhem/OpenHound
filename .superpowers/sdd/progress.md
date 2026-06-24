# Stage 2 (ope-2ff3) — subagent-driven progress ledger
Plan: sccm/sccm/docs/superpowers/plans/2026-06-23-sccm-preproc-convert-stage2.md
Mechanic: no commits (CLAUDE.md); per-task diffs via ephemeral git tree snapshots; implementers stage only.
Stop gate: after Phase E (re-collect required before Phase F).

## Tasks
(pending)

- Task A1: complete (tree 2b4df8f..f4c86954, review clean). Minor (non-blocking, deferred to final): pre-existing redundant `or {}` guard; warning-path untested (brief didn't require).
- Task A2: complete (tree f4c86954..f0b7654e, review clean). collection_settings resource wired into DISCOVERY_RESOURCE_NAMES (consumed at main.py:967) + source() return + _preproc_table_map. Phase A done.
- Task B1: complete (tree f0b7654e..d32ac283, review clean after 1 fix). FIX: collection_type mapping corrected to {0:Other,1:User,2:Device} per CMBP:1741 (bug originated in plan; plan doc corrected); collection_variables_count now flows through. node_collection + SCCMCollection + _root_code helper.
- Task B2: complete (tree d32ac283..(B2), review clean, no fixes). node_security_role + SCCMSecurityRole.
- Task B3: complete (tree (B2)..(B3), review clean, DONE_WITH_CONCERNS resolved). node_admin_user (stores original-case logon_name, dedup GROUP BY upper(logon_name); model uppercases for id) + SCCMAdminUser. NOTE for C4/C5: use `\` (one backslash) in Python test VALUES for DOMAIN\user logons.
- Task B4: complete (tree (B3)..(B4), review clean, 2 minor non-blocking). node_client_device (real clients, possible/ad_domain_sid placeholders) + SCCMClientDevice. PHASE B DONE.
- DESIGN CHANGE for Phase C: graph_edges stays 3-col (start_id,end_id,kind) — NO JSON properties column (DuckDB returns JSON as str -> would break GraphEdge.properties:dict). Edge collection_source deferred (YAGNI; Stage 1 edges had none). Edge builders SELECT start_id,end_id,kind only. GraphEdge sets traversable from TRAVERSABLE_EDGE_KINDS.
- Task C0: complete (tree (B4)..(C0), review clean). ReplicationEdge->GraphEdge (generic; sets traversable from TRAVERSABLE_EDGE_KINDS); kinds/edges.py +10 kinds +allowlist; SCCMEdgeProperties; _graph_edges split -> _graph_edges_init + _edge_replication. graph_edges stays 3-col. 8 tests pass.
- Task C1: complete (tree (C0)..(C1), review clean, 1 minor non-blocking). resource_to_sid, device_by_resourceid, collection_by_name, role_by_name + principal_by_name enriched (unique_user_name/full_user_name/user_principal_name). 5 tests pass.
- Task C2: complete (tree (C1)..(C2), review clean). _edge_has_client (Site->ClientDevice). Note: edge builders import kind constants in-function (consistent w/ _edge_replication).
- Task C3: complete (tree (C2)..(C3), review clean). _edge_has_member (Collection->device/user; coalesce device-then-sid; built-in filter; start=collection_id@root). 1 test.
- Task C4: complete (tree (C3)..(C4), review clean). _edge_is_mapped_to (AD principal->AdminUser; coalesce(admin_sid, pbn.sid); end=logon@root). 1 test.
- Task C5: complete (tree (C4)..(C5), review clean). _edge_is_assigned (AdminUser->Collection by name; ->Role by id-list w/ role_names fallback gated on len(_arr(roles))=0). 1 test. PHASE C DONE.
- Task D1: complete (tree (C5)..(D1), review clean). _edge_has_user (3 ClientDevice->User kinds; name-only fields resolved via principal_by_name; INNER JOIN drops unresolved). 1 test.
- Task D2: complete (tree (D1)..(D2), review clean). _edge_member_of (Computer/User->Group; reuses _node_group unnest+principal_by_name; principal->group only, nesting via SharpHound). 1 test.
- Task D3: complete (tree (D2)..(D3), review clean; full suite 119/119). _edge_has_session (RemoteRegistry host->user + MSSQL site_systems svc-acct->host, domain-only gate). DEFERRED-MINOR (final review): wmi_site_systems arm not separately test-covered (schema-identical mirror of tested adminservice arm; applies to ALL Stage 2 tasks' wmi arms by convention).
- Task D4: complete (tree (D3)..(D4), review clean). _edge_has_stored_account (Site->User/Group from reserved_accounts). 1 test. PHASE D DONE.
- Task E1: complete (tree (D4)..(E1), review clean). _read_disable_possible gate reader (absent->False). 3 tests. Not yet wired (E2 wires it).
- Task E2: complete (tree (E1)..(E2), review clean). _node_client_device_possible (id=object_sid@root, gated on disable+root; ad_domain_sid=raw SID for Stage4) + wired _read_disable_possible into transforms(). HasClient auto-covers possibles. 2 tests.
- Task E3: complete (tree (E2)..(E3), review clean, no findings). _node_backfill (stub nodes for nodeless edge endpoints, inferred kind + warn) + StubNode + BACKFILL_END_KIND. 4 tests; FULL SUITE 129 passed. PHASE E DONE.
- ===== RE-COLLECT GATE: Phases A-E complete. Phase F (docs + code-tour harness) needs the user's single lab re-collect (covers A1 host-sid, A2 collection_settings, + ope-a88e user_group). =====
- FINAL whole-branch review (opus): fix-then-merge. ID consistency/ordering/root-inlining/backfill all CLEAN. Fixes applied:
  - [Important] graph_edges dedup -> _graph_edges_dedup (after edges, before backfill). dedup test + full suite 130 passed.
  - [Minor] stale _graph_edges docstrings in graph_edges_test.py + transforms_test.py fixed.
- DEFERRED to Phase F (real-data decision): backfill misses model-DROPPED builtin SIDs (e.g. S-1-5-32-544) reached by MemberOf/HasMember/HasStoredAccount — node_* row exists so _existing_ids skips it, but UserNode/GroupNode drop non-domain SIDs w/o fallback -> dangling edge. Latent (collected data is domain-direct). Revisit with re-collected data; interacts with locked Stage 1 drop rule.
- DEFERRED to Phase F: README:434 stale link to deleted models/replication_edge.py (README rewrite is Task F2).
- STATUS: Phases A-E COMPLETE + final-review fixes. All staged (NO commit per CLAUDE.md). Awaiting user: review+commit, then ONE lab re-collect, then Phase F.

== PHASE F (post-recollect, /tmp/redo) ==
- REAL-DATA VALIDATION: all 4 Stage 2 node kinds present (collection 10, role 17, admin 3, client_device 31 + 13 possible). Edges present EXCEPT IsAssigned=0 (BUG). node_backfill=0. collection_settings(disable=F,bad_opsec=F).
- [CRITICAL BUG found] C5 IsAssigned: real collection_names/role_names are JSON-array TEXT ('["All Systems",...]'), but C5 used string_split(',') -> garbage -> 0 edges. roles already uses _arr. FIX: use _arr() for collection_names + role_names too (superset; existing test stays green).
- DEFERRED builtin-SID concern: NOT triggered on real data (no S-1-5-32-* endpoints; security_group_name is domain-direct). Keep backfill as-is; document latent gap. Resolved.
- IsAssigned FIX confirmed on real data: re-preprocess+re-convert -> IsAssigned=9 (e.g. DOMAINADMIN@CAS->SMS0001R@CAS Full Admin role + collection scopes, deduped). Graph JSON has all 4 node kinds + all edge kinds. PHASE F real-data validation PASS.
- TEST RELOCATION: 46 co-located *_test.py moved (git mv) into tests/ (kept *_test.py names, collision-free); 3 needed relative-import fixes. tests/ now 421 passed / 13 failed / 5 skipped; src collects 0.
- 13 FAILURES = PRE-EXISTING STALE TESTS (not Stage 2): tests/test_lookup_computer_site_system_roles.py + tests/test_transforms_computer_roles.py test a removed lookup/transform design (computer_site_system_roles / site_types / computer_mp_roles). Verified: gone from current code AND from HEAD before my changes (old commits 8c8e366/d1ba4a5/0f7554f). They were never moved by me. DECISION NEEDED from user: delete stale tests or leave.
- per_host_phases_test.py moved but has 0 test functions (it's a fixture helper) — candidate to become conftest/fixtures later.
- PHASE F: F1 integration+preproc tests refreshed (assert Stage 2 kinds + collection_settings); F2 README + ARCHITECTURE updated (Node/Edge Reference, Limitations, CLI, Testing->pytest tests, stale replication_edge link fixed, ARCHITECTURE §11 + changelog incl. stub-backfill divergence); F3 validation doc written (real-data results). Final suite: 421 passed / 5 skipped / 13 pre-existing-stale failed.
- ALL STAGED (no commit). OPEN DECISIONS for user: (1) delete the 13 stale tests? (2) add Stage 2 code-tour launch.json profile? (3) commit.
- USER DECISIONS applied: (1) deleted 2 stale test files -> suite now 421 passed / 5 skipped / 0 failed. (2) added tour_driver_stage2.py + "Debug: Stage 2 code tour" launch profile (verified: emits all 4 entity nodes + possible-client + every Stage 2 edge kind incl IsAssigned + both HasSession arms; AdminsReplicatedTo CAS<->PS1 + PS1->SEC).
- Validation doc corrected: real topology CAS -> PS1 (primary) -> SEC (secondary), NOT "2 primaries" (user catch; 3 replication edges = 2 + 1 confirms it).
- STAGE 2 COMPLETE. All staged (no commit). Final suite 421/5/0.
