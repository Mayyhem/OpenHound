# SDD Progress — Collect summary per-run metric (ticket ope-4c6f)

Plan: sccm/sccm/docs/superpowers/plans/2026-06-29-collect-summary-per-run-metric.md
Branch: ohsccm
NOTE: No commits per CLAUDE.md — owner commits manually. Reviews use working-tree diffs.

- [x] Task 1: _normalize_row_counts helper — complete (no commit; spec PASS, review clean except 1 Minor)
- [x] Task 2: _log_collect_summary rewrite — complete (no commit; spec PASS, quality Approved, no actionable findings)
- [x] Task 3: wire counts into collect_sccm + _run_per_host_stage — complete (no commit; spec PASS, quality Approved)

## Minor findings (for final whole-branch review fix wave)
- [Task 1] tests/collect_summary_test.py::test_normalize_row_counts_returns_empty_when_no_normalize_info
  passes `_FakeTrace(None)` instead of the spec's `_FakePipeline(_FakeTrace(None))`, so it hits the
  except branch rather than the `if info is None` branch it names. Fix: restore the spec's verbatim arg.

---

# SDD Progress — Split AD nodes/edges into a separate untagged OpenGraph file (ticket ope-6aa7)

Plan: sccm/sccm/docs/superpowers/plans/2026-06-29-split-ad-nodes-edges-output.md
Branch: ohsccm
NOTE: No commits per CLAUDE.md — owner commits manually. Reviews use working-tree diffs.
NOTE: main.py has unrelated pre-existing uncommitted changes (ope-4c6f collect-summary); Task 3
      review uses a pre-task snapshot of main.py to isolate this ticket's diff. Other task files
      are clean vs HEAD b4b2e3a.

- [x] Task 1: Preproc edge split (_graph_edges_split) — complete (no commit; spec ✅, quality Approved; 2 Minor)
- [x] Task 2: Untagged destination + parameterized emit_graph_from_duckdb — complete (no commit; spec ✅, 1 Important + 1 Minor fixed, re-review Approved)
- [x] Task 3: Split convert specs + two-pass convert — complete (no commit; spec ✅, all 4 named risks clean, quality Approved; brief test seed site_type fixed 'Primary'->2 int)
- [x] Task 4: Docs (README + ARCHITECTURE §11f) — complete (no commit; spec ✅, 6/6 code-truth checks pass, quality Approved; 2 cosmetic Minor)
- [x] FINAL whole-branch review (opus) — Ready to merge: YES. No Critical/Important defects. 513 passed/5 skipped.
      Cross-task invariants verified vs live source (table-name lineup, post-backfill ordering, bare-Base
      stub routing on both axes, no-metadata AD writer, faithful core mirror).
      ⚠️ COMMIT-SEQUENCING CAVEAT: this ticket renames NODE_SPECS/EDGE_SPECS -> SCCM_*/AD_*. The uncommitted
      Stage 5 (MSSQL) plan adds entries to NODE_SPECS and a test imports NODE_SPECS — incompatible. Whichever
      lands second must reconcile: Stage 5 MSSQL nodes go into SCCM_NODE_SPECS (before node_backfill), and the
      Stage 5 test must import SCCM_NODE_SPECS.

## Minor findings — ALL APPLIED 2026-06-29 (cosmetic cleanup, split test re-run 1 passed)
- [x] [Task 1] graph_edges_split_test.py _seed helper: collapsed alignment whitespace on AS sid/AS id selects.
- [x] [Task 1] transforms.py: added comment on _ad_ids that the bare (unqualified) TEMP TABLE name is intentional.
- [x] [Task 4] ARCHITECTURE.md §11f: reworded "Node routing is free" -> "Node routing needs no preproc step".
- [x] [Task 4] ARCHITECTURE.md §11f trade-offs: graph_edges_split_test.py now a relative-path markdown link.

---

## Stage 5 (MSSQL) — gtk ope-6716 — subagent-driven, started 2026-06-29
Plan: sccm/sccm/docs/superpowers/plans/2026-06-29-sccm-preproc-convert-stage5.md
Baseline: HEAD efb3d1c (clean; split ope-6aa7 landed -> SCCM_NODE_SPECS/AD_NODE_SPECS + _graph_edges_split present).
NO-COMMIT regime (CLAUDE.md): implementers stop at green tests, never commit. Per-task review diff =
working-tree vs HEAD for single-task files; transforms.py (multi-task) diffed vs a pre-task snapshot
($SCRATCH/prev_transforms.py via scratchpad/snap_tf.sh + mkdiff.sh). Recovery: there are no commits, so
trust THIS ledger + `git diff HEAD` over recollection; do not re-dispatch a task marked complete below.
Tasks: A1 edge-consts; B1 props; C1 sql-servers; C2 server-merge; D1 db; E1 login; E2 dbuser;
F1 server-role; F2 db-role; G1 structural-edges; G2 membership-edges; G3 svc-acct-edges; G4 db-assign-all;
H1 models; H2 exports; H3 SCCM_NODE_SPECS; I1 README; I2 ARCHITECTURE; I3 validation-harness; FINAL review.

- [x] Task A1: complete (no commit; spec OK, quality Approved, 0 issues; MSSQL_ServiceAccountFor correctly excluded from TRAVERSABLE per ps1:2233; 2 tests green)
- [x] Task B1: complete (no commit; spec OK, quality Approved, 0 issues; 6 MSSQL*Properties verbatim CMBP casing; 2 tests green)
- [x] Task C1: complete (no commit; spec OK, quality Approved; plan bug fixed: _mssql_sql_servers persistent {schema}.* not TEMP; 1 test green; 2 Minors logged below)
- [x] Task C2: complete (no commit; spec OK, quality Approved; 3-source merge, non-SCCM survives; 3 tests green; 2 Minors logged)
- [x] Task D1: complete (no commit; spec OK, quality Approved; database_id backslash correct; 1 test green, 7 prior MSSQL tests pass; 1 Minor logged)
- [x] Task E1: complete (no commit; spec OK, quality Approved; role-match site-anchored + self-exclusion correct; 2 tests green; 2 Minors logged)
- [x] Task E2: complete (no commit; spec OK, quality Approved, 0 defects; database alias unquoted works; 3 tests green)
- [x] Task F1: complete (no commit; spec OK, quality Approved; sccm_infra filter + members coalesce correct, scope-bug fix verified; 1 test green; 3 style Minors)
- [x] Task F2: complete (no commit; spec OK, quality Approved; db_owner members scoped to database_id; full MSSQL node suite 9/9 green; 1 cosmetic Minor)
- [x] Task G1: complete (no commit; spec OK, quality Approved; 7 structural edges, host_sid as Computer id, kind constants imported; 1 test green; 1 style Minor)
- [x] Task G2: complete (no commit; spec OK, quality Approved; HasLogin start=computer SID, role-id ends match F1/F2; 1 test green; 1 cosmetic formatting Minor)
- [x] Task G3: complete (no commit; spec OK, quality Approved; all 4 gate checks pass: dual-table EXISTS, acct!=host on 15b/c only, collected port, GetTGS fan-out; 1 test green, 10/10 MSSQL; 2 harmless Minors)
- [x] Task G4: complete (no commit; spec OK, quality Approved, 0 issues; site filter char-identical to _edge_assign_all_permissions; split-routing test confirms MSSQL edges route correctly; 60 edge+split tests green)
- [x] Task H1: complete (no commit; spec OK, quality Approved; 6 models, id keys + environmentid(host_sid) + CMBP-cased props + kinds all verified; 4 tests green; 3 comment Minors)
- [x] Task H2: complete (no commit; spec OK, quality Approved, 0 issues; 6 models imported + in __all__, sorted; 5 tests green)
- [x] Task H3: complete (no commit; spec OK, quality Approved, 0 issues; 6 MSSQL tables in SCCM_NODE_SPECS, edge specs untouched, node_backfill stays AD; FULL SUITE 537 passed / 5 skipped / 0 failed)
- [x] Task I1: complete (no commit; README Node+Edge Reference, code-truth verified; Important edge-count inconsistency FIXED — 22+11=33 across all 3 sites incl. line 235 the fixer missed/controller caught; login phrasing Minor fixed)
- [x] Task I2: complete (no commit; ARCHITECTURE §11g extends existing divergence section; claims code-verified; Important GROUP BY prose + UNION framing + temp->staging wording fixed by controller)
- [x] Task I3: complete (no commit; validation harness code-tour, 28 file:line citations verified; LIVE RUN against lab raw C:	mpedo: 3 srv/3 db/3 srvrole/3 dbrole/1 login/1 dbuser + full edge spread, AD/SCCM split confirmed in JSON; Important "6->3 MSSQL_Contains" + Stop-3 self-login query fixed by controller)
- [x] FINAL whole-branch review (opus): READY TO MERGE = YES. 0 Critical/Important; all 12 Minors triaged defer (cosmetic/test-coverage). Cross-task id chain, transforms() ordering, _graph_edges_split-unchanged + routing, layer alignment all verified.

## Stage 5 COMPLETE 2026-06-30 — verification evidence (controller-run):
- Full suite: 537 passed, 5 skipped, 0 failed (110.91s, isolated env). Package imports OK.
- ruff: Stage-5-authored code (transforms.py, graph.py, kinds/edges.py, 6 models) CLEAN. Pre-existing F401s in main.py:27,31 (LookupManager/DltSource) + raw_table.py:25 (typing.Any) NOT introduced by Stage 5 (absent from the Stage-5 diff) -> defer to Stage 7 validate-extension sweep.
- Live E2E (I3): preprocess+convert on lab raw C:	mpedo -> 3 srv/3 db/3 srvrole/3 dbrole/1 login/1 dbuser + full edge spread; AD/SCCM split confirmed in emitted JSON.
- NO COMMITS made (per CLAUDE.md; user commits after testing).

## Stage 5 Minor findings (for FINAL review triage; not fix-dispatched)
- [C1] transforms.py _mssql_sql_servers docstring: stale "transforms.py:1199" line ref (will drift) -> drop the number.
- [C1] node_mssql_server_test.py test_sql_server_temp_built_from_role_rows asserts only 3/8 cols (no node_site JOIN cols: root_site_code/port/db_name/service_account*). Transitively covered by C2 (db_name=CM_PS1) + D1 (port) tests; optional richer C1 case.
- [C2] transforms.py _node_mssql_server Arm 1: coalesce(port,'1433') uses string literal; NON-ISSUE (C1 _mssql_sql_servers.port is VARCHAR) but CAST(coalesce(port,1433) AS VARCHAR) would match arms 2/3 for consistency.
- [C2] transforms.py _node_mssql_server Arm 3: _ensure_columns declares instance_names "VARCHAR" but target is VARCHAR[]; harmless (_arr handles wrap + NULL->[]) — declare "VARCHAR[]" for accuracy.
- [D1] node_mssql_database_test.py asserts 5/8 cols (omits host_sid/port/collection_source); brief-inherited gap, low risk (['...']->VARCHAR[] pattern proven). Optional richer assert.
- [E1] node_mssql_login_dbuser_test.py login test asserts 4/9 cols (omits host_sid/port/sql_server/sccm_site/collection_source); code correct, optional broader assert.
- [E1] test fixtures rely on _node_computer tolerating absent optional tables (brief-inherited pattern); maintenance risk if a future stage adds a strict dep.
- [F1] _node_mssql_server_role members subquery uses generic inner alias "l" (could shadow a future outer join); cosmetic. Also tests use transforms(con) implicit schema default + membership-not-length asserts (generic, applies to most MSSQL tests).
- [F2] node_mssql_roles_test.py module docstring stale future-tense ("F2 will append"); update to completed state.
- [G1] edge builders import kind constants inside the function (deferred import) — consistent with existing Stage 2-4 _edge_* builders; G2/G3/G4 follow same pattern. Final review: decide whether to hoist all edge-builder imports to module top (touches pre-existing code).
- [G3] redundant "service_account_domain_sid IS NOT NULL" alongside acct_exists EXISTS (harmless, brief-inherited); test :1433 is default-port fallback, add clarifying comment.
- [H1] add clarifying comments (cleanup wave): mssql_login.py sysadmin_computer_sid is the HasLogin edge endpoint (not a node prop) — note it; mssql_database.py isTrustworthy/SCCMInfra hardcoded True (CMBP sets site DB trustworthy) — comment; role models isFixedRole=True (only fixed sysadmin/db_owner roles collected) — comment.
