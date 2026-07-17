## Stage 6 (Coerce-and-relay possible edges) — gtk ope-d820 — subagent-driven, started 2026-06-30
Plan: sccm/sccm/docs/superpowers/plans/2026-06-30-sccm-preproc-convert-stage6.md
Baseline: HEAD 638ea1c "Stage 5 complete" (committed; working tree clean except ticket/plan files).
NO-COMMIT regime (CLAUDE.md): implementers stop at green tests, never commit. Per-task diff via
.sdd/mkdiff.sh — transforms.py diffed vs .sdd/prev_transforms.py (re-snapshot with .sdd/snap_tf.sh
BEFORE each transforms.py task: B1,C1,D1,E1,F1,G1,H1), other files vs HEAD. Briefs/reports/diffs in
sccm/sccm/.sdd/{briefs,reports,diffs}/. Tasks: A1 edge-consts+traversable-fix; B1 relay-props+cols+model;
C1 dedup+split carry; D1 smb_signing_source; E1 adminservice-relay; F1 mssql-relay; G1 smb-relay;
H1 authusers-node+wire; I1 docs; J1 validation-harness; FINAL review. Locked decisions in
[[sccm-stage6-relay-decisions]] / the plan's "Locked Stage 6 decisions" block.

- [x] Task A1: complete (no commit; spec ✅, quality Approved; 3 constants + traversable fix `CoerceAndRelayNTLMtoSMB`->`CoerceAndRelayToSMB`; 3 tests green; 1 Minor self-resolved as correct practice)
- [x] Task B1: complete (no commit; spec ✅ all 3 files correct, quality "Needs fixes" for ONE Critical that is C1's scope by design: `_graph_edges_dedup` drops the 2 new cols. Controller adjudication: NOT a B1 gap — cols are all-NULL until E1 writes them, C1 adds dedup+split carry-through BEFORE E1. Full suite green after B1 (61 passed/1 skip). The `_graph_edges_init` docstring "(dedup coalesces NULL->[])" becomes accurate after C1. **C1 reviewer MUST confirm the col round-trip (init->builders->dedup->split) closes this.** Reviewer's suggested FILTER aggregation == C1 plan's dedup SQL.)
- [x] Task C1: complete (no commit; spec ✅, quality Approved; CLOSES B1's Critical — FILTER-form array-union in `_graph_edges_dedup` (NULL non-relay rows -> []), split carries both cols to ad+sccm; also fixed 2 pre-existing stale-4-col tests (assertions preserved, not weakened) + `sort()`->`list_sort()` for DuckDB 1.5.2; 2 new tests green, regression 26/26).

## Stage 6 Minor findings (FINAL review triage; not fix-dispatched)
- [C1] graph_edges_coercion_cols_test.py ~L100: split test asserts coercion cols on graph_edges_ad but not graph_edges_sccm (symmetric code verified in diff; optional 2-line assert).
- [F1] edge_coerce_relay_mssql_test.py: no test for flag-mode + host-NTLM-null (should skip); code correct, coverage gap only.
- [F1] transforms.py `_edge_coerce_relay_mssql` ~L2919: `coalesce(v.dnshostname, v.sid)` SID branch is dead (JOIN enforces `dnshostname LIKE '%.%'`); cosmetic.
- [H1] transforms.py `_node_authenticated_users` ~L3054: post-INSERT count query `WHERE sid LIKE '%-S-1-5-11'` counts ALL such rows, not just inserted (log metric only; over-counts if S-1-5-11 rows pre-exist). Add clarifying comment or scope the count.
- [H1] node_authenticated_users_test.py: _seed only wires adminservice relay; mssql/smb relay kinds not exercised as INSERT sources (coverage gap, code correct).
- [H1] transforms.py ~L3039: `relay_kinds` IN-clause manually formatted (codebase-idiom); add-a-kind needs manual edit; fine as-is.
- (D1: complete — spec ✅, quality Approved, ZERO issues. `smb_signing_source VARCHAR[]` added to node_computer: 4 insertions (DDL, smb_computers tag ['SMB-Negotiate'], remoteregistry tag ['RemoteRegistry-SMBSigningCheck'], FILTER-form GROUP BY); additive, list_sort() used; 2 new tests green, regression 29/29.)
- (E1: complete — spec ✅, quality Approved. `_authed_users_id` helper + `_edge_coerce_relay_adminservice`; NOT wired (H1). Builder added `CAST(restrict_receiving_ntlm_traffic AS VARCHAR)` in ntlm gate (DuckDB types ?-bound NULL as INTEGER; harmless in prod where col is VARCHAR) — reviewer OK'd as robust. **CARRY TO F1/G1: apply same CAST to their NTLM/EPA gate cols.** 3 tests green. Minors: helper placed before `_arr` not after (cosmetic); no `LIKE '%.%'` guard on providers CTE (harmless, _authed_users_id only used on srv).)
- [x] Task F1: complete (no commit; spec ✅ all 17 checks, quality Approved. `_edge_coerce_relay_mssql` off node_mssql_login; CAST applied to both EPA+NTLM gates; victim(sysadmin_computer)/host distinct joins; EPA-source collection_source filter exact; NOT wired (H1); 3 tests green. 2 Minors logged above.)
- [x] Task G1: complete (no commit; spec ✅ all 4 risks, quality Approved, 0 Critical/Important. `_edge_coerce_relay_smb`: end=SMB-signing-disabled target, start=site-server-domain AuthUsers, coercionVictimHostnames=[server dns], smb_signing_source filter, CAST on NTLM, non-sec only, NOT wired (H1); 3 tests green. Only readability notes (non-issues).)
- [x] Task H1: complete (no commit; spec ✅ ALL hard constraints, quality Approved, 0 Critical/Important. `_node_authenticated_users` + wired all 4 builders into transforms() in order (adminservice,mssql,smb,authusers) after _edge_mssql_db_assign_all, before _graph_edges_dedup -> runs before backfill/split (verified live lines 3224/3230-3233/3237/3241/3245); disable_possible reuses L3172 read; FULL SUITE 558 passed/5 skipped/0 failed; no existing test adjusted. 3 log/coverage Minors logged above.)
  ** STAGE 6 CODE COMPLETE + INTEGRATED. Remaining: I1 docs, J1 validation harness, FINAL review. **
- [x] Task I1: complete (no commit; README + ARCHITECTURE. Review found 1 Critical + 1 Important; fix subagent applied both but its PROCESS EXITED mid-run (report-append lost, README edits persisted). Controller-verified directly: (Critical) AuthUsers node blockquote README.md:495 now `collectionSource = []` (code-true, GroupNode hardcodes []); (Important) edge-kind count = 37 everywhere (banner L14, Limitations L238, Edge Ref L773), "eleven from Stages 1–2", breakdown 11+10+2+11+3=37. ARCHITECTURE §11c 6-col table + §11h + smb_signing_source note + changelog. Minor: TOC uses manual #coerceandrelaytosmbedge anchor (intentional, works).)
- [x] Task J1: complete (no commit; validation harness `2026-06-30-...-stage6-validation.md` 640 lines: 6 breakpoints w/ live file:line (transforms.py:2832/2884/2932/2986/3035/3114), driver + CLI smoke check. LIVE RUN vs lab C:\tmp\redo -> scratch C:\tmp\stage6-validate (default+disable both emitted ad/sccm nodes+edges JSON): DEFAULT 4 CoerceAndRelayToSMB + AUTHENTICATED USERS@MAYYHEM.COM (traversable, env=domain SID), AdminService/MSSQL=0 (lab topology; unit-tested); DISABLE-POSSIBLE all relays=0 (null-NTLM suppressed).
  J1 CAUGHT A REAL README BUG: --disable-possible-edges is COLLECT-time only (main.py:896 -> collection_settings -> preproc reads; NOT a preprocess flag). Controller FIXED README L350-360 (example now `collect ... --disable-possible-edges`; note clarified collect-time + collection_settings patch). L248/L333 already correct.)
  ** ALL 10 TASKS COMPLETE (A1-J1). Next: FINAL whole-branch review (opus). **
- [x] FINAL whole-branch review (opus): READY TO MERGE = YES. 0 Critical/0 Important. All 7 cross-task invariants verified w/ file:line (coercion col round-trip init->builders->dedup->split->GraphEdge with no drop + non-relay output byte-identical; transforms() order 3224<relays/authusers 3230-3233><dedup 3237<backfill 3241<split 3245 so AuthUsers in AD id set; surgical gate via single disable_possible read L3172; CoerceAndRelayToSMB traversable fix + AuthUsers UPPER(FQDN)-S-1-5-11 + collectionSource tags; edge directions not swapped; no regression - no positional graph_edges INSERT exists, 2 modified tests adapted-not-weakened; docs code-truth incl 37-count + collect-time flag). All logged Minors triaged DEFER. 1 new Minor: domain_environment_id anchored-regex safe for ...-S-1-5-11 (no fix).

## Stage 6 COMPLETE 2026-06-30 — verification evidence (controller-run):
- Full suite (isolated env): 558 passed, 5 skipped, 98 subtests passed, 0 failed (117.96s). 5 skips + dlt/pydantic warnings are pre-existing (test_per_host_integration.py), not Stage 6.
- Live E2E (J1): preprocess+convert on lab raw C:\tmp\redo -> scratch C:\tmp\stage6-validate. DEFAULT: 4 CoerceAndRelayToSMB + AUTHENTICATED USERS@MAYYHEM.COM (traversable, env=domain SID); AdminService/MSSQL relays=0 (lab topology, unit-tested). --disable-possible-edges (via collection_settings patch): all relays=0.
- NO COMMITS made (per CLAUDE.md; user commits after testing). Working tree clean except Stage 6 files + ticket/plan/validation docs + .sdd/ (gitignored).

## Post-Stage-6 follow-ups (user-requested 2026-06-30):
- [x] Task K1: deferred-Minor cleanup wave — DONE, spec ✅, quality Approved (0 Critical/Important/Minor). 7 fixes: [C1] split test asserts coercion cols on graph_edges_sccm too; [E1] moved `_authed_users_id` after `_arr`; [F1b] dropped dead `coalesce(v.dnshostname,v.sid)`->`v.dnshostname`; [F1a] +test_mssql_relay_flag_drops_assumed_ntlm; [H1a] reworded log msg (query unchanged); [H1b] +test AuthUsers built from non-adminservice relay kind; [H1c] relay_kinds comment. Full suite 560 passed/5 skipped/0 failed. NO behavior change.
- [x] Task L1: preprocess-time env-var override for disable_possible_edges — DONE, spec ✅, quality Approved (0 issues; reviewer independently re-ran suite). Decided w/ user: literal `preprocess --flag` NOT feasible (core owns @app.preproc; can't add core flags without reimplementing preproc wiring). ENV-VAR OVERRIDE chosen: `_read_disable_possible` honors SOURCES__SCCM__DISABLE_POSSIBLE_EDGES (tightening-only: env truthy OR table value; env can force-disable, never re-enable). Reuses the exact env var collect maps to (main.py:97). Usage: `SOURCES__SCCM__DISABLE_POSSIBLE_EDGES=true openhound preprocess sccm <raw> <db>`. + tests + README/help doc.
  RESULT: `_read_disable_possible` now returns `table_disabled OR env_disabled` (import os + `_TRUTHY_ENV={1,true,yes,on}`); env unset = unchanged behavior; env can force-disable, never re-enable. 10 new test cases (monkeypatch, no leak). README Note + ARCHITECTURE §11h updated (stale "hand-edit only" text removed). Full suite 570 passed/5 skipped/0 failed (560+10). NO COMMITS.
  ** BOTH POST-STAGE-6 FOLLOW-UPS (K1 cleanup + L1 env override) COMPLETE + REVIEWED. **
- [B1] transforms.py `_graph_edges_init` docstring "(dedup coalesces NULL->[])" — ACCURATE post-C1, no action.

---

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

## Stage 7 (Docs + validation) — gtk ope-255b — subagent-driven, started 2026-07-01
Plan: sccm/sccm/docs/superpowers/plans/2026-07-01-sccm-preproc-convert-stage7.md
Baseline: HEAD 5edf791 "Fix failing tests and loading bug" (user committed plan+ticket in parallel; tree clean).
NO-COMMIT regime (CLAUDE.md): implementers stop at green checkpoint (verification passes), never commit.
Per-task diff via .sdd (git diff HEAD -- <file>); README touched by Tasks 2 & 3 -> snapshot README before Task 3
(.sdd/prev_README.md) and diff --no-index. .sdd/{briefs,reports,diffs}/ (gitignored). User committing in parallel
=> always diff SPECIFIC files, never bare git diff. Locked decisions: docs+validation ONLY (no behavioral code);
ground truth = code-static (14 node kinds / 37 edge kinds); "docs" incl non-behavioral docstrings/comments/ruff-autofix/mypy-annotations.
Tasks: 0 scaffold(controller); 1 code-truth matrix; 2 README reconcile; 3 three Mermaid diagrams; 4 docstring/Attributes;
5 ARCHITECTURE reconcile+changelog; 6 validation run; 7 harness doc+final self-check; FINAL whole-branch review.

- [x] Task 0: complete (controller; .sdd dirs reused from Stage 6, briefs extracted, ledger appended, baseline 5edf791 clean)
- [x] Task 1: complete (no commit; spec ✅ Approved by independent source-verify review, 33 tool uses). Matrix at
  .sdd/reports/2026-07-01-stage7-code-truth-matrix.md (14 nodes / 37 edges, verified). Findings F1-F9 (F1 AdminTo dead
  allow-list entry; F4 ZERO Attributes docstrings across all 14 dataclasses ~190 fields -> Task 4 starts from scratch;
  F5 is_confirmed_active_client = the one deliberately snake_case output key). CODE-TRUTH ENDPOINT CORRECTIONS vs stale
  spec §3 that Task 3 diagrams MUST use (matrix is authority): MSSQL_IsMappedTo = Login->DatabaseUser (NOT ->AD principal);
  MSSQL_HostFor = Computer->Server (NOT Server->Computer); MSSQL_HasLogin = Computer(sysadmin)->Login (NOT Server->Login);
  MSSQL_ExecuteOnHost = Server->Computer. My plan's diagram source had these reversed/wrong.
- [x] Task 2: complete (no commit; spec ✅ Approved by review). README text reconciled: Graph Model "8 emitted"->14 prose
  (brief Step 1 verbatim); killed false "property keys lowercase with underscores" claim (they're CMBP camelCase);
  fixed dead anchor #mssql_ismappedto-1->#mssql_ismappedto (intro + ToC). Node/Edge Reference + all 4 MSSQL endpoint
  watch-points were ALREADY correct vs matrix. 4 hunks / +7 -5. Dead-link sweep clean. NO diagrams added (Task 3 scope).
  README snapshotted post-Task-2 -> .sdd/prev_README_task2.md for Task 3 diff isolation.
- [x] Task 3: complete (no commit; spec ✅ after 1 fix). 3 Mermaid diagrams added to README Graph Model section
  (pipeline; clustered AD/SCCM/MSSQL; full 37-edge/14-node hairball). All endpoints matrix-correct incl 3 corrections
  (MSSQL_HostFor Computer->Server, HasLogin Computer->Login, IsMappedTo Login->DatabaseUser). Review found 1 Important
  (caption "Node color=cluster" w/ no styling) -> FIXED: added classDef/class cluster coloring to both graph-model
  diagrams (AD blue/SCCM green/MSSQL orange). 37/14 coverage intact, fences=3, subgraph/end=6/6. Mermaid NOT
  parser-validated (no mmdc/node in env) -> flagged for visual check on GitHub (Task 6/7 note).
- [x] Task 4: complete (no commit; spec ✅ Approved by independent field-by-field review of all 16 classes). graph.py
  gained Attributes: docstrings on 2 edge + 14 node property dataclasses (+398/-7; the -7 are comments folded into
  docstrings, intent preserved). NOTE: these docstrings appeared in the WORKING TREE (HEAD had 0) — provenance = user
  parallel edit or agent; verified non-behavioral + matrix-accurate regardless. Field names are CMBP-cased (only
  is_confirmed_active_client is snake_case). 2 Minors (cosmetic): task-4-report field counts off by 3; matrix Section 1
  undercounts Computer(15->16)/ClientDevice(29->30 missing SCCMInfra) while Section 3 is correct — matrix is gitignored
  scratch, left as-is, Section 3 authoritative.
- [FOUND during Task 4] README property-parity GAP (Task 2 missed it; matrix Section 1 undercount masked it): 4 SCCM-native
  kinds (SCCM_Collection, SCCM_AdminUser, SCCM_SecurityRole, SCCM_ClientDevice) each MISSING 3 emitted props from their
  README tables: SCCMInfra, collectionSource, rootSiteCode. Other 10 kinds complete, no extras. Authoritative diff via
  code_fields (docstring-stripped graph.py) vs README Node Reference tables. -> dispatching README-parity fix (Task 2 follow-up).
- [x] README-parity fix (Task 2 follow-up): complete (no commit). Added 12 rows (collectionSource/rootSiteCode/SCCMInfra x
  4 SCCM-native sections), descriptions from graph.py Attributes docstrings; per-kind SCCMInfra wording (Always-true for
  Collection/AdminUser/SecurityRole, conditional-default-false for ClientDevice). INDEPENDENT controller recheck:
  ALL 14 KINDS PARITY-CLEAN; SCCMInfra rows 8->12. README now matches emitted code exactly (Stage 7 acceptance bar).
- [x] Task 5: complete (no commit; controller-verified). ARCHITECTURE.md: §11 function-ref check ALL OK (no renamed/removed
  fns); Stage 7 changelog row added (line 1030, 1-insertion diff). Implementer correctly caught PLAN ERROR: brief's
  "status line ~L11 / count ~L238" refer to README (not ARCHITECTURE — which has no status banner); left README to its
  owner. Those README strings ("mid-migration…Stages 1-6 shipping", "fourteen…thirty-seven") are ACCURATE, no change needed.
- [x] README anchor-integrity fix (Task 2 dead-ref follow-up; controller-applied): audited all 121 intra-doc #anchor links
  -> found 4 broken (Task 2's sweep was file-path-only). Fixed: intro #coerceandrelaytosmbedge->#coerceandrelaytosmb (+ToC),
  and 3 intro Has*User links (#sccm_hasprimaryuser/currentuser/adlastlogonuser) -> combined heading slug (ToC already had it).
  RE-AUDIT: ALL ANCHOR LINKS RESOLVE.
- [x] Task 6: complete (no commit; validation run = the acceptance gate). Report:
  .sdd/reports/2026-07-01-stage7-validation-report.md. Isolated env = session scratchpad
  dir (not literal /tmp per brief — harness instructs scratchpad over /tmp on this
  Windows/Git-Bash setup; functionally equivalent, outside repo, `uv sync --group dev`
  succeeded first try, no fallback needed). pytest 582 passed/5 skipped/0 failed (ran
  twice, before+after the ruff fix, identical). ruff: 8->4 findings after `--fix` (fixed:
  1 f-string trim in ldap.py + 3 unused imports in main.py/raw_table.py, all non-
  behavioral, confirmed via git diff HEAD -- src/ + re-run pytest; remaining 4 F841
  unused-locals in ldap.py's SD/ACL parser are pre-existing, not autofixable). mypy: 223
  pre-existing errors (import-untyped stub gaps + custom Logger.verbose unrecognized by
  stdlib stubs + ~15 genuine logic-shaped errors), ZERO in Stage-7-touched code (graph.py's
  only hit is the same import-untyped notice every model file gets). Both ruff+mypy
  findings folded into ope-1f0f (no new ticket). Structural checklist 10/10 PASS (4
  brief-specified + 6 extra: NodeDef/EdgeDef-equivalent as_node/.edges pattern verified,
  dlt.secrets.value creds, global @app.convert(lookup=) registration, domain_environment_id
  root/environment mechanism, no kind-enum classes) with 3 documented intentional
  environmentid non-matches (graph_edge.py edge asset, raw_table.py no-emit placeholder,
  target_entry.py non-graph internal dataclass). No checks skipped for tooling/network
  reasons; noted which AST-level Search Checks were inherited from prior-stage per-task
  review rather than re-derived from scratch (no code changed since those reviews).
- [x] Task 6: complete (no commit; controller-verified non-behavioral autofix diff). Isolated scratchpad venv, uv sync OK.
  pytest 582 passed / 5 skipped / 0 FAILED. ruff 8->4 via --fix (non-behavioral: f-string F541 in ldap.py + 3 unused-import
  F401 in main.py x2/raw_table.py; verified diff = only import/f-prefix removals, pytest re-green). Remaining 4 ruff F841
  (ldap.py SD/ACL parser unused locals) + 223 mypy errors (missing stubs + ~15 logic-shaped) = ALL PRE-EXISTING, none in
  Stage-7 code -> folded to ope-1f0f. Structural checklist 10/10 (3 documented environmentid exceptions). Report:
  .sdd/reports/2026-07-01-stage7-validation-report.md. NOTE: ruff --fix touched 3 non-docs src files (ldap/main/raw_table)
  -- authorized by user's "fix everything non-behavioral" choice; flag to user at handoff.
- [x] Task 7: complete (no commit; controller-completed after subagent WRITE DENIED by permission layer for both scratchpad
  AND repo paths). Harness doc written by controller: docs/superpowers/plans/2026-07-01-sccm-preproc-convert-stage7-validation.md
  (reproduction-guide style: re-derive counts, README self-consistency gate, validation-suite reproduction, optional lab
  cross-check, Last-run results). Final self-consistency gate LIVE: 37 edge constants, 0 MISSING in diagram, all pass.
  ope-7f61 CLOSED (banner verified resolved). Task-7 subagent verification (all-pass) folded in.
- [x] FINAL whole-branch review (opus): READY TO MERGE. Independently re-verified all gates (14/37 banners, diagram
  coverage 0-MISSING, anchors resolve, 14/14 parity-clean, all fields documented, ARCHITECTURE changelog accurate,
  MSSQL endpoints match matrix). Non-behavioral CONFIRMED: graph.py docstrings-only (field decls/defaults untouched;
  -7 comments folded into docstrings, intent preserved); ldap.py/main.py/raw_table.py = dead-import/f-string removals
  with 0 remaining refs. No Critical/Important. 4 Minors ALL triaged ACCEPTABLE (gitignored .sdd artifacts + flagged
  manual Mermaid visual check). STAGE 7 COMPLETE. NO COMMIT (user commits after testing per CLAUDE.md).

## Edge entity-panel help content — gtk ope-aa39 — subagent-driven, started 2026-07-15
Plan: sccm/sccm/docs/superpowers/plans/2026-07-15-edge-entity-panel-help.md
Spec: sccm/sccm/docs/superpowers/specs/2026-07-15-edge-entity-panel-help-design.md
Baseline: HEAD d0857d4 "Fix SCCM_HasMember" (working tree has M .tickets/ope-aa39.md + new spec/plan; unrelated).
NO-COMMIT regime (CLAUDE.md): implementers stop at green tests, never commit. Per-task diff via
.sdd/mkdiff.sh (no transforms.py this run, so PREV_TF arg unused). Briefs/reports/diffs in
sccm/sccm/.sdd/{briefs,reports,diffs}/.
Design: EDGE_HELP dict (per-kind bespoke help) -> 5 nullable fields on SCCMEdgeProperties ->
GraphEdge merges non-None fields; convert prunes null keys. Vertical slice wires
SCCM_AdminsReplicatedTo; PENDING_HELP_KINDS holds 34 kinds awaiting user prose. Decisions in
[[sccm-property-casing-cmbp]] context + spec. Tasks: 1 edge_help.py; 2 graph fields+wiring;
3 e2e+README; FINAL review.

- [x] Task 1: complete (no commit; spec ✅, quality Approved; edge_help.py + tests/edge_help_test.py; 6/6 green; 0 findings; scope=35 verified vs kinds/edges.py)
- [x] Task 2: complete (no commit; spec ✅, quality Approved; graph.py +5 nullable help fields, graph_edge.py merges as_fields into both branches; tests/edge_help_emit_test.py; 5/5 new + 19/19 regression green; 1 Minor [unused imports] fixed + added base-class isinstance coverage; ruff clean)
- [x] Task 3: complete (no commit; spec ✅, quality Approved after fixes; tests/edge_help_integration_test.py + README Edge Reference; 2 Important [vacuous negative assertion -> now seeds SCCM_HasClient PENDING edge; README 2-col -> 3-col] + 1 Minor [heading ####->##] fixed; cross-task mypy fix: as_fields -> dict[str,Any]; 12/12 help tests green; mypy clean of new errors [2 pre-existing openhound import-untyped remain]; ruff clean)
- [x] FINAL whole-branch review (opus): Ready-to-merge WITH FIXES; all fixes applied+verified. 1 Important [README example collectionSource ["AdminService"]->["SCCM_Invoke-PostProcessing"] code-truth] + 3 Minor [TOC entry; test kind-literals->ek.*; windowsAbuse excerpt faithful] + 2 hardening [scope test now closure-assertion (self-maintaining); coupling guard test EdgeHelp fields <= SCCMEdgeProperties]. 13/13 help tests green; ruff clean; mypy no-new-errors.
- [x] COMPLETE (no commit; awaiting user commit). Files: src/openhound_sccm/edge_help.py (NEW), graph.py, models/graph_edge.py, tests/edge_help_test.py + edge_help_emit_test.py + edge_help_integration_test.py (NEW), README.md. PENDING_HELP_KINDS = 34 kinds awaiting user prose.

## collect sccm --run-all end-to-end flag + shared orchestrator — gtk ope-f27c — subagent-driven, started 2026-07-16
Plan: sccm/sccm/docs/superpowers/plans/2026-07-16-openhound-run-all-shared-orchestrator.md
Baseline: HEAD d0857d4 "Fix SCCM_HasMember". Working tree PRE-DIRTY (edge-help ope-aa39 awaiting user commit):
  M sccm/sccm/README.md, M sccm/sccm/src/openhound_sccm/main.py (+ graph.py, models/graph_edge.py, collect_summary_test.py).
NO-COMMIT regime (CLAUDE.md): implementers stop at green tests, never commit. Per-task diff isolation:
  T1 all-NEW files (openhound-collector-common/.../orchestration/* + tests/test_orchestration.py) -> git diff --no-index /dev/null.
  T2 main.py PRE-DIRTY -> diff vs snapshot sccm/sccm/.sdd/prev_main_runall.py (taken 2026-07-16 pre-T2); collect_run_all_test.py NEW.
  T3 README.md PRE-DIRTY -> snapshot sccm/sccm/.sdd/prev_README_runall.md pre-T3; ARCHITECTURE.md CLEAN -> git diff HEAD.
Decisions (locked, [[openhound-cli-extension-seam]] + [[silence-dlt-progress]]): flag-not-verb (no core edit),
  in-process app.preprocessor/app.converter, land shared fn in openhound-collector-common now (MSSQL adopts later),
  stop-on-first-failure, zero-config derived paths, single --progress; progress contract = Progress|None (shim convert-side).
Tasks: 1 shared orchestrator+tests; 2 SCCM --run-all glue+tests; 3 README+ARCHITECTURE docs; FINAL review.

- [x] Task 1: complete (no commit; spec ✅, quality Approved, 0 issues; orchestration/__init__.py + run.py + tests/test_orchestration.py; 9/9 green; reviewer independently verified None-vs-shim asymmetry vs openhound/core preproc.py:81 + convert.py:84, and path layout == main.py:1201-1203)
- [x] Task 2: complete (no commit; spec ✅, quality Approved, 0 Critical/Important; --run-all option + _log_collect_summary(run_all) hint-suppression + _run_e2e_after_collect(off->None,else Progress(value); resume-log+re-raise) + return moved after finally; uv run KEPT (controller-authorized) w/ derive_stage_paths values; 5/5 new + 14/14 regression green; reviewer verified 3 named risks live)
- [x] Task 3: complete (no commit; spec ✅ after 1 fix, quality Approved; README --run-all option row + uv-run Quick Start example (surgical, 2 hunks) + ARCHITECTURE §12 + 2 table rows + TOC + changelog. Review found 1 Important: §12 baseline had mount-vs-import order INVERTED -> controller-fixed to code-true (extensions load inside TyperOverride.__init__ via from_entrypoint at override.py:22, BEFORE add_typer mounting at main.py:31-36) + quick-ref cell; reviewer re-verified RESOLVED vs main.py:18-36+override.py:20-25)

## run-all Minor findings (FINAL review triage; not fix-dispatched)
- [T2] DRY: _log_collect_summary next-steps block and _run_e2e_after_collect failure-log each format the same `uv run openhound preprocess/convert sccm ...` strings from derive_stage_paths (brief-inherited). Optional: extract `_format_resume_commands(paths)->(str,str)`. Non-blocking.
- [T2] Pre-existing/unrelated: `openhound collect sccm --help` throws UnicodeEncodeError on cp1252 Windows consoles due to a `→` char in an UNRELATED existing help string (not --run-all). Worth its own ticket; out of this feature's scope.
- [T3] Minor (final-triage): §12 links [collect_sccm]/[_run_e2e_after_collect] omit #Lxx line anchors (several existing ARCHITECTURE links also do; style-only).
- [T3] Observation (pre-existing, NOT this feature): §11b TOC entry text (ARCHITECTURE.md:59 "for 'possible' nodes") mismatches the real ### 11b heading ("for inferred client nodes"). Left untouched.

- [x] FINAL whole-branch review (opus): READY TO MERGE = YES. 0 Critical / 0 Important. All 5 cross-file invariants verified code-true vs real framework (progress contract convert.py:84/preproc.py:81/app.py:163,226,278; derived paths==manual hint; --run-all only on success path incl early return None + exception-past-finally; no runtime openhound/dlt import; no core file touched). Both adjudicated items confirmed (uv run kept + derive_stage_paths; §12 order code-true). In-process handoff DuckDB-lock/dlt-trace risk traced clean. Minors all DEFER (T2 DRY cmd strings; T3 §12 #Lxx anchors; resume-hint always says preproc+convert [harmless, write_disposition=replace]; twin _SilentProgress/_NullProgress shims justified by layering).
- [x] OFFLINE E2E SMOKE (controller): copied lab raw C:\tmp\redo\sccm (78 tables) -> C:\tmp\runall-smoke (original untouched); ran run_end_to_end(m.app, C:\tmp\runall-smoke, progress=None) in ONE process. EXIT 0. preproc built lookup.duckdb (23M); convert emitted split graph: sccm_nodes 55K / sccm_edges 372K (~205) / ad_nodes 78K / ad_edges 226K (~194). Real in-process preproc->convert handoff VERIFIED (DuckDB lock release, dlt trace reuse, progress=None shim through run_convert). Full network --run-all (collect phase) still needs lab -> user to run.
- FEATURE COMPLETE (no commit; awaiting user commit). Files: openhound-collector-common/src/openhound_collector_common/orchestration/{__init__,run}.py (NEW) + tests/test_orchestration.py (NEW); sccm/sccm/src/openhound_sccm/main.py (MOD, also carries unrelated pre-existing edits); sccm/sccm/tests/collect_run_all_test.py (NEW); sccm/sccm/README.md (MOD, also carries edge-help rows); sccm/sccm/ARCHITECTURE.md (MOD §12). 28/28 feature tests green.

## FOLLOW-UP (user, 2026-07-17): --run-all shows ALL output file locations at end of convert
Change: _run_e2e_after_collect now RETURNS StagePaths; new _log_all_output_locations(output_path, paths,
collect_log, diag_log, issue_count) helper logs a consolidated block (output dir, raw JSONL, collect log,
diagnostics log w/ warn/err count, lookup DB, each OpenGraph json) as the last step of collect_sccm's run_all
block. README --run-all row + ARCHITECTURE §12 note updated. +4 tests (return passthrough, full listing,
no-warn/empty-graph, absent-logs/missing-graph). LIVE RUN: `uv run openhound collect sccm --run-all ./output -v
--debug` EXIT 0 -> fresh lookup.duckdb(37M)+graph(sccm/ad nodes+edges)+collect logs @10:41; 0 UnicodeEncodeError
/0 Traceback in this run's logs (the earlier subagent report was a non-interactive cp1252 pipe artifact, NOT a
bug — user confirmed they don't see it; no ticket). Summary rendered against real output dir = correct.
- Delta review (sonnet): 3 Important -> ALL FIXED: (1) StagePaths F821/mypy name-defined -> module TYPE_CHECKING
  import (ruff "All checks passed", mypy no name-defined); (2) false "diag file always created" comment (it's
  delay=True, absent on clean runs) -> comment corrected + README reworded ("whichever logs were produced");
  (3) README overstatement -> reworded. +test for absent-logs/missing-graph branches. 32 feature tests pass.
  Re-review (sonnet): RESOLVED - reviewer re-ran ruff (All checks passed) + mypy (no name-defined) + pytest itself; delta APPROVED, no remaining findings.
