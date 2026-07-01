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
