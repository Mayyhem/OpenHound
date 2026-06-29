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
