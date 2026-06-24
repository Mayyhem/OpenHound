# Final Fix Report — Stage 2 Review Fixes

**Date:** 2026-06-24

## Files Changed

| File | Change |
|------|--------|
| `sccm/sccm/src/openhound_sccm/transforms.py` | Added `_graph_edges_dedup()` function; added call in `transforms()` after `_edge_has_stored_account`, before `_node_backfill` |
| `sccm/sccm/src/openhound_sccm/graph_edges_dedup_test.py` | **New** TDD test file proving dedup collapses duplicate cross-source edges |
| `sccm/sccm/src/openhound_sccm/graph_edges_test.py` | Updated module docstring: `_graph_edges` → `_graph_edges_init + _edge_replication` |
| `sccm/sccm/src/openhound_sccm/transforms_test.py` | Updated test docstring inside `test_transforms_graph_edges_always_created`: `_graph_edges` → `_graph_edges_init + _edge_replication` |

All four files staged with `git add`.

## Fix 1: graph_edges dedup

`_graph_edges_dedup` uses `CREATE OR REPLACE TABLE ... AS SELECT DISTINCT start_id, end_id, kind`
— the same pattern used by `_principal_by_name`, `_site_hierarchy`, and the lookup tables, so it
matches the existing transforms idiom.

Called in `transforms()` immediately after `_edge_has_stored_account` (the last edge builder) and
before `_node_backfill` (which reads graph_edges to find endpoints missing a node). The inline
comment explains why the call lives there.

## Fix 2: Stale docstrings

Both files contained a stale `_graph_edges` reference (the old single function that was split into
`_graph_edges_init` + `_edge_replication`). Both were updated with prose-only changes; no test
logic was modified.

## Verification

### Targeted tests

```
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest .../graph_edges_dedup_test.py .../graph_edges_test.py -v
```

```
============================= test session starts =============================
collected 6 items

sccm/sccm/src/openhound_sccm/graph_edges_dedup_test.py::test_graph_edges_deduplicated_across_sources PASSED [ 16%]
sccm/sccm/src/openhound_sccm/graph_edges_test.py::test_cas_primary_edges_are_bidirectional PASSED [ 33%]
sccm/sccm/src/openhound_sccm/graph_edges_test.py::test_primary_secondary_edge_is_one_way PASSED [ 50%]
sccm/sccm/src/openhound_sccm/graph_edges_test.py::test_no_cas_secondary_direct_edge PASSED [ 66%]
sccm/sccm/src/openhound_sccm/graph_edges_test.py::test_graph_edges_overwrites_spike PASSED [ 83%]
sccm/sccm/src/openhound_sccm/graph_edges_test.py::test_total_edge_count PASSED [100%]

6 passed in 1.94s
```

### Full suite

```
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest .../src/openhound_sccm -q
```

```
130 passed in 22.87s
```

## Concerns

None. The dedup is a straightforward `SELECT DISTINCT` over the three columns that define edge identity
(`start_id`, `end_id`, `kind`), matching CMBP's `Upsert-Edge` contract. Placement after all edge
builders and before `_node_backfill` is correct. The stale docstrings were genuine and required fixing.
