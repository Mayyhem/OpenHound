# Task C0 Report — GraphEdge generalisation

## Status: COMPLETE

## Files changed / renamed / deleted

| Action | Path |
|--------|------|
| Modified | `sccm/sccm/src/openhound_sccm/kinds/edges.py` — added Stage 2 edge-kind constants + `TRAVERSABLE_EDGE_KINDS` frozenset |
| Modified | `sccm/sccm/src/openhound_sccm/graph.py` — added `EdgeProperties` to import; added `SCCMEdgeProperties(EdgeProperties)` dataclass |
| Created | `sccm/sccm/src/openhound_sccm/models/graph_edge.py` — `GraphEdge(BaseAsset)` replaces `ReplicationEdge`; sets `traversable` from `TRAVERSABLE_EDGE_KINDS` |
| Created | `sccm/sccm/src/openhound_sccm/models/graph_edge_test.py` — 3 new unit tests per spec |
| Deleted | `sccm/sccm/src/openhound_sccm/models/replication_edge.py` — `git rm` |
| Deleted | `sccm/sccm/src/openhound_sccm/models/replication_edge_test.py` — `git rm` |
| Modified | `sccm/sccm/src/openhound_sccm/models/__init__.py` — `ReplicationEdge` → `GraphEdge` in import + `__all__` |
| Modified | `sccm/sccm/src/openhound_sccm/transforms.py` — replaced `_graph_edges()` with `_graph_edges_init()` + `_edge_replication()`; updated call site in `transforms()` |
| Modified | `sccm/sccm/src/openhound_sccm/main.py` — import `GraphEdge` not `ReplicationEdge`; `EDGE_SPECS = [("graph_edges", GraphEdge)]` |

## All `ReplicationEdge` references updated

| File | Change |
|------|--------|
| `models/replication_edge.py` | Deleted (`git rm`) |
| `models/replication_edge_test.py` | Deleted (`git rm`) |
| `models/__init__.py` | `from .replication_edge import ReplicationEdge` → `from .graph_edge import GraphEdge`; `__all__` updated |
| `main.py` line 37 | `from .models.replication_edge import ReplicationEdge` → `from .models.graph_edge import GraphEdge` |
| `main.py` line 1189 | `("graph_edges", ReplicationEdge)` → `("graph_edges", GraphEdge)` |

Remaining `ReplicationEdge` occurrences in `sccm/sccm/docs/` are history/planning markdown — no code change required.

## Commands + outputs

### Failing test run (before implementation)
```
pytest models/graph_edge_test.py -v
ERROR: ModuleNotFoundError: No module named 'openhound_sccm.models.graph_edge'
```

### Passing test run (after implementation)
```
pytest models/graph_edge_test.py graph_edges_test.py -v
8 passed in 1.07s
  graph_edge_test.py::test_graph_edge_sets_traversable_from_allowlist  PASSED
  graph_edge_test.py::test_graph_edge_non_traversable_kind             PASSED
  graph_edge_test.py::test_graph_edge_drops_incomplete_row             PASSED
  graph_edges_test.py::test_cas_primary_edges_are_bidirectional        PASSED
  graph_edges_test.py::test_primary_secondary_edge_is_one_way          PASSED
  graph_edges_test.py::test_no_cas_secondary_direct_edge               PASSED
  graph_edges_test.py::test_graph_edges_overwrites_spike               PASSED
  graph_edges_test.py::test_total_edge_count                           PASSED
```

### Import check
```
python -c "import openhound_sccm.main"
(no output — clean)
```

### Staging
```
git rm models/replication_edge.py models/replication_edge_test.py
git add -A sccm/sccm/src/openhound_sccm/models
git add kinds/edges.py graph.py transforms.py main.py
```

## Deviations

None. All steps executed exactly as specified in the brief.

## Concerns

None. The `graph_edges_test.py` transforms-level test (`test_total_edge_count`) still asserts exactly 3 replication edges after the split — verified green. The `_edge_replication` INSERT uses `BY NAME` so column order in the UNION ALL legs is position-independent.
