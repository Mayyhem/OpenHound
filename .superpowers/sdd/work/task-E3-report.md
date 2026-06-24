# Task E3 Report: `node_backfill`

## Files Changed

| File | Action |
|---|---|
| `sccm/sccm/src/openhound_sccm/graph.py` | Added `BACKFILL_END_KIND` dict (7 entries) before `SCCMEdgeProperties` |
| `sccm/sccm/src/openhound_sccm/transforms.py` | Added `_node_backfill()` function; called LAST in `transforms()` after `_edge_has_stored_account` |
| `sccm/sccm/src/openhound_sccm/models/stub_node.py` | Created `StubNode(BaseAsset)` with `as_node` property |
| `sccm/sccm/src/openhound_sccm/models/__init__.py` | Added `from .stub_node import StubNode` + added to `__all__` |
| `sccm/sccm/src/openhound_sccm/main.py` | Imported `StubNode`; appended `("node_backfill", StubNode)` as LAST `NODE_SPECS` entry |
| `sccm/sccm/src/openhound_sccm/node_backfill_test.py` | Created (1 test) |
| `sccm/sccm/src/openhound_sccm/models/stub_node_test.py` | Created (3 tests) |

## Test Commands and Output

### Target tests (4 tests):
```
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/node_backfill_test.py C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/models/stub_node_test.py -v
```
Output:
```
collected 4 items
sccm/sccm/src/openhound_sccm/node_backfill_test.py::test_node_backfill_synthesizes_missing_endpoint PASSED
sccm/sccm/src/openhound_sccm/models/stub_node_test.py::test_stub_node_user_gets_base_and_domain_env PASSED
sccm/sccm/src/openhound_sccm/models/stub_node_test.py::test_stub_node_base_only_falls_back_to_id_env PASSED
sccm/sccm/src/openhound_sccm/models/stub_node_test.py::test_stub_node_missing_returns_none PASSED
4 passed in 0.59s
```

### Full suite:
```
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm -q
```
Output:
```
129 passed in 23.64s
```

## Deviations

None. Implementation follows the brief exactly, including verbatim SQL and model code from the spec.

## Concerns

None. The `_existing_ids` temp table unions all four SID/smsid-keyed node tables; `CREATE OR REPLACE TEMP TABLE` is idempotent if `transforms()` were called twice in the same connection (test isolation), though in production it is called once per preproc run.
