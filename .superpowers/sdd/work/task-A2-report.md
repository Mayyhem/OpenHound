# Task A2 Report — Persist `--disable-possible-edges` / `--enable-bad-opsec` as `collection_settings`

## Status: DONE

## Files Changed

| File | Change |
|------|--------|
| `sccm/sccm/src/openhound_sccm/collectors/collection_settings_test.py` | CREATED — test exercising `collection_settings_rows(ctx)` |
| `sccm/sccm/src/openhound_sccm/collectors/local.py` | MODIFIED — added `collection_settings_rows(ctx)` helper and `@app.resource` wrapper |
| `sccm/sccm/src/openhound_sccm/context.py` | MODIFIED — added `disable_possible_edges: bool = False` and `enable_bad_opsec: bool = False` to `SourceContext` dataclass |
| `sccm/sccm/src/openhound_sccm/source.py` | MODIFIED — (a) set the two flags on `SourceContext(...)` construction, (b) imported `collection_settings` from `collectors/local.py`, (c) added `"collection_settings"` to `DISCOVERY_RESOURCE_NAMES`, (d) added `collection_settings(ctx)` to the `return (...)` tuple in `source()` |
| `sccm/sccm/src/openhound_sccm/main.py` | MODIFIED — added `"collection_settings"` to the local-discovery group in `_preproc_table_map()` |

## Commands and Outputs

### Failing test (before implementation):
```
pytest ... collection_settings_test.py -v
ImportError: cannot import name 'collection_settings_rows' from 'openhound_sccm.collectors.local'
```

### Passing test (after implementation):
```
sccm/sccm/src/openhound_sccm/collectors/collection_settings_test.py::test_collection_settings_single_row PASSED [100%]
1 passed in 0.94s
```

### Import check:
```
uv run ... python -c "import openhound_sccm.source"
# No output = clean (exit 0)
```

## How the local.py Convention Was Matched

Sibling resources mirrored: `local_wmi_sms_authority`, `local_wmi_ccm_client`.

All three share:
- Imports at module top: `from ..context import SourceContext`, `from ..main import app`, `from ..models.raw_table import raw_table_asset`
- Decorator: `@app.resource(name="...", parallelized=False, columns=raw_table_asset("..."))`
- Parameter: `ctx: "SourceContext"` injected by the caller in `source.py` (i.e. `collection_settings(ctx)` in the `return (...)` tuple)

`collection_settings` intentionally omits `@with_log_context` — the sibling decorator adds `[target][phase]` prefixes for per-host resources; this resource runs once per collection and carries no host context. No other deviation.

## Deviations

The brief lists 4 files to modify. A 5th edit was needed: `source.py` also required wiring `collection_settings` into `DISCOVERY_RESOURCE_NAMES` and the `source()` return tuple (import + two additions) so the resource is actually executed during Stage 1. Without this the table would never be written even though it was registered in `_preproc_table_map()`. This is consistent with how every other local resource is wired.

## Concerns

None.
