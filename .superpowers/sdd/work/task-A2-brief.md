# Task A2: Persist `--disable-possible-edges` / `--enable-bad-opsec` as a `collection_settings` table

**Why:** the flags are collect-time source params but the graph is built in preproc/convert (separate CLI runs). Persist them once at collect so preproc can gate "possible" rows later. Today `disable_possible_edges` is read in `sccm/sccm/src/openhound_sccm/source.py` (~line 234) and used nowhere.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/context.py` (carry the flags on `SourceContext`)
- Modify: `sccm/sccm/src/openhound_sccm/source.py` (set them on the `SourceContext(...)` it constructs)
- Modify: `sccm/sccm/src/openhound_sccm/collectors/local.py` (emit the one-row resource)
- Modify: `sccm/sccm/src/openhound_sccm/main.py` (add the table to `_preproc_table_map()`)
- Create (test): `sccm/sccm/src/openhound_sccm/collectors/collection_settings_test.py`

**Interfaces — Produces:** a one-row table `collection_settings(disable_possible_edges BOOLEAN, enable_bad_opsec BOOLEAN)` collected under `sccm/collection_settings`, and a pure helper `collection_settings_rows(ctx)` in `local.py`.

## Step 1: Write the failing test

```python
# src/openhound_sccm/collectors/collection_settings_test.py
import types
from openhound_sccm.collectors.local import collection_settings_rows


def test_collection_settings_single_row():
    ctx = types.SimpleNamespace(disable_possible_edges=True, enable_bad_opsec=False)
    rows = list(collection_settings_rows(ctx))
    assert rows == [{"disable_possible_edges": True, "enable_bad_opsec": False}]
```

## Step 2: Run — expect failure (`ImportError`).

## Step 3a: Carry the flags on `SourceContext`
Add two fields to the `SourceContext` dataclass in `context.py`:
```python
    disable_possible_edges: bool = False
    enable_bad_opsec: bool = False
```

## Step 3b: Set them in `source.py`
Where `SourceContext(...)` is constructed (after the flags are normalised, around `disable_possible_edges = bool(disable_possible_edges)` / `enable_bad_opsec = bool(enable_bad_opsec)`), pass `disable_possible_edges=disable_possible_edges, enable_bad_opsec=enable_bad_opsec` into the `SourceContext(...)` call.

## Step 3c: Emit the resource
Add to `collectors/local.py` a pure helper + an `@app.resource`. The helper is what the test calls; the resource wraps it so it runs once (not per-host):
```python
def collection_settings_rows(ctx):
    """One row capturing the collect-time behaviour flags, so preproc/convert can
    gate possible nodes/edges without re-reading the CLI (the flags are collect-time)."""
    yield {
        "disable_possible_edges": bool(getattr(ctx, "disable_possible_edges", False)),
        "enable_bad_opsec": bool(getattr(ctx, "enable_bad_opsec", False)),
    }


@app.resource(name="collection_settings", parallelized=False, columns=raw_table_asset("collection_settings"))
def collection_settings(ctx: SourceContext = None):
    # ctx is injected the same way sibling local resources receive it; emit exactly one row.
    yield from collection_settings_rows(ctx)
```

**IMPORTANT — match existing patterns:** Read the EXISTING `@app.resource` functions in `local.py` (e.g. `local_wmi_sms_authority`, `local_wmi_ccm_client`) to see (a) how they import/reference `app`, `raw_table_asset`, `SourceContext`, and (b) EXACTLY how `ctx` is injected into a resource function (the signature/parameter name and any decorator like `with_log_context`). Mirror that exact convention for `collection_settings`. If sibling resources receive `ctx` via a different mechanism (e.g. a positional `target, ctx` or a closure), adapt the wrapper to match — but the pure helper `collection_settings_rows(ctx)` must keep the signature the test calls. The test only exercises `collection_settings_rows`, not the resource wrapper.

## Step 3d: Register in `_preproc_table_map()`
In `main.py`, add `"collection_settings"` to the local-discovery group of the `base_tables` list in `_preproc_table_map()`.

## Step 4: Run — expect PASS. Also run `python -c "import openhound_sccm.source"` (in the isolated env) to confirm the new resource registers without import errors.

## Step 5: Checkpoint — `git add` (stage only, NO commit) the four changed files + the test.
