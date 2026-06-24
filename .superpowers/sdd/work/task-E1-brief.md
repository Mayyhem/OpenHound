# Task E1: `_read_disable_possible` gate reader

Add a helper that reads the persisted `collection_settings.disable_possible_edges` flag (written at collect time by A2) so preproc can gate "possible" rows. This task adds ONLY the helper + its test; Task E2 wires it into `transforms()` and uses it (so do NOT call it from `transforms()` here — `_node_client_device_possible` doesn't exist yet).

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_read_disable_possible`)
- Create (test): `sccm/sccm/src/openhound_sccm/transforms_settings_test.py`

**Interfaces — Produces:** `_read_disable_possible(con, schema) -> bool` — True only if `collection_settings.disable_possible_edges` is true; False if the table is absent (older collections) or the flag is false/NULL.

## Step 1: Write the failing test
```python
# src/openhound_sccm/transforms_settings_test.py
import duckdb
from openhound_sccm.transforms import _read_disable_possible


def test_read_disable_possible_absent_defaults_false():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    assert _read_disable_possible(con, "sccm") is False


def test_read_disable_possible_true():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.collection_settings AS "
                "SELECT true AS disable_possible_edges, false AS enable_bad_opsec")
    assert _read_disable_possible(con, "sccm") is True


def test_read_disable_possible_false():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.collection_settings AS "
                "SELECT false AS disable_possible_edges, false AS enable_bad_opsec")
    assert _read_disable_possible(con, "sccm") is False
```

## Step 2: Run — expect failure (`ImportError`).
`pytest .../transforms_settings_test.py -v`

## Step 3: `_read_disable_possible` in `transforms.py`
```python
def _read_disable_possible(con: duckdb.DuckDBPyConnection, schema: str) -> bool:
    """Read the persisted disable_possible_edges flag (collection_settings, written at
    collect time). True only if the flag is set; False if the table is absent (older
    collection) or the flag is false/NULL. Gates the possible-client rows (E2) and,
    later, Stage 6 relay edges."""
    try:
        row = con.execute(
            f"SELECT bool_or(disable_possible_edges) FROM {schema}.collection_settings"
        ).fetchone()
        val = bool(row[0]) if row and row[0] is not None else False
    except duckdb.CatalogException:
        # Older collection without the settings table -> default to emitting possible rows.
        logger.info("collection_settings absent; possible edges/nodes enabled by default")
        val = False
    logger.info("disable_possible_edges = %s", val)
    return val
```
Place it near the other small helpers (e.g. after `_root_code`). Do NOT call it from `transforms()` yet (E2 does that).

## Step 4: Run — expect PASS (3 tests). ## Step 5: Checkpoint — `git add` (stage only).
