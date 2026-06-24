# Task C1: Stage 2 lookups + `principal_by_name` enrichment

Builds the four name/id→id lookup tables the Stage 2 edges join against, and enriches `principal_by_name` so `DOMAIN\user` name forms (device primary/current users, SQL service accounts) resolve to SIDs.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add 4 lookup builders + enrich `_principal_by_name`; call the 4 builders from `transforms()` after the `_node_*` coalesces and before `_graph_edges_init`)
- Create (test): `sccm/sccm/src/openhound_sccm/transforms_lookups_test.py`

**Interfaces — Produces:**
- `resource_to_sid(resource_key, sid)` — `resource_key = '<resource_id>@<site>'` → SID (from r_system=computer, r_user=user, user_group=group).
- `device_by_resourceid(resource_key, smsid)` — from client_devices (real clients).
- `collection_by_name(name, collection_id)` — `name = upper(trim(collection name))`.
- `role_by_name(name, role_id)` — `name = upper(trim(role_name))`.
- enriched `principal_by_name` (adds r_user `unique_user_name`/`full_user_name`/`user_principal_name` → sid).

## Step 1: Write the failing test

```python
# src/openhound_sccm/transforms_lookups_test.py
import duckdb
from openhound_sccm.transforms import transforms

def _seed(con):
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    con.execute("CREATE TABLE sccm.adminservice_r_system AS SELECT 'WS01' AS name, "
                "'S-1-5-21-1-2-3-1104' AS sid, 7 AS resource_id, 'PS1' AS source_site_code, false AS obsolete")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'alice' AS name, "
                "'S-1-5-21-1-2-3-1106' AS sid, 9 AS resource_id, 'PS1' AS source_site_code, "
                "'MAYYHEM\\alice' AS unique_user_name")
    con.execute("CREATE TABLE sccm.adminservice_client_devices AS SELECT 'GUID-1' AS smsid, 'WS01' AS name, "
                "7 AS resource_id, 'PS1' AS site_code, true AS is_client, false AS is_obsolete")
    con.execute("CREATE TABLE sccm.adminservice_collections AS SELECT 'PS100016' AS collection_id, 'All Systems' AS name")
    con.execute("CREATE TABLE sccm.adminservice_security_roles AS SELECT 'SMS000AR' AS role_id, 'Full Administrator' AS role_name")

def test_lookups_built():
    con = duckdb.connect(":memory:"); _seed(con); transforms(con)
    assert con.execute("SELECT sid FROM sccm.resource_to_sid WHERE resource_key='9@PS1'").fetchone()[0] == "S-1-5-21-1-2-3-1106"
    assert con.execute("SELECT smsid FROM sccm.device_by_resourceid WHERE resource_key='7@PS1'").fetchone()[0] == "GUID-1"
    assert con.execute("SELECT collection_id FROM sccm.collection_by_name WHERE name='ALL SYSTEMS'").fetchone()[0] == "PS100016"
    assert con.execute("SELECT role_id FROM sccm.role_by_name WHERE name='FULL ADMINISTRATOR'").fetchone()[0] == "SMS000AR"

def test_principal_by_name_resolves_unique_user_name():
    con = duckdb.connect(":memory:"); _seed(con); transforms(con)
    # the DOMAIN\user form resolves to the user's SID (enrichment)
    row = con.execute("SELECT sid FROM sccm.principal_by_name WHERE upper(name)=upper('MAYYHEM\\alice')").fetchone()
    assert row is not None and row[0] == "S-1-5-21-1-2-3-1106"
```
> Backslash rule (from B3): `'MAYYHEM\\alice'` in Python source = one backslash stored. Use `\\` (not `\\\\`).

## Step 2: Run — expect failure.
`pytest .../transforms_lookups_test.py -v`

## Step 3a: The four lookup builders in `transforms.py`

```python
def _resource_to_sid(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """resource_key '<resource_id>@<site>' -> SID. r_system=computer, r_user=user, user_group=group."""
    con.execute(f"CREATE OR REPLACE TABLE {schema}.resource_to_sid (resource_key VARCHAR, sid VARCHAR)")
    rsys = ("adminservice_r_system", "wmi_r_system")
    ruser = ("adminservice_r_user", "wmi_r_user")
    ugroup = ("adminservice_user_group", "wmi_user_group")
    for _src in rsys:
        _ensure_columns(con, schema, _src, {"resource_id": "BIGINT", "source_site_code": "VARCHAR", "sid": "VARCHAR", "obsolete": "BOOLEAN"})
        _safe(con, f"resource_to_sid<-{_src}",
              f"INSERT INTO {schema}.resource_to_sid "
              f"SELECT CAST(resource_id AS VARCHAR)||'@'||CAST(source_site_code AS VARCHAR), upper(sid) "
              f"FROM {schema}.{_src} WHERE resource_id IS NOT NULL AND sid IS NOT NULL AND NOT coalesce(obsolete, false)")
    for _src in ruser:
        _ensure_columns(con, schema, _src, {"resource_id": "BIGINT", "source_site_code": "VARCHAR", "sid": "VARCHAR"})
        _safe(con, f"resource_to_sid<-{_src}",
              f"INSERT INTO {schema}.resource_to_sid "
              f"SELECT CAST(resource_id AS VARCHAR)||'@'||CAST(source_site_code AS VARCHAR), upper(sid) "
              f"FROM {schema}.{_src} WHERE resource_id IS NOT NULL AND sid IS NOT NULL")
    for _src in ugroup:
        _ensure_columns(con, schema, _src, {"resource_id": "BIGINT", "source_site_code": "VARCHAR", "sid": "VARCHAR"})
        _safe(con, f"resource_to_sid<-{_src}",
              f"INSERT INTO {schema}.resource_to_sid "
              f"SELECT CAST(resource_id AS VARCHAR)||'@'||CAST(source_site_code AS VARCHAR), upper(sid) "
              f"FROM {schema}.{_src} WHERE resource_id IS NOT NULL AND sid IS NOT NULL")
    con.execute(f"CREATE OR REPLACE TABLE {schema}.resource_to_sid AS "
                f"SELECT DISTINCT resource_key, sid FROM {schema}.resource_to_sid "
                f"WHERE resource_key IS NOT NULL AND sid IS NOT NULL")
    logger.info("resource_to_sid built in schema %r", schema)


def _device_by_resourceid(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """resource_key '<resource_id>@<site>' -> smsid, from real client_devices."""
    con.execute(f"CREATE OR REPLACE TABLE {schema}.device_by_resourceid (resource_key VARCHAR, smsid VARCHAR)")
    for _src in ("adminservice_client_devices", "wmi_client_devices"):
        _ensure_columns(con, schema, _src, {"resource_id": "BIGINT", "site_code": "VARCHAR", "is_client": "BOOLEAN", "is_obsolete": "BOOLEAN"})
        _safe(con, f"device_by_resourceid<-{_src}",
              f"INSERT INTO {schema}.device_by_resourceid "
              f"SELECT CAST(resource_id AS VARCHAR)||'@'||CAST(site_code AS VARCHAR), upper(smsid) "
              f"FROM {schema}.{_src} WHERE resource_id IS NOT NULL AND smsid IS NOT NULL "
              f"AND coalesce(is_client, false) AND NOT coalesce(is_obsolete, false)")
    con.execute(f"CREATE OR REPLACE TABLE {schema}.device_by_resourceid AS "
                f"SELECT DISTINCT resource_key, smsid FROM {schema}.device_by_resourceid "
                f"WHERE resource_key IS NOT NULL AND smsid IS NOT NULL")
    logger.info("device_by_resourceid built in schema %r", schema)


def _collection_by_name(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """upper(trim(collection name)) -> upper(collection_id). Names may not be unique."""
    con.execute(f"CREATE OR REPLACE TABLE {schema}.collection_by_name (name VARCHAR, collection_id VARCHAR)")
    for _src in ("adminservice_collections", "wmi_collections"):
        _ensure_columns(con, schema, _src, {"name": "VARCHAR"})
        _safe(con, f"collection_by_name<-{_src}",
              f"INSERT INTO {schema}.collection_by_name "
              f"SELECT upper(trim(name)), upper(collection_id) "
              f"FROM {schema}.{_src} WHERE name IS NOT NULL AND collection_id IS NOT NULL")
    con.execute(f"CREATE OR REPLACE TABLE {schema}.collection_by_name AS "
                f"SELECT DISTINCT name, collection_id FROM {schema}.collection_by_name")
    dupes = con.execute(f"SELECT count(*) FROM (SELECT name FROM {schema}.collection_by_name GROUP BY name HAVING count(*) > 1)").fetchone()[0]
    if dupes:
        logger.info("collection_by_name: %d collection name(s) map to multiple ids (IsAssigned will fan out)", dupes)
    else:
        logger.debug("collection_by_name: all names unique")


def _role_by_name(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """upper(trim(role_name)) -> upper(role_id)."""
    con.execute(f"CREATE OR REPLACE TABLE {schema}.role_by_name (name VARCHAR, role_id VARCHAR)")
    for _src in ("adminservice_security_roles", "wmi_security_roles"):
        _ensure_columns(con, schema, _src, {"role_name": "VARCHAR"})
        _safe(con, f"role_by_name<-{_src}",
              f"INSERT INTO {schema}.role_by_name "
              f"SELECT upper(trim(role_name)), upper(role_id) "
              f"FROM {schema}.{_src} WHERE role_name IS NOT NULL AND role_id IS NOT NULL")
    con.execute(f"CREATE OR REPLACE TABLE {schema}.role_by_name AS "
                f"SELECT DISTINCT name, role_id FROM {schema}.role_by_name")
    logger.info("role_by_name built in schema %r", schema)
```
Call all four from `transforms()` AFTER the `_node_*` coalesces and BEFORE `_graph_edges_init` (they read raw tables, not graph_edges).

## Step 3b: Enrich `_principal_by_name`
In the existing `_principal_by_name`, ADD three more `(label, select)` entries to the `sources` list (for both adminservice and wmi r_user), so `DOMAIN\user`/UPN forms resolve. Use `_ensure_columns` only if a referenced column might be absent — simpler: guard each with `_safe` (already used for every source). Add:
```python
        ("principal_by_name<-adminservice_r_user_unique",
         f"SELECT unique_user_name AS name, sid FROM {schema}.adminservice_r_user WHERE sid IS NOT NULL AND unique_user_name IS NOT NULL"),
        ("principal_by_name<-wmi_r_user_unique",
         f"SELECT unique_user_name AS name, sid FROM {schema}.wmi_r_user WHERE sid IS NOT NULL AND unique_user_name IS NOT NULL"),
        ("principal_by_name<-adminservice_r_user_full",
         f"SELECT full_user_name AS name, sid FROM {schema}.adminservice_r_user WHERE sid IS NOT NULL AND full_user_name IS NOT NULL"),
        ("principal_by_name<-wmi_r_user_full",
         f"SELECT full_user_name AS name, sid FROM {schema}.wmi_r_user WHERE sid IS NOT NULL AND full_user_name IS NOT NULL"),
        ("principal_by_name<-adminservice_r_user_upn",
         f"SELECT user_principal_name AS name, sid FROM {schema}.adminservice_r_user WHERE sid IS NOT NULL AND user_principal_name IS NOT NULL"),
        ("principal_by_name<-wmi_r_user_upn",
         f"SELECT user_principal_name AS name, sid FROM {schema}.wmi_r_user WHERE sid IS NOT NULL AND user_principal_name IS NOT NULL"),
```
(These are extra `(name, sid)` rows; the existing dedup `SELECT DISTINCT` at the end of `_principal_by_name` already handles overlaps. The `trim(name)`/`upper(sid)` insert already in place applies to all sources.)

## Step 4: Run — expect PASS (2 tests). Also re-run the existing `transforms_principal_test.py` to confirm no regression:
```
UV_PROJECT_ENVIRONMENT=C:/Users/domainadmin/AppData/Local/Temp/openhound-venv uv run --project C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm pytest C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/transforms_lookups_test.py C:/Users/domainadmin/Desktop/OpenHound/sccm/sccm/src/openhound_sccm/transforms_principal_test.py -v
```
## Step 5: Checkpoint — `git add` (stage only, NO commit).
