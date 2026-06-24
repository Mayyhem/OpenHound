# Task D3: `HasSession` edge (Computer → User) — RemoteRegistry + MSSQL service account

Two sources UNIONed into the `HasSession` kind:
1. **RemoteRegistry logged-on user (CMBP :5029):** from `remoteregistry_users`, `start = upper(host_object_sid)` (added in A1), `end = upper(object_sid)` (the logged-on user).
2. **MSSQL service account on the site DB server (CMBP :8007):** from `adminservice_site_systems`/`wmi_site_systems` where `sql_server_service_logon_account` is a **domain** account, `start =` the SQL host's Computer SID (resolve `network_os_path` host → `node_computer`), `end =` the service-account SID (resolve via `principal_by_name`). Skip local accounts (`NT AUTHORITY\*`, `LOCALSYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, anything without a backslash).

`HasSession` IS in `TRAVERSABLE_EDGE_KINDS` (C0), so the model already marks it traversable.

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` (add `_edge_has_session`; call from `transforms()` immediately after `_edge_member_of`)
- Create (test): `sccm/sccm/src/openhound_sccm/edge_has_session_test.py`

**Interfaces — Consumes:** `remoteregistry_users` (`host_object_sid`, `object_sid`), `adminservice_site_systems`/`wmi_site_systems` (`network_os_path`, `sql_server_service_logon_account`), `node_computer` (`sid`, `name`, `dnshostname`), `principal_by_name`. **Produces:** `HasSession` rows in `graph_edges`.

## Step 1: Write the failing test
```python
# src/openhound_sccm/edge_has_session_test.py
import duckdb
from openhound_sccm.transforms import transforms

def test_edge_has_session_registry_and_mssql():
    con = duckdb.connect(":memory:")
    con.execute("CREATE SCHEMA IF NOT EXISTS sccm")
    # RemoteRegistry arm: host -> logged-on user
    con.execute("CREATE TABLE sccm.remoteregistry_users AS SELECT "
                "'S-1-5-21-1-2-3-1106' AS object_sid, 'S-1-5-21-1-2-3-1104' AS host_object_sid")
    # MSSQL arm: a node_computer for SQL01 (from r_system), a domain svc account, and a local account (excluded)
    con.execute("CREATE TABLE sccm.adminservice_r_system AS SELECT 'SQL01' AS name, "
                "'S-1-5-21-1-2-3-1200' AS sid, false AS obsolete")
    con.execute("CREATE TABLE sccm.adminservice_r_user AS SELECT 'svc_sql' AS name, "
                "'S-1-5-21-1-2-3-1300' AS sid, 'MAYYHEM\\svc_sql' AS unique_user_name")
    con.execute("CREATE TABLE sccm.adminservice_site_systems AS SELECT * FROM (VALUES "
                "('\\\\SQL01.lab', 'MAYYHEM\\svc_sql'), "
                "('\\\\SQL01.lab', 'NT AUTHORITY\\SYSTEM')) "
                "AS t(network_os_path, sql_server_service_logon_account)")
    transforms(con)
    rows = con.execute("SELECT start_id, end_id FROM sccm.graph_edges "
                       "WHERE kind='HasSession' ORDER BY start_id, end_id").fetchall()
    assert rows == [
        ("S-1-5-21-1-2-3-1104", "S-1-5-21-1-2-3-1106"),   # RemoteRegistry: host -> user
        ("S-1-5-21-1-2-3-1200", "S-1-5-21-1-2-3-1300"),   # MSSQL: SQL01 host -> svc account
    ]
    # the NT AUTHORITY\SYSTEM local account produced no edge
```
> Backslash rule: in Python source, `'\\'` = one backslash, `'\\\\'` = two backslashes. So `'\\\\SQL01.lab'` stores `\\SQL01.lab` (a UNC-style leading double backslash, as SMS emits), and `'MAYYHEM\\svc_sql'` stores `MAYYHEM\svc_sql`.

## Step 2: Run — expect failure.
`pytest .../edge_has_session_test.py -v`

## Step 3: `_edge_has_session` in `transforms.py`
```python
def _edge_has_session(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Computer -> User sessions (CMBP ps1:5029 + :8007). Two sources:
    (1) RemoteRegistry logged-on user; (2) the MSSQL service account on the site DB
    server (domain accounts only). HasSession is traversable (allow-list)."""
    from .kinds.edges import HAS_SESSION

    # (1) RemoteRegistry: host_object_sid -> the logged-on user's object_sid.
    _safe(con, "edge_has_session<-remoteregistry_users",
          f"INSERT INTO {schema}.graph_edges BY NAME "
          f"SELECT upper(host_object_sid) AS start_id, upper(object_sid) AS end_id, "
          f"'{HAS_SESSION}' AS kind "
          f"FROM {schema}.remoteregistry_users "
          f"WHERE host_object_sid IS NOT NULL AND object_sid IS NOT NULL")

    # (2) MSSQL service account: SQL host computer -> service-account user.
    # network_os_path is like '\\\\SQL01.lab' -> strip leading backslashes, take the host
    # label before the first dot, lowercase; match node_computer by dnshostname or name.
    host_expr = "lower(split_part(ltrim(ss.network_os_path, '\\'), '.', 1))"
    for _src in ("adminservice_site_systems", "wmi_site_systems"):
        _ensure_columns(con, schema, _src, {"network_os_path": "VARCHAR", "sql_server_service_logon_account": "VARCHAR"})
        _safe(con, f"edge_has_session<-{_src}",
              f"INSERT INTO {schema}.graph_edges BY NAME "
              f"SELECT nc.sid AS start_id, pbn.sid AS end_id, '{HAS_SESSION}' AS kind "
              f"FROM {schema}.{_src} ss "
              f"JOIN {schema}.node_computer nc "
              f"  ON lower(split_part(nc.dnshostname, '.', 1)) = {host_expr} "
              f"  OR lower(nc.name) = {host_expr} "
              f"JOIN {schema}.principal_by_name pbn "
              f"  ON upper(trim(ss.sql_server_service_logon_account)) = upper(pbn.name) "
              f"WHERE ss.network_os_path IS NOT NULL "
              f"  AND ss.sql_server_service_logon_account IS NOT NULL "
              f"  AND contains(ss.sql_server_service_logon_account, '\\') "
              f"  AND upper(ss.sql_server_service_logon_account) NOT LIKE 'NT AUTHORITY\\%' "
              f"  AND upper(ss.sql_server_service_logon_account) NOT IN ('LOCALSYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE')")
```
Call `_edge_has_session(con, schema)` in `transforms()` immediately after `_edge_member_of(con, schema)`.

> Backslash-in-SQL note: inside the Python f-strings, `'\\'` becomes a single backslash in the emitted SQL (so `ltrim(..., '\')`, `contains(..., '\')`), and `'NT AUTHORITY\\%'` becomes `'NT AUTHORITY\%'` (literal backslash + `%` wildcard; DuckDB `LIKE` uses no escape char by default, so `\` is literal). `contains('\')` gates to accounts that have a domain separator; the `NT AUTHORITY\%` exclusion removes the built-in virtual accounts that also contain a backslash.

## Step 4: Run — expect PASS. ## Step 5: Checkpoint — `git add` (stage only).
