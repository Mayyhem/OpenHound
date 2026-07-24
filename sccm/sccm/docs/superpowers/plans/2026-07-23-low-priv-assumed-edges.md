# Low-Privilege Assumed Nodes/Edges Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make DEFAULT collection mode (possible edges ON) build the SCCM/MSSQL attack graph a non-privileged domain user can support — by wiring OpenHound's already-collected low-priv evidence (LDAP management-point capabilities + RemoteRegistry-on-site-servers) into `site_hierarchy` and the assumption/scaffolding builders — while `--disable-possible-edges` stays conservative, and every assumed node/edge is provenance-tagged and documented.

**Architecture:** The dominant fix is data wiring in the DuckDB preprocess transforms (`transforms.py`): feed `site_hierarchy` from LDAP+RemoteRegistry (unblocks the `nonsec`-gated families), and give the MSSQL site-DB identity a non-privileged signal (RemoteRegistry-confirmed → `MSSQLSvc` SPN + SCCM-relatedness). Assumed families get a shared provenance stamp and stay traversable. Collectors are NOT re-collected — the evidence is already present; only preprocess/convert and docs change.

**Tech Stack:** Python 3.13+ (stdlib + DuckDB SQL via `duckdb`), Typer CLI (existing), pytest 9. Design spec: `docs/superpowers/specs/2026-07-23-low-priv-assumed-edges-design.md`.

## Global Constraints

- **No git commits.** No-commit harness: each task ends at a *green checkpoint* (targeted tests pass); the human commits. Never run `git add`/`git commit`. ([[sdd-no-commit-harness]])
- **Only modify `sccm/sccm/`.** Do not edit OpenHound core or `openhound-collector-common` without asking (this plan needs neither).
- **Property casing = ConfigManBearPig-verbatim on OUTPUT** (graph.py `*Properties` field names / output keys), while DuckDB columns + model input fields stay `snake_case`. ([[sccm-property-casing-cmbp]])
- **`schema_SCCM.json` is hand-maintained** — if a new node/edge kind is emitted, sync it both ways with `kinds/edges.py`. `MSSQL_*` kinds go in the MSSQL schema, NOT `schema_SCCM.json`. ([[sccm-opengraph-schema-maintenance]])
- **`site_type` INTEGER contract:** 1=Secondary, 2=Primary, 4=CAS. Root = CAS(4) else parentless Primary(2). Preserve this in every `site_hierarchy` writer.
- **`--disable-possible-edges` is tightening-only** — it removes/does-not-create *assumed* families; it never removes *confirmed* data. `site_hierarchy` (Task 1) is confirmed and populated in BOTH modes.
- **Targeted tests only** ([[feedback-targeted-tests]]): run the specific offline `*_test.py` with the SCCM venv from repo root `c:\Users\domainadmin\Desktop\OpenHound`:
  `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/<file>_test.py -v`. Do NOT run the full suite.
- **Logging:** every new if/else or try/except gets an appropriately-levelled log line (error/warning/info/verbose/debug) or a comment saying why not (project CLAUDE.md).

---

## File Structure

**Modify (preprocess/convert):**
- `sccm/sccm/src/openhound_sccm/transforms.py` — the bulk. New: `_assumed_site_dbs` CTE/helper, provenance-stamp helper `_mark_assumed`. Modified: `_site_hierarchy` (add LDAP+RR arms + root fallback), `_mssql_sql_servers` (non-privileged arm), the MSSQL scaffolding node/edge builders (Tier C gating + provenance), the Tier-B edge builders (provenance tags), `_edge_coerce_relay_smb` (traversability), `_node_client_device_possible` (deterministic id — verify).
- `sccm/sccm/src/openhound_sccm/kinds/edge_help.py` (or the existing edge-help module) — help blurbs for assumed edge kinds.

**Modify (docs):**
- `sccm/sccm/README.md` — Assumptions/possible-edges catalog + Tier-D "needs privilege" callout + examples.
- `sccm/sccm/ARCHITECTURE.md` — new subsystem section + changelog.

**Modify (fixtures/tests):**
- `sccm/sccm/src/openhound_sccm/integration/fixtures/` — low-priv-expected cases (Task 9).
- Tests: `sccm/sccm/tests/site_hierarchy_lowpriv_test.py`, `assumed_site_db_test.py`, `provenance_test.py`, `mssql_scaffold_possible_test.py`, `sccm_possible_edges_lowpriv_test.py`, `coerce_smb_traversable_test.py`, `edge_help_assumed_test.py`, `integration_lowpriv_fixtures_test.py`.

**Test harness note:** the transforms take a `duckdb` connection + schema name. Existing offline tests (e.g. `transforms_safe_fallback_test.py`) show the pattern: create an in-memory/temp duckdb, create the raw input tables with the columns the transform reads, call the transform, assert on the output table. Reuse that pattern; read `transforms_safe_fallback_test.py` first for the exact fixture helpers.

---

## Task 1: Feed `site_hierarchy` from LDAP MP-capabilities + RemoteRegistry (the unlock)

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — `_site_hierarchy` (currently lines 192-256).
- Test: `sccm/sccm/tests/site_hierarchy_lowpriv_test.py`

**Interfaces:**
- Consumes: raw tables `ldap_management_points_raw` (cols incl. `site_code`, `site_type` STRING, `parent_site_code` STRING, `root_site_code` STRING — see `collectors/ldap.py:300-304`) and `remoteregistry_sites` (cols `source`, `site_code` — see `collectors/registry.py:342`).
- Produces: `{schema}.site_hierarchy(site_code, parent_site_code, site_type INTEGER, root_site_code)` populated when only LDAP and/or only RemoteRegistry ran. Downstream `_root_code`/`_first_primary_code` unchanged.

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/site_hierarchy_lowpriv_test.py
import duckdb
from openhound_sccm.transforms import _site_hierarchy

SCHEMA = "sccm"

def _con():
    con = duckdb.connect()
    con.execute(f"CREATE SCHEMA {SCHEMA}")
    return con

def _mp_raw(con, rows):
    con.execute(f"CREATE TABLE {SCHEMA}.ldap_management_points_raw "
                "(site_code VARCHAR, site_type VARCHAR, parent_site_code VARCHAR, root_site_code VARCHAR)")
    con.executemany(f"INSERT INTO {SCHEMA}.ldap_management_points_raw VALUES (?,?,?,?)", rows)

def _rr_sites(con, rows):
    con.execute(f"CREATE TABLE {SCHEMA}.remoteregistry_sites (source VARCHAR, site_code VARCHAR)")
    con.executemany(f"INSERT INTO {SCHEMA}.remoteregistry_sites VALUES (?,?)", rows)

def test_hierarchy_from_ldap_mp_caps_only():
    con = _con()
    # CAS 'CAS' (root), Primary 'PS1' reporting to CAS.
    _mp_raw(con, [("PS1", "Primary Site", "CAS", "CAS"),
                  ("CAS", "Central Administration Site", "None", "CAS")])
    _site_hierarchy(con, SCHEMA)
    rows = {r[0]: r for r in con.execute(
        f"SELECT site_code, parent_site_code, site_type, root_site_code FROM {SCHEMA}.site_hierarchy").fetchall()}
    assert rows["CAS"][2] == 4 and rows["PS1"][2] == 2
    assert rows["PS1"][3] == "CAS" and rows["CAS"][3] == "CAS"   # root stamped

def test_hierarchy_from_remoteregistry_only_falls_back_to_single_primary():
    con = _con()
    _rr_sites(con, [("RemoteRegistry-Triggers", "PS1")])
    _site_hierarchy(con, SCHEMA)
    row = con.execute(
        f"SELECT site_code, root_site_code FROM {SCHEMA}.site_hierarchy").fetchone()
    # RR gives site_code with no type; the single-site fallback treats it as the root.
    assert row[0] == "PS1" and row[1] == "PS1"

def test_privileged_still_works(monkeypatch):
    con = _con()
    con.execute(f"CREATE TABLE {SCHEMA}.adminservice_site_definitions "
                "(site_code VARCHAR, parent_site_code VARCHAR, site_type VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.adminservice_site_definitions VALUES ('PS1','None','2')")
    _site_hierarchy(con, SCHEMA)
    assert con.execute(f"SELECT site_type FROM {SCHEMA}.site_hierarchy").fetchone()[0] == 2
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/site_hierarchy_lowpriv_test.py -v`
Expected: FAIL — the LDAP-only and RR-only tests find an empty `site_hierarchy` (no LDAP/RR arms today).

- [ ] **Step 3: Add the LDAP + RemoteRegistry INSERT arms and a root fallback**

In `_site_hierarchy`, after the existing adminservice/wmi INSERTs (transforms.py:206-219) and BEFORE the "Collapse duplicate rows" block (222), add two `_safe` INSERTs. Map the MP-caps string `site_type` to the INTEGER contract; normalize sentinel parents to NULL:

```python
    # LDAP management-point capabilities already carry site type/parent/root
    # (collectors/ldap.py _parse_mp_capabilities). Low-priv reachable; feed them
    # so a domain-only bind still yields a hierarchy. String site_type -> INTEGER
    # contract (1=Secondary, 2=Primary, 4=CAS).
    _safe(
        con,
        "site_hierarchy<-ldap_mp",
        f"INSERT INTO {schema}.site_hierarchy "
        f"SELECT DISTINCT upper(site_code), "
        f"  CASE WHEN parent_site_code IN ('None','Undetermined','') OR parent_site_code IS NULL "
        f"       THEN NULL ELSE upper(parent_site_code) END, "
        f"  CASE site_type WHEN 'Central Administration Site' THEN 4 "
        f"                 WHEN 'Primary Site' THEN 2 "
        f"                 WHEN 'Secondary Site' THEN 1 ELSE NULL END "
        f"FROM {schema}.ldap_management_points_raw WHERE site_code IS NOT NULL",
    )
    # RemoteRegistry on a site server yields the site code (no type/parent). Feed
    # it so an RR-only run still registers the site; type stays NULL and is
    # filled by any LDAP row for the same code during the collapse below.
    _safe(
        con,
        "site_hierarchy<-remoteregistry",
        f"INSERT INTO {schema}.site_hierarchy "
        f"SELECT DISTINCT upper(site_code), NULL, NULL "
        f"FROM {schema}.remoteregistry_sites WHERE site_code IS NOT NULL",
    )
```

`_safe` already no-ops when a source table is absent (see other callers), so this is safe when only some phases ran.

- [ ] **Step 4: Add the single-site root fallback**

The existing root query (transforms.py:234-241) returns `None` when no row has `site_type` 4 or a parentless 2 — which happens for an RR-only run (all types NULL). After computing `root_code` (line 243) and before stamping (251), add:

```python
    if root_code is None:
        # No type-classified root (e.g. RemoteRegistry-only, which lacks site_type).
        # Fall back to the sole/first site code so single-hierarchy low-priv runs
        # still anchor a root. Deterministic ordering keeps reruns stable.
        fallback = con.execute(
            f"SELECT site_code FROM {schema}.site_hierarchy "
            f"WHERE site_code IS NOT NULL ORDER BY site_code LIMIT 1"
        ).fetchone()
        if fallback:
            root_code = fallback[0]
            logger.info("site_hierarchy: no typed root; falling back to first site %r in schema %r",
                        root_code, schema)
        else:
            logger.warning("site_hierarchy: no sites from any source in schema %r", schema)
```

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/site_hierarchy_lowpriv_test.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Green checkpoint** — leave uncommitted for the human.

---

## Task 2: Non-privileged site-database-server signal (`_assumed_site_dbs`) — decision D2

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — add helper `_assumed_site_dbs`; extend `_mssql_sql_servers` (currently line 2078) with a non-privileged arm.
- Test: `sccm/sccm/tests/assumed_site_db_test.py`

**Interfaces:**
- Consumes: `node_computer` (cols incl. `sid`/`object_sid`, `site_system_roles` VARCHAR[], `sccm_infra`), `mssql_server_instances` (SPN-derived host/port, from `collectors/mssql.py`), `remoteregistry_computers` (role tags incl. `SMS SQL Server@<site>`).
- Produces: a DuckDB view/CTE `{schema}.assumed_site_dbs(host_sid, site_code, basis)` where `basis` ∈ {`RemoteRegistry`, `SPN+SCCM`}; consumed by Task 4. Also: `_mssql_sql_servers` now includes these hosts (not only privileged `*_site_definitions_computers`).

- [ ] **Step 1: Read the current `_mssql_sql_servers`**

Read `transforms.py` around line 2078 (`_mssql_sql_servers`) and 2127-2207 (`_node_mssql_server` 3 arms) to see the exact columns produced (`host_sid`, `server_id`, `site_code`, `sccm_infra`). The new arm must produce the same columns.

- [ ] **Step 2: Write the failing test**

```python
# sccm/sccm/tests/assumed_site_db_test.py
import duckdb
from openhound_sccm.transforms import _assumed_site_dbs

SCHEMA = "sccm"

def _con_with_computers(rows):
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.node_computer "
                "(sid VARCHAR, site_system_roles VARCHAR[], sccm_infra BOOLEAN, mssql_spn BOOLEAN)")
    con.executemany(f"INSERT INTO {SCHEMA}.node_computer VALUES (?,?,?,?)", rows)
    return con

def test_rr_confirmed_site_db_classified():
    con = _con_with_computers([("S-1-DB", ["SMS SQL Server@PS1"], True, False)])
    _assumed_site_dbs(con, SCHEMA)
    r = con.execute(f"SELECT host_sid, site_code, basis FROM {SCHEMA}.assumed_site_dbs").fetchone()
    assert r == ("S-1-DB", "PS1", "RemoteRegistry")

def test_spn_plus_sccm_related_classified():
    con = _con_with_computers([("S-1-DB", ["SMS Site Server@PS1"], True, True)])
    _assumed_site_dbs(con, SCHEMA)
    assert con.execute(f"SELECT basis FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == "SPN+SCCM"

def test_arbitrary_sql_host_not_classified():
    # MSSQLSvc SPN but NOT SCCM-related (no SMS role, not sccm_infra) -> excluded.
    con = _con_with_computers([("S-1-RANDOM", [], False, True)])
    _assumed_site_dbs(con, SCHEMA)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.assumed_site_dbs").fetchone()[0] == 0
```

> Note: the test models the `MSSQLSvc` SPN presence as a boolean `mssql_spn` column for isolation. In the real transform, derive SPN presence by joining `mssql_server_instances` (SPN-sourced) on `host_sid`; the implementer wires that join in Step 4 and the smoke/live run validates it.

- [ ] **Step 3: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/assumed_site_db_test.py -v`
Expected: FAIL — `_assumed_site_dbs` does not exist.

- [ ] **Step 4: Implement `_assumed_site_dbs`**

Add near the other MSSQL helpers. RR-confirmed (authoritative) UNION the SPN+SCCM-related fallback:

```python
def _assumed_site_dbs(con: duckdb.DuckDBPyConnection, schema: str) -> None:
    """Identify site database servers without privileged (AdminService) data (D2).

    Primary signal: RemoteRegistry-confirmed 'SMS SQL Server@<site>' role (low-priv
    on a site server). Fallback: a host with an MSSQLSvc SPN that is also
    SCCM-related (carries an SMS role or sccm_infra). This is a deliberate
    tightening of CMBP's 'any host reachable on 1433' rule.
    """
    con.execute(
        f"CREATE OR REPLACE TABLE {schema}.assumed_site_dbs AS "
        # RR-confirmed
        f"SELECT sid AS host_sid, "
        f"       upper(split_part(list_filter(site_system_roles, x -> x LIKE 'SMS SQL Server@%')[1], '@', 2)) AS site_code, "
        f"       'RemoteRegistry' AS basis "
        f"FROM {schema}.node_computer "
        f"WHERE len(list_filter(site_system_roles, x -> x LIKE 'SMS SQL Server@%')) > 0 "
        f"UNION "
        # SPN + SCCM-related fallback (only hosts not already RR-confirmed)
        f"SELECT nc.sid AS host_sid, "
        f"       upper(split_part(list_filter(nc.site_system_roles, x -> x LIKE '%@%')[1], '@', 2)) AS site_code, "
        f"       'SPN+SCCM' AS basis "
        f"FROM {schema}.node_computer nc "
        f"WHERE nc.mssql_spn = true "                       # replace with join to mssql_server_instances on host_sid
        f"  AND (nc.sccm_infra = true OR len(nc.site_system_roles) > 0) "
        f"  AND len(list_filter(nc.site_system_roles, x -> x LIKE 'SMS SQL Server@%')) = 0"
    )
```

Replace the `nc.mssql_spn = true` placeholder-column with a real semi-join to the SPN-derived instances table, e.g. `nc.sid IN (SELECT host_sid FROM {schema}.mssql_server_instances)` (confirm the column name while reading in Step 1). Add a `logger.info` reporting the assumed-site-DB count.

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/assumed_site_db_test.py -v`
Expected: PASS (3 tests) — the `mssql_spn` boolean stands in for the SPN join in the unit test.

- [ ] **Step 6: Green checkpoint.**

---

## Task 3: Provenance stamp helper (`_mark_assumed`) — decision D3

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — add `_mark_assumed`.
- Test: `sccm/sccm/tests/provenance_test.py`

**Interfaces:**
- Produces: `_mark_assumed(props: dict, basis: str) -> dict` — returns `props` with `assumed=True`, `assumptionBasis=<human string>`, and `collectionSource` list gaining `f"Assumed-{basis}"`. Idempotent; preserves existing `collectionSource` entries. Output keys use CMBP-verbatim casing (`assumed`, `assumptionBasis`, `collectionSource`).

- [ ] **Step 1: Write the failing test**

```python
# sccm/sccm/tests/provenance_test.py
from openhound_sccm.transforms import _mark_assumed

def test_marks_assumed_and_tags_source():
    out = _mark_assumed({"collectionSource": ["LDAP-CmRcService"]},
                        basis="CmRcService SPN; SCCM client not confirmed")
    assert out["assumed"] is True
    assert out["assumptionBasis"] == "CmRcService SPN; SCCM client not confirmed"
    assert "Assumed-CmRcService SPN; SCCM client not confirmed" not in out["collectionSource"]  # tag is slugged, not raw
    assert any(s.startswith("Assumed-") for s in out["collectionSource"])
    assert "LDAP-CmRcService" in out["collectionSource"]  # preserved

def test_idempotent():
    a = _mark_assumed({}, basis="x")
    b = _mark_assumed(dict(a), basis="x")
    assert b["collectionSource"].count(next(s for s in b["collectionSource"] if s.startswith("Assumed-"))) == 1
```

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/provenance_test.py -v`
Expected: FAIL — `_mark_assumed` not defined.

- [ ] **Step 3: Implement `_mark_assumed`**

```python
def _mark_assumed(props: dict, basis: str) -> dict:
    """Stamp provenance on an assumed (unconfirmed) node/edge property dict (D3).

    Adds assumed=True, a human assumptionBasis, and an 'Assumed-<slug>' entry in
    collectionSource (idempotent). Assumed items still stay traversable — the tag
    is how an operator tells assumed from confirmed, not a suppression.
    """
    props["assumed"] = True
    props["assumptionBasis"] = basis
    slug = "Assumed-" + basis.split(";")[0].strip().replace(" ", "")
    sources = list(props.get("collectionSource") or [])
    if slug not in sources:
        sources.append(slug)
    props["collectionSource"] = sources
    return props
```

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/provenance_test.py -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Green checkpoint.**

> Note: SQL-built edges (most of transforms.py) can't call a Python dict helper mid-query. For those, add the equivalent columns directly in the INSERT (`true AS assumed`, `'<basis>' AS assumptionBasis`, `list_append(collectionSource, 'Assumed-<slug>')`). `_mark_assumed` is for any Python-side row construction; the SQL builders in Tasks 4-5 inline the same three fields. Keep the slug/basis strings identical between the two paths.

---

## Task 4: Tier-C MSSQL template scaffolding gated on `assumed_site_dbs`, possible-ON only

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — `_node_mssql_database` (2210), `_node_mssql_login` (2231), `_node_mssql_database_user` (2262), `_node_mssql_server_role` (2284), `_node_mssql_database_role` (2305); edge builders `_edge_mssql_structural` (2836), `_edge_mssql_membership` (2876), `_edge_coerce_relay_mssql` (3032).
- Test: `sccm/sccm/tests/mssql_scaffold_possible_test.py`

**Interfaces:**
- Consumes: `{schema}.assumed_site_dbs` (Task 2), `disable_possible_edges` flag (threaded via env `SOURCES__SCCM__DISABLE_POSSIBLE_EDGES`, read in transforms — confirm the exact accessor while reading).
- Produces: under possible-ON, the MSSQL scaffolding (`MSSQL_Database` `CM_<site>`, sysadmin/db_owner roles, machine-account logins/users, `MSSQL_Contains`/`Control*`/`HasLogin`/`IsMappedTo`/`MemberOf`, `MSSQL_CoerceAndRelayToMSSQL`) built off `assumed_site_dbs`, each carrying `assumed=true`/`assumptionBasis`/`Assumed-*`. Under possible-OFF, only RR-confirmed (basis='RemoteRegistry') scaffolding survives; the SPN+SCCM-assumed rows are dropped.

- [ ] **Step 1: Read the current MSSQL node/edge builders**

Read `transforms.py` 2078-2100 (`_mssql_sql_servers`), 2210-2322 (the scaffold node builders), 2836-2938 (structural/membership/service-account edges), 3032-3079 (`_edge_coerce_relay_mssql`). Note which read `_mssql_sql_servers` and how the site-DB rows flow in. Confirm how `disable_possible_edges` is currently read in transforms (grep `disable_possible_edges` in transforms.py; per `main.py:150` it maps to `SOURCES__SCCM__DISABLE_POSSIBLE_EDGES`).

- [ ] **Step 2: Write the failing test**

```python
# sccm/sccm/tests/mssql_scaffold_possible_test.py
import duckdb
from openhound_sccm.transforms import _assumed_site_dbs, _node_mssql_database

SCHEMA = "sccm"

def _base(disable, basis):
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    con.execute(f"CREATE TABLE {SCHEMA}.assumed_site_dbs (host_sid VARCHAR, site_code VARCHAR, basis VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.assumed_site_dbs VALUES ('S-1-DB','PS1',?)", [basis])
    con.execute(f"CREATE TABLE {SCHEMA}.node_mssql_server (server_id VARCHAR, host_sid VARCHAR, sccm_infra BOOLEAN)")
    con.execute(f"INSERT INTO {SCHEMA}.node_mssql_server VALUES ('S-1-DB:1433','S-1-DB',true)")
    return con

def test_database_built_when_possible_on():
    con = _base(disable=False, basis="SPN+SCCM")
    _node_mssql_database(con, SCHEMA, disable_possible_edges=False)
    r = con.execute(f"SELECT name, assumed FROM {SCHEMA}.node_mssql_database").fetchone()
    assert r[0] == "CM_PS1" and r[1] is True

def test_spn_assumed_database_dropped_when_possible_off():
    con = _base(disable=True, basis="SPN+SCCM")
    _node_mssql_database(con, SCHEMA, disable_possible_edges=True)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.node_mssql_database").fetchone()[0] == 0

def test_rr_confirmed_database_kept_when_possible_off():
    con = _base(disable=True, basis="RemoteRegistry")
    _node_mssql_database(con, SCHEMA, disable_possible_edges=True)
    assert con.execute(f"SELECT count(*) FROM {SCHEMA}.node_mssql_database").fetchone()[0] == 1
```

> This pins the contract for `_node_mssql_database`; apply the same possible-ON gate + basis filter + provenance columns to the sibling builders listed in Files. The test signature assumes these builders take `disable_possible_edges: bool` — if they currently read it from a context object instead, adapt the test to that accessor (discovered in Step 1) rather than changing the builder's real signature gratuitously.

- [ ] **Step 3: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/mssql_scaffold_possible_test.py -v`
Expected: FAIL — builders don't yet source `assumed_site_dbs` or emit `assumed`/`CM_<site>` off it.

- [ ] **Step 4: Rewire each scaffold builder to source `assumed_site_dbs` + gate + provenance**

For `_node_mssql_database`: build one `MSSQL_Database` per `assumed_site_dbs` row, name `CM_<site_code>`, linked to the `MSSQL_Server` by `host_sid`. Add the three provenance columns (`true AS assumed`, `'CM_<site> inferred from site code; DB internals not observed' AS assumptionBasis`, and append `'Assumed-SiteDB'` to `collectionSource`). Gate:

```python
    #  possible-OFF keeps only RemoteRegistry-confirmed site DBs; the SPN+SCCM
    #  fallback is an assumption, so it is dropped when tightening.
    basis_filter = "" if not disable_possible_edges else " AND a.basis = 'RemoteRegistry'"
```

Apply the identical pattern (source from `assumed_site_dbs`, `basis_filter`, provenance columns) to `_node_mssql_server_role` (sysadmin), `_node_mssql_database_role` (db_owner), `_node_mssql_login` + `_node_mssql_database_user` (machine-account logins for hosts whose `site_system_roles` include `SMS Site Server@<site>`/`SMS Provider@<site>`), and the edge builders `_edge_mssql_structural`, `_edge_mssql_membership`, `_edge_coerce_relay_mssql`. Keep the existing privileged arms intact (they already emit confirmed, un-assumed rows); the new arm is additive and de-duplicates by node id (privileged/confirmed wins — do not stamp `assumed` on a row that also has a confirmed source).

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/mssql_scaffold_possible_test.py -v`
Expected: PASS (3 tests).

- [ ] **Step 6: Green checkpoint.**

---

## Task 5: Tier-B SCCM edges — provenance tags now that `site_hierarchy` is populated

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — `_edge_assign_all_permissions` (2752), `_edge_coerce_relay_adminservice` (2965), `_edge_coerce_relay_smb` (3082), `_edge_local_admin_required` (grep for it), `_edge_replication` (2338).
- Test: `sccm/sccm/tests/sccm_possible_edges_lowpriv_test.py`

**Interfaces:**
- Consumes: `site_hierarchy` (Task 1, now non-empty at low-priv), `node_computer.site_system_roles`.
- Produces: these edges now emit at low-priv (they already build once `nonsec` is non-empty — Task 1 does that); the assumption-derived ones gain `assumed`/`assumptionBasis`/`Assumed-*`. `_edge_replication` stays confirmed (topology), NOT assumed.

- [ ] **Step 1: Confirm the Task-1 unblock end-to-end (integration-style offline test)**

```python
# sccm/sccm/tests/sccm_possible_edges_lowpriv_test.py
import duckdb
from openhound_sccm.transforms import _site_hierarchy, _edge_assign_all_permissions

SCHEMA = "sccm"

def _con():
    con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
    # LDAP-only hierarchy: single Primary PS1 (root via type=2, parentless).
    con.execute(f"CREATE TABLE {SCHEMA}.ldap_management_points_raw "
                "(site_code VARCHAR, site_type VARCHAR, parent_site_code VARCHAR, root_site_code VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.ldap_management_points_raw VALUES ('PS1','Primary Site','None','PS1')")
    _site_hierarchy(con, SCHEMA)
    # One computer tagged SMS Provider@PS1 (from HTTP SMS_Identification at low-priv).
    con.execute(f"CREATE TABLE {SCHEMA}.node_computer (id VARCHAR, sid VARCHAR, site_system_roles VARCHAR[])")
    con.execute(f"INSERT INTO {SCHEMA}.node_computer VALUES ('C-PROV','S-1-PROV',['SMS Provider@PS1'])")
    con.execute(f"CREATE TABLE {SCHEMA}.node_site (id VARCHAR, site_code VARCHAR)")
    con.execute(f"INSERT INTO {SCHEMA}.node_site VALUES ('SITE-PS1','PS1')")
    return con

def test_assign_all_permissions_emits_at_lowpriv_and_is_marked():
    con = _con()
    _edge_assign_all_permissions(con, SCHEMA, disable_possible_edges=False)
    rows = con.execute(f"SELECT assumed FROM {SCHEMA}.graph_edges "
                       f"WHERE kind = 'SCCM_AssignAllPermissions'").fetchall()
    assert len(rows) >= 1 and all(r[0] is True for r in rows)
```

> Adapt the exact input-table columns/edge-output table (`graph_edges` vs a per-builder table) to what you find in Step-1-of-Task-4's read. The behavioral assertion — "emits at low-priv once `site_hierarchy` is fed, and carries `assumed`" — is the contract.

- [ ] **Step 2: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/sccm_possible_edges_lowpriv_test.py -v`
Expected: FAIL — edge emits (Task 1 populated the hierarchy) but lacks the `assumed` column.

- [ ] **Step 3: Add provenance columns to the assumption-derived edge builders**

In `_edge_assign_all_permissions`, `_edge_coerce_relay_adminservice`, `_edge_coerce_relay_smb`, `_edge_local_admin_required`, add to each INSERT's edge-properties: `true AS assumed`, a builder-specific `assumptionBasis` (e.g. AssignAllPermissions → `"SMS Provider role implies site control; RBAC not confirmed"`; CoerceRelay* → `"relay feasibility assumed from role topology + NTLM/SMB-signing state"`), and append the matching `Assumed-*` tag to `collectionSource`. Leave `_edge_replication` unmarked (it is confirmed hierarchy topology, not an assumption). No change to the SQL join logic — Task 1 already made `nonsec` non-empty.

- [ ] **Step 4: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/sccm_possible_edges_lowpriv_test.py -v`
Expected: PASS.

- [ ] **Step 5: Green checkpoint.**

---

## Task 6: `SCCM_CoerceAndRelayToSMB` traversability + deterministic possible-client ids

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/transforms.py` — `_edge_coerce_relay_smb` (3082); `_node_client_device_possible` (1924).
- Test: `sccm/sccm/tests/coerce_smb_traversable_test.py`

**Interfaces:**
- Produces: `SCCM_CoerceAndRelayToSMB` edges carry `traversable=true`; possible-client-device node ids are deterministic (stable across reruns), not random GUIDs.

- [ ] **Step 1: Read the two functions** — confirm the current traversable value on `_edge_coerce_relay_smb` (CMBP shipped this non-traversable due to a kind-name-mismatch bug; verify OpenHound's value) and confirm `_node_client_device_possible` id construction (per agent map it may already be deterministic — if so, this half is a no-op + a regression test).

- [ ] **Step 2: Write the failing/guard test**

```python
# sccm/sccm/tests/coerce_smb_traversable_test.py
import duckdb
from openhound_sccm.transforms import _node_client_device_possible

SCHEMA = "sccm"

def test_possible_client_ids_are_deterministic():
    def run():
        con = duckdb.connect(); con.execute(f"CREATE SCHEMA {SCHEMA}")
        con.execute(f"CREATE TABLE {SCHEMA}.ldap_cmrc_devices "
                    "(name VARCHAR, ad_domain_sid VARCHAR, site_code VARCHAR)")
        con.execute(f"INSERT INTO {SCHEMA}.ldap_cmrc_devices VALUES ('PS1-DEV','S-1-DEV','PS1')")
        con.execute(f"CREATE TABLE {SCHEMA}.site_hierarchy "
                    "(site_code VARCHAR, parent_site_code VARCHAR, site_type INTEGER, root_site_code VARCHAR)")
        con.execute(f"INSERT INTO {SCHEMA}.site_hierarchy VALUES ('PS1',NULL,2,'PS1')")
        _node_client_device_possible(con, SCHEMA, disable_possible_edges=False)
        return con.execute(f"SELECT id FROM {SCHEMA}.node_client_device").fetchone()[0]
    assert run() == run()   # same id across two independent runs
```

- [ ] **Step 3: Run to verify it fails (or passes if already deterministic)**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/coerce_smb_traversable_test.py -v`
Expected: FAIL if ids are random; PASS if already deterministic (then this is a guard test).

- [ ] **Step 4: Make ids deterministic + ensure SMB relay traversable**

If ids are random, derive them from stable inputs, e.g. `'possible-client-' || lower(ad_domain_sid)` (one possible client per computer SID). In `_edge_coerce_relay_smb`, ensure the emitted edge sets `traversable = true` (match the other coerce builders). Add a comment referencing the CMBP kind-mismatch bug this avoids ([[sccm-stage6-relay-decisions]]).

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/coerce_smb_traversable_test.py -v`
Expected: PASS.

- [ ] **Step 6: Green checkpoint.**

---

## Task 7: Entity-panel help blurbs for assumed edge kinds

**Files:**
- Modify: the edge-help module (grep for the existing edge-help/property-bag pattern — [[bloodhound-opengraph-edge-help-limit]]; likely `src/openhound_sccm/kinds/edge_help.py` or similar).
- Test: `sccm/sccm/tests/edge_help_assumed_test.py`

**Interfaces:**
- Produces: each assumed edge kind (`SCCM_AssignAllPermissions`, `SCCM_LocalAdminRequired`, `SCCM_CoerceAndRelayToAdminService`, `SCCM_CoerceAndRelayToSMB`, `MSSQL_CoerceAndRelayToMSSQL`, `MSSQL_Contains`/`Control*`/`HasLogin`/`IsMappedTo`/`MemberOf` when assumed, `SCCM_SameHostAs`/`SCCM_HasClient`) has a help string stating: the inference rule, the data source, and the false-positive caveat.

- [ ] **Step 1: Read the existing edge-help module** to learn the exact structure (dict keyed by kind → help text) and how it reaches the property bag.

- [ ] **Step 2: Write the failing test**

```python
# sccm/sccm/tests/edge_help_assumed_test.py
from openhound_sccm.kinds import edge_help  # adjust import to the real module

ASSUMED_KINDS = [
    "SCCM_AssignAllPermissions", "SCCM_LocalAdminRequired",
    "SCCM_CoerceAndRelayToAdminService", "SCCM_CoerceAndRelayToSMB",
    "MSSQL_CoerceAndRelayToMSSQL", "SCCM_SameHostAs", "SCCM_HasClient",
]

def test_every_assumed_kind_has_help_with_caveat():
    table = edge_help.HELP  # adjust to the real accessor
    for k in ASSUMED_KINDS:
        assert k in table, f"missing help for {k}"
        assert any(w in table[k].lower() for w in ("assume", "may be", "false positive", "unconfirmed"))
```

- [ ] **Step 3: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/edge_help_assumed_test.py -v`
Expected: FAIL — missing kinds or missing caveat wording.

- [ ] **Step 4: Add/extend the help entries** with the inference rule + source + caveat for each kind (concrete text per the design-spec §4 table).

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/edge_help_assumed_test.py -v`
Expected: PASS.

- [ ] **Step 6: Green checkpoint.**

---

## Task 8: Documentation — README assumption catalog + ARCHITECTURE section

**Files:**
- Modify: `sccm/sccm/README.md`, `sccm/sccm/ARCHITECTURE.md`.

- [ ] **Step 1: README** — expand the possible-edges/Assumptions section into a catalog table (one row per assumed family: kind, inference rule, data source, false-positive caveat), add a "Requires privileged collection (AdminService/WMI)" callout listing the Tier-D families (design-spec §5), and add copy-pasteable mayyhem examples for default vs `--disable-possible-edges`. Keep it code-truth ([[readme-code-truth-scope]]): only document kinds actually emitted.

- [ ] **Step 2: ARCHITECTURE.md** — add a section describing the LDAP/RemoteRegistry-fed `site_hierarchy` (the Task-1 wiring, why it diverges from a stock AdminService-only build) and the assumption/provenance engine (`_assumed_site_dbs`, `_mark_assumed`, the possible-edges gate and basis filter). Add a changelog entry. Fix any code references the change invalidated (per CLAUDE.md ARCHITECTURE rule).

- [ ] **Step 3: Doc-truth check** — re-read both against the final code; confirm every documented kind is emitted and every assumption row matches a builder. No automated test; this is a manual read.

- [ ] **Step 4: Green checkpoint.**

---

## Task 9: Integration fixtures — low-priv baseline for `--run-integration-tests`

**Files:**
- Modify: `sccm/sccm/src/openhound_sccm/integration/fixtures/` (edges.py/nodes.py) and `integration/__init__.py`.
- Test: `sccm/sccm/tests/integration_lowpriv_fixtures_test.py`

**Interfaces:**
- Produces: a low-priv-expected fixture set (or per-case tags) capturing what DEFAULT mode should now emit without AdminService (the Tier A+B+C families), distinct from the existing domainadmin baseline. Decide the mechanism during Step 1 (a second fixture list vs a `requires_privilege` flag per case that the runner can partition).

- [ ] **Step 1: Read `integration/fixtures/edges.py`, `nodes.py`, `__init__.py`** and decide the partition mechanism. Recommended: add a `requires_privilege: bool` to `EdgeCase`/`NodeCase` (default False) for the Tier-D families, so a low-priv run asserts only the non-privileged subset.

- [ ] **Step 2: Write the failing test**

```python
# sccm/sccm/tests/integration_lowpriv_fixtures_test.py
from openhound_sccm.integration.fixtures.edges import MAYYHEM_EDGE_CASES

def test_tier_d_cases_flagged_requires_privilege():
    # The RBAC/service-account families cannot be built without AdminService.
    tier_d = {"SCCM_FullAdministrator", "SCCM_IsAssigned", "SCCM_IsMappedTo",
              "SCCM_AllPermissions", "MSSQL_GetTGS", "MSSQL_GetAdminTGS", "MSSQL_ServiceAccountFor"}
    for c in MAYYHEM_EDGE_CASES:
        if c.kind in tier_d:
            assert getattr(c, "requires_privilege", False) is True, f"{c.id} must be flagged"
```

- [ ] **Step 3: Run to verify it fails**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/integration_lowpriv_fixtures_test.py -v`
Expected: FAIL — the attribute/flag doesn't exist yet.

- [ ] **Step 4: Add the `requires_privilege` flag** to the case dataclasses (shared engine change is owner-approved-additive only if truly needed — prefer keeping the flag in the SCCM fixture layer if `EdgeCase` can't be extended without a shared-lib edit; if a shared-lib edit is required, STOP and ask). Flag the Tier-D cases. Update `run_integration_tests` to accept a `privileged: bool` param (default True to preserve current behavior) that filters out `requires_privilege` cases when False.

- [ ] **Step 5: Run to verify it passes**

Run: `./sccm/sccm/.venv/Scripts/python.exe -m pytest sccm/sccm/tests/integration_lowpriv_fixtures_test.py -v`
Expected: PASS.

- [ ] **Step 6: Green checkpoint.**

---

## Task 10: Live re-validation (no TDD — evidence gathering)

**Files:** none (uses `sccm/tests/live-comparison/lowpriv_check/` harness).

- [ ] **Step 1:** Re-run the `lowpriv_check` harness end-to-end: `run-cmbp-both.ps1` (already produces CMBP baselines) and `run-openhound-both.ps1` (default + `--disable-possible-edges`), both as `MAYYHEM\lowpriv` via the netonly launcher.
- [ ] **Step 2:** Confirm DEFAULT-mode OpenHound now emits the Tier A+B+C families (client devices, SameHostAs/HasClient, AdminsReplicatedTo, AssignAllPermissions, LocalAdminRequired, CoerceAndRelay{AdminService,SMB,MSSQL}, MSSQL scaffolding) with `assumed`/`assumptionBasis` set, and that `--disable-possible-edges` drops the assumed families while keeping confirmed data.
- [ ] **Step 3:** Confirm NO Tier-D fabrication (no `SCCM_FullAdministrator`/`IsAssigned`/`AllPermissions`, no `MSSQL_GetTGS`/service-account edges) unless privileged data was actually collected.
- [ ] **Step 4:** Run `--run-integration-tests` in low-priv mode (Task 9 partition) and confirm the non-privileged subset passes.
- [ ] **Step 5:** Update `lowpriv_check/SUMMARY.md` with the post-fix comparison. Green checkpoint (no commit).

---

## Self-Review notes

- **Spec coverage:** Tiers A (Task 1,6), B (Task 1,5), C (Task 2,4); provenance (Task 3, inlined in 4/5); labeling/help (Task 7); docs (Task 8); Tier-D exclusion asserted (Task 9); improvements #1 (Task 1), #2 (Task 1 root/D4), #3 (Task 2), #4 (Task 3), #5 (Task 6), #6 (Task 6); live re-validation (Task 10). All spec sections map to a task.
- **Discovery steps are deliberate, not placeholders:** Tasks 2/4/5/6/7/9 open with a "read the current function" step because they modify a large existing file (`transforms.py`, ~3400 lines) whose exact current SQL must be seen before editing; the concrete change (SQL/columns/predicates) is specified in the following step.
- **Type consistency:** provenance fields are `assumed`/`assumptionBasis`/`collectionSource` everywhere; `assumed_site_dbs(host_sid, site_code, basis)` with `basis ∈ {RemoteRegistry, SPN+SCCM}` is consumed identically in Task 4; `site_type` INTEGER 1/2/4 is used consistently in Tasks 1/6.
- **Open item to confirm at execution:** whether the MSSQL scaffold builders read `disable_possible_edges` via a parameter or a context/env accessor (Task 4 Step 1) — adapt the test signatures accordingly; do not change a builder's real signature just to fit the test.
