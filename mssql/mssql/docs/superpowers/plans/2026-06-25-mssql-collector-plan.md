# MSSQL OpenHound Collector — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Read the companion spec `../specs/2026-06-25-mssql-collector-design.md` first — it holds the locked decisions (D1–D9), full node/edge catalogs, ID scheme, CLI surface, collection order, and acceptance criteria. The **source of truth for per-edge derivation logic** is the Go implementation in `MSSQLHound/internal/collector/{collector,cve}.go` and `internal/bloodhound/edges.go`; for collection *order/intent* it is `MSSQLHound/powershell_deprecated/MSSQLHound.ps1`. The reference for every OpenHound/DLT pattern is `sccm/sccm/src/openhound_sccm/`.

**Goal:** Build a pure-Python OpenHound/DLT collector in `mssql/mssql` with full feature parity to MSSQLHound — identical nodes, edges, edge types, properties, CLI, logging, and output — verified by the existing MSSQLHound validators run against the new collector's output, as three privilege-tiered users.

**Architecture:** `collect` runs per-target SQL in the exact `.ps1` order via pure-Python TDS/auth (`impacket`+`pywin32`) and writes raw JSONL; `preproc` loads it into DuckDB and builds derived/lookup tables; `convert` runs the ported edge-derivation logic and emits OpenGraph. A pure-Python adapter reshapes the OpenGraph output into MSSQLHound's zip envelope so the existing Go/PS1 validators consume it unchanged.

**Tech Stack:** Python 3.13–3.14, OpenHound (DLT), DuckDB, impacket (TDS/NTLM/Kerberos/SPNEGO), pywin32 (SSPI), ldap3 (AD/SPN), dnspython, Typer.

## Global Constraints

- Only modify files under `mssql/mssql/`. Never modify OpenHound core; if unavoidable, STOP and ask (CLAUDE.md).
- Pure Python, in-process only — no child processes, no native binaries (D1). Applies to the shipped collector; the **test harness** may shell out to the Go binary / `go test` / `.ps1` (D4).
- Port **all** node/edge properties for entity-panel parity (CLAUDE.md).
- Verbatim kind strings: node kinds `MSSQL_Server|Login|ServerRole|Database|DatabaseUser|DatabaseRole|ApplicationRole` + `User|Group|Computer` (AD, with `"Base"`); edge kinds exactly per spec §6; `source_kind = "MSSQL_Base"`.
- Preserve the exact `.ps1` collection order inside `collect` (D8, spec §8).
- Use an isolated uv venv outside the repo for validation: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-mssql-venv uv run …` (AGENTS.md §5). Do not touch the repo `.venv`.
- A log line of appropriate level per if/else and try/except, or a comment (CLAUDE.md).
- Tests under `mssql/mssql/tests/`. Do not `git commit` (user commits). Track with `gtk`.
- Cap every EPA/auth TLS context at `ssl.TLSVersion.TLSv1_2` (spec §3, §14).
- Surface any decision made on the basis of SCCM prior art before executing (CLAUDE.md).

> **Shared-library note (D10, spec §2.1):** generic infra — auth/TDS/AD/WMI clients, DNS discovery, `phased_pipeline`, the push→pull DLT source bridge, the convert-reads-DuckDB pipeline, `duckdb_safe` helpers, `log_context`, `stub_node`/`graph_edge`, SOCKS5 — lives in **`openhound-collector-common`** (built in Stage S). Anywhere a later task says "port/reuse from `sccm/.../X`", it means **import from `openhound_collector_common`** (which was generalized from that SCCM source in Stage S). The `mssql` package contains only MSSQL-specific code. SCCM is not modified.

---

## Stage 0 — Tickets, scaffolding teardown, deps, framework wiring

**Outcome:** `openhound collect mssql --help` shows the full flag surface; the extension imports and passes `validate_extension`; boilerplate example schema removed. No collection yet.

### Task 0.1: Create tickets and isolated venv

- [ ] Run `gtk help`; create a parent ticket "MSSQL OpenHound collector port" and per-stage child tickets (flags BEFORE the title positional — memory `gtk-create-flag-order`).
- [ ] Create the **SCCM-agent convergence ticket** (D10): "Migrate SCCM extension onto `openhound-collector-common` shared library" — body lists the modules SCCM should switch to importing (spec §2.1) and notes SCCM currently keeps its own copies. This is the tracked DRY follow-up; SCCM stays untouched in this milestone.
- [ ] Create the validation venv: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-mssql-venv uv sync` from `mssql/mssql`. Expected: resolves `openhound` + dev deps.
- [ ] Verify baseline import: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-mssql-venv uv run python -c "import openhound_mssql.main"`. Expected: no error (boilerplate still present).

### Task 0.2: Declare runtime dependencies

**Files:** Modify `mssql/mssql/pyproject.toml`

- [ ] Add the local **`openhound-collector-common`** path/workspace dependency per spec §3 (the third-party auth/transport deps live in the shared lib's own pyproject — Stage S). Keep the `openhound` git dep.
- [ ] `UV_PROJECT_ENVIRONMENT=/tmp/openhound-mssql-venv uv sync`. Expected: shared lib + transitive impacket/ldap3/pywin32 resolve. (Stage S must be created first, or sync will fail to find the path dep — do Stage S before this sync.)
- [ ] Verify: `uv run python -c "import impacket.tds, ldap3, dns.resolver; import sys, importlib; print('win32' if sys.platform=='win32' else 'nonwin', importlib.util.find_spec('win32security') is not None)"`. Expected: prints `win32 True` on this host.

### Task 0.3: Real extension metadata

**Files:** Modify `mssql/mssql/extension.yaml`

- [ ] Replace example credential/parameter with the real credential names (sql_user/sql_password/nt_hash/ldap_user/ldap_password/kerberos params) and non-secret parameters (targets, domain, dc, workers, etc.) matching the CLI (spec §4). Set `homepage`/`references` URLs (or leave a tracked TODO if unknown — surface to user).
- [ ] Verify it still loads: `uv run python -c "import yaml,io; yaml.safe_load(open('extension.yaml'))"`.

### Task 0.4: App object + package skeleton

**Files:** Modify `src/openhound_mssql/main.py`; Create `src/openhound_mssql/clients/__init__.py`, `src/openhound_mssql/log_context.py`

**Interfaces — Produces:** `app = OpenHound("mssql", source_kind="MSSQL_Base", help=…)` importable from `openhound_mssql.main`.

- [ ] Set `app = OpenHound("mssql", source_kind="MSSQL_Base", help="OpenGraph collector for Microsoft SQL Server attack paths")`. Remove the `# replace source_kind` comment.
- [ ] Port `log_context.py` from `sccm/sccm/src/openhound_sccm/log_context.py` (VERBOSE tier, `target_context`/`phase_context` contextvars, `LogContextFilter`, `install_filter`, `with_log_context`), trimming SCCM-specific phase names.
- [ ] Verify: `uv run python -c "from openhound_mssql.main import app; print(app.name, app._source_kind if hasattr(app,'_source_kind') else 'ok')"`.

### Task 0.5: Custom Typer collect command with full flag surface

**Files:** Modify `src/openhound_mssql/main.py`

**Interfaces — Produces:** `collect_mssql(output_path, …all flags…)` registered via `@_collect_typer.command(name="mssql")`; `app.collector = collect_mssql`; `_FLAG_TO_ENV` map; `_apply_env_overrides`, `_drop_empty_dlt_env_values`, `_apply_log_level` helpers (ported/trimmed from SCCM `main.py`).

- [ ] `from openhound.cli.collect import collect as _collect_typer`. Define `collect_mssql` with every flag in spec §4 as `typer.Option(...)` (short+long aliases, defaults, help, group annotations). Add the mutual-exclusion validation — SQL: nt-hash⊕password, ticket⊕password, ticket⊕nt-hash; LDAP: ldap-nt-hash⊕ldap-password, ldap-ticket⊕ldap-password, ldap-ticket⊕ldap-nt-hash. Kerberos is a single `--ticket` / `--ldap-ticket` (base64 .kirbi/KRB-CRED), not the five Go krb5 flags (D12).
- [ ] Build `_FLAG_TO_ENV` (`SOURCES__MSSQL__*`); set envs before building the source (CLI wins; drop empties).
- [ ] `app.collector = collect_mssql` (so `validate_extension` passes). Leave the body calling a `_run_collection(...)` stub that currently just logs and returns (filled in Stage 3).
- [ ] Wire `_apply_log_level(verbose, debug)` (RUNTIME__LOG_* env + handler level lowering; ported from SCCM).

- [ ] **Verify flag surface:** `uv run python -m openhound collect mssql --help` (or `uv run openhound collect mssql --help`). Expected: all Authentication/Collection/Performance/Output flags listed.
- [ ] **Verify validation:** `uv run python -c "from openhound.core.manager import CollectorManager; import openhound_mssql.main as m; print(bool(m.app.collector))"`. Expected: `True`.

### Task 0.6: Remove example schema, add empty real modules

**Files:** Modify `kinds/nodes.py`, `kinds/edges.py`, `models/__init__.py`, `models/asset.py`, `graph.py`, `source.py`, `transforms.py`, `lookup.py`; delete the `EX_Asset`/`Group`/`example_assets` example content.

- [ ] Strip example `EX_*` kinds, the 100-dummy-asset resource, and the phantom `organizations`/`applications` lookup methods. Leave minimal compiling stubs (filled in Stages 1–6).
- [ ] Update `tests/test_extension_methods.py` so the structural assertions still pass against the new (empty-but-valid) registration. Replace the bare `try/except: pass` import guard with a real import.
- [ ] **Verify:** `UV_PROJECT_ENVIRONMENT=/tmp/openhound-mssql-venv uv run pytest mssql/mssql/tests/test_extension_methods.py -v`. Expected: PASS.

---

## Stage 1 — Graph schema (kinds, properties, IDs)

**Outcome:** All node/edge kind constants, property dataclasses, and the ID-generation helpers exist with unit tests. No live data yet.

### Task 1.1: Kind constants

**Files:** `kinds/nodes.py`, `kinds/edges.py`, `kinds/__init__.py`
**Interfaces — Produces:** node-kind constants (spec §5) and edge-kind constants + `TRAVERSABLE_EDGE_KINDS`, `POSSIBLE_EDGE_KINDS`, `NONTRAVERSABLE_EDGE_KINDS` frozensets (spec §6).

- [ ] Write all node-kind strings and edge-kind strings verbatim (cross-check against `internal/bloodhound/writer.go` `NodeKinds`/`EdgeKinds` and `integration_report_test.go` `knownEdgeTypes`).
- [ ] Test `tests/unit/test_kinds.py`: assert the set of edge kinds ⊇ the 38 `knownEdgeTypes`; assert traversable/possible/nontraversable partitions match `edges.go IsTraversableEdge` + the possible-edge list.
- [ ] Verify: `uv run pytest mssql/mssql/tests/unit/test_kinds.py -v`. Expected: PASS.

### Task 1.2: ID-generation helpers

**Files:** Create `src/openhound_mssql/ids.py`; Test `tests/unit/test_ids.py`
**Interfaces — Produces:** `server_oid(computer_sid, hostname, instance, port)`, `principal_oid(name, server_oid)`, `database_oid(server_oid, db_name)`, `db_principal_oid(name, server_oid, db_name)`, `extract_db_id(principal_id)`, `rewrite_server_id(old, new, objs)`.

- [ ] Implement per spec §5 / collector.go ID rules. `db_principal_oid` = `f"{name}@{server_oid}\\{db_name}"`; `extract_db_id` splits on first `@`.
- [ ] Test with the Go example IDs (e.g. `S-1-5-21-…-1001:1433`, `dbo@…:1433\msdb`, `public@…\msdb`). Include the hostname-fallback and named-instance cases.
- [ ] Verify: `uv run pytest mssql/mssql/tests/unit/test_ids.py -v`. Expected: PASS.

### Task 1.3: Node/edge property dataclasses + graph base

**Files:** `graph.py`; Test `tests/unit/test_graph.py`
**Interfaces — Produces:** `MSSQLNode(Node)`, `MSSQLNodeProperties(NodeProperties)` (+ one subclass or field-superset per node kind), `MSSQLEdgeProperties(EdgeProperties)` (composition/general/windowsAbuse/linuxAbuse/opsec/references/withGrant + injected typed props). Use the **dataclass** variants (`openhound.core.models.entries_dataclass`), since convert serializes via `asdict` (framework brief §4).

- [ ] Subclass `NodeProperties` adding every property in spec §5 using **MSSQLHound's EXACT original names (D11)** — `isMixedModeAuthEnabled`, `servicePrincipalNames`, `SQLServer`, `ownerPrincipalID`, etc. (explicit fields — dataclass form has no `extra="allow"`). Keep OpenHound's mandated base fields (`name`/`displayname`/`environmentid`/`last_seen`). `MSSQLNode.__post_init__` sets `self.id`; `environmentid` = the server node's OpenGraph id (root/environment node per openhound.md rule). Edge property keys verbatim too (`general`, `windowsAbuse`, `linuxAbuse`, `opsec`, `references`, `composition`, `withGrant`).
- [ ] Test: build a `MSSQL_Server` node + a `MSSQL_MemberOf` edge, `asdict(...)`, assert JSON shape matches spec §7 (`{"id","kinds","properties"}`, edge `{"start":{"value"},"end":{"value"},"kind","properties"}`).
- [ ] Verify: `uv run pytest mssql/mssql/tests/unit/test_graph.py -v`. Expected: PASS.

---

## Stage S — Shared library `openhound-collector-common` (D10)

**Outcome:** A new repo-root sibling package exists, generalized from SCCM's working modules (SCCM untouched), with `mssql` depending on it via a local path. Per-module smoke tests pass. Build this **before** Stage 0.2's sync and Stage 2.

> Provenance rule: each shared module carries a header comment naming the SCCM source file it was generalized from. Generalize = strip SCCM-specific names/phases/SMS logic; keep the transport/auth/infra. Do NOT modify `sccm/`.

### Task S.1: Package skeleton + deps

**Files:** Create `openhound-collector-common/pyproject.toml`, `openhound-collector-common/src/openhound_collector_common/__init__.py`, `openhound-collector-common/README.md`
- [ ] Hatchling package `openhound-collector-common`, Python `>=3.13,<=3.14`, dependencies per spec §3 (impacket/ldap3/dnspython/pyasn1/cryptography/pywin32/winkerberos).
- [ ] Add the path/workspace wiring so `mssql/mssql` can install it (`[tool.uv.sources]` path, editable).
- [ ] Verify: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-mssql-venv uv sync` from `mssql/mssql` resolves the path dep; `uv run python -c "import openhound_collector_common"`.

### Task S.2: Auth/transport clients

**Files:** Create `clients/mssql.py`, `clients/auth.py`, `clients/ad.py`, `clients/wmi.py` (generalized from SCCM `clients/{mssql_epa,http_auth,ad,wmi}.py`)
**Interfaces — Produces:** `clients.mssql.MssqlConnection.connect(target, auth) -> conn` + `conn.query(sql) -> list[dict]`; `clients.mssql.detect_epa(target, auth) -> dict`; `clients.ad.AdClient` (`enumerate_mssql_spns`, `resolve_sid`, `resolve_principal`); `clients.wmi.WmiClient` (`local_group_members`, `service_account`); `clients.auth` token minters (Kerberos/NTLM/SSPI).
- [ ] Generalize the TDS+EPA client (TLS-1.2 cap on every path — spec §3, §14) and the AD/WMI clients. Keep lockout-safety (result-49 subcodes only) and the SSPI Windows gate.
- [ ] Smoke tests in `openhound-collector-common/tests/` that import and construct each client (no live connection).
- [ ] Verify: `UV_PROJECT_ENVIRONMENT=/tmp/openhound-mssql-venv uv run pytest openhound-collector-common/tests -v`.

### Task S.3: DLT + pipeline + logging + graph infra

**Files:** Create `discovery/dns.py`, `phased_pipeline/{engine,work_queue,streams}.py`, `dlt/{source_bridge,convert_pipeline,duckdb_safe}.py`, `logging/log_context.py`, `graph/{stub_node,graph_edge}.py`, `proxy/socks.py`
- [ ] Generalize from SCCM `collectors/dns.py`, `phased_pipeline/*`, `source.py` helpers, `convert_pipeline.py`, `transforms.py` helpers, `log_context.py`, `models/{stub_node,graph_edge}.py`. Add a pure-Python SOCKS5 dialer (`proxy/socks.py`) porting Go `internal/proxydialer` (no SCCM source).
- [ ] Smoke tests: import each; `phased_pipeline` queue/stream round-trip; `duckdb_safe` helpers on a fixture; `proxy/socks` parse of `socks5://[user:pass@]host:port`.
- [ ] Verify: `uv run pytest openhound-collector-common/tests -v`.

---

## Stage 2 — MSSQL auth/EPA wiring (on the shared library)

**Outcome:** Can connect to `ps1-db.mayyhem.com` as each of the 3 users via the shared client and run a trivial query; EPA detection matches the Go binary. (Live; gated tests.)

### Task 2.1: MSSQL connection adapter

**Files:** Create `src/openhound_mssql/auth.py` (thin adapter building the shared `clients.mssql` `auth` object from the CLI flags / `SOURCES__MSSQL__*` env)
**Interfaces — Consumes:** `openhound_collector_common.clients.mssql.MssqlConnection`, `.detect_epa`. **Produces:** `build_auth(cfg) -> Auth`, `connect(target, cfg) -> conn`.

- [ ] Map CLI auth flags (spec §4/§9) → the shared client's `auth`. Connection waterfall + stop-on-auth-error live in the shared client; this layer only selects the mode and SPN.
- [ ] Logs per branch at appropriate levels.
- [ ] **Live verify (manual, this host):** a temporary script: `connect("ps1-db.mayyhem.com", cfg_for("MAYYHEM\\domainadmin","password")).query("SELECT @@VERSION")`. Expected: version string. Repeat for `roanalyst`/`lowpriv` (lowpriv may fail to connect — expected; must yield partial-from-SPN output later).

### Task 2.2: EPA detection wiring

**Files:** `src/openhound_mssql/auth.py` (expose `detect_epa(target, cfg)`)
- [ ] Wrap the shared `clients.mssql.detect_epa`; map result to the `forceEncryption`/`extendedProtection`/`strictEncryption` fields the server node needs. SSPI ambiguity → literal `"Allowed/Required"` (memory `feedback_epa_uncertainty_label`).
- [ ] **Live verify vs oracle:** run Go `./mssqlhound` EPA path and the Python `detect_epa` against `ps1-db`; assert same verdict. Cross-check with `sccm/sccm/debug_epa_matrix.py`.

---

## Stage 3 — Collection (per-target SQL in `.ps1` order → raw JSONL)

**Outcome:** `collect mssql -t ps1-db.mayyhem.com -u 'MAYYHEM\domainadmin' -p password` writes raw JSONL tables whose content matches the Go `ServerInfo` JSON (same principals/permissions/databases/linked-servers/credentials/proxies). Derivation NOT done yet.

### Task 3.1: Per-target SQL collection functions

**Files:** Create `src/openhound_mssql/collection/server.py` (and `queries.py` holding the exact T-SQL strings)
**Interfaces — Produces:** `collect_server(conn, ctx) -> Iterator[tuple[str, dict]]` yielding `(table_name, row)` in the exact order of spec §8 steps 5–23.

- [ ] Port each SQL query from the `.ps1` (cross-check columns vs Go `client.go` collection). Tables: `servers`, `server_principals`, `server_permissions`, `server_role_members`, `server_principal_credentials`, `databases`, `database_principals`, `database_permissions`, `database_role_members`, `database_scoped_credentials`, `credentials`, `proxy_accounts`, `service_accounts`, `linked_servers`, `local_group_members`. Version-aware columns; ORDER BY as in ps1.
- [ ] Preserve order; emit a `collection_settings` one-row table carrying CLI flags into preproc (SCCM pattern, memory: persist-at-collect / gate-in-preproc).
- [ ] Logs per query block.
- [ ] **Verify (live):** run; dump JSONL row counts per table; compare against `jq` over the Go binary's per-server JSON for the same server/user (counts of principals, databases, permissions, linked servers).

### Task 3.2: Target discovery + classification

**Files:** Create `src/openhound_mssql/collection/targets.py` (AD/LDAP/SID resolution + DNS discovery come from the shared lib `clients.ad` / `discovery.dns`)
**Interfaces — Consumes:** `openhound_collector_common.clients.ad.AdClient`, `openhound_collector_common.discovery.dns`. **Produces:** `resolve_targets(cfg) -> list[Target]` (explicit/list/file/SPN-enum/scan-all-computers), `classify_target(s)`, `extract_credentials(s)`.

- [ ] Reproduce Go `classifyTarget`/`extractAndApplyCredentials` semantics (verify against the cases in `cmd/mssqlhound/main_test.go`). LDAP SPN enum `(servicePrincipalName=MSSQLSvc/*)` and `scan-all-computers` `(objectClass=computer)` via the shared `AdClient`. DC auto-resolve (SRV `_ldap._tcp` → A) via shared `discovery.dns`. DNS-based IP dedupe unless `--skip-ip-dedupe`.
- [ ] AD auth ladder + lockout-safety + SSPI Windows gate are in the shared `AdClient`; this task only orchestrates target resolution.
- [ ] Test `tests/unit/test_targets.py` porting the `main_test.go` table cases (classify + extract credentials + port list parsing).
- [ ] Verify: `uv run pytest mssql/mssql/tests/unit/test_targets.py -v`; **live**: SPN enum finds `ps1-db`.

### Task 3.3: DLT source wiring (push→pull bridge) + `_run_collection`

**Files:** `source.py`; finish `main.py::_run_collection`
**Interfaces — Produces:** `mssql_source()` (DLT `@app.source`) with per-table emit resources draining a queue filled by the per-target worker pool (SCCM `source.py` pattern: `_drain_stream`, `parallelized=True`, `EXTRACT__WORKERS` bump, module-global state handoff). `--workers` controls the pool (0 = sequential).

- [ ] Worker pool over `resolve_targets`; per target: connect (Stage 2), `detect_epa`, `collect_server` (Stage 3.1) → push rows; partial-from-SPN path when connect fails but SPN exists. Linked-server recursion queue (Stage 7).
- [ ] **Verify (live, all 3 users):** `collect mssql -t ps1-db.mayyhem.com -u 'MAYYHEM\<user>' -p password <out>`; confirm JSONL tables under the bucket; spot-check row counts vs Go.

---

## Stage 4 — Preproc (DuckDB derived + lookup tables)

**Outcome:** `preproc` loads raw JSONL and builds the derived tables convert needs; lookup methods resolve principals/roles/SIDs.

### Task 4.1: transforms.py derived tables

**Files:** `transforms.py`
**Interfaces — Produces:** `transforms(con)` building: `principal_map` (server + per-db), `role_membership_closure` (nested), `effective_permissions` (BFS + fixed-role expansion → domainPrincipalsWith*), `linked_server_hierarchy`, `sid_resolution`. Use the SCCM `_safe`/`_ensure_columns`/`_arr` defenses against dlt column-dropping (memory `sccm-dlt-coalesce-gotchas`).

- [ ] Port `Get-NestedRoleMembership`/`Get-EffectivePermissions` + `$fixedServerRolePermissions`/`$fixedDatabaseRolePermissions` (ps1) / collector.go fixed-role logic into SQL/Python over DuckDB.
- [ ] Register via `@app.preproc(transformer=transforms)`; return the `{table: jsonl_subpath}` map.
- [ ] Test `tests/unit/test_transforms.py` over a small fixture DuckDB (nested role closure, fixed-role expansion).
- [ ] Verify: `uv run pytest mssql/mssql/tests/unit/test_transforms.py -v`; **live**: `preproc mssql <bucket>` builds `lookup.duckdb` without BinderException.

### Task 4.2: lookup.py

**Files:** `lookup.py`
**Interfaces — Produces:** `MSSQLLookup(LookupManager)` with `__init__(self, client, schema="mssql")` (schema MUST default) and cached methods: `principal(server_oid, principal_id)`, `db_principal(db_oid, principal_id)`, `role_members(...)`, `effective_high_priv(server_oid)`, `resolve_sid(sid)`, `linked_servers(server_oid)`, `table_rows(table)`.

- [ ] Implement memoized point/list lookups (framework gives no caching — build dicts in `__init__` or per-method memo).
- [ ] Verify (live): used in Stage 6.

---

## Stage 5 — Convert scaffold (node emission + framework bridge)

**Outcome:** `convert` emits all 10 node kinds with full properties; uses the SCCM convert-reads-DuckDB pattern.

### Task 5.1: convert pipeline bridge

**Files:** Create `src/openhound_mssql/convert_pipeline.py` (port from `sccm/sccm/src/openhound_sccm/convert_pipeline.py`); wire `@app.convert(lookup=MSSQLLookup)` in `main.py`.
**Interfaces — Produces:** convert callback that runs a self-run `dlt.pipeline` reading DuckDB via `ctx.lookup` and writing via `opengraph_file`, returning a no-op source + `{}` so `Converter.run` does nothing (framework brief §7).

- [ ] Verify (live): `convert mssql <bucket> <out>` runs and produces an OpenGraph file (possibly empty of nodes initially).

### Task 5.2: Node assets

**Files:** `models/server.py`, `models/login.py`, `models/server_role.py`, `models/database.py`, `models/db_user.py`, `models/db_role.py`, `models/app_role.py`, `models/ad.py`; `models/__init__.py`
**Interfaces — Produces:** one `BaseAsset` per node kind with `as_node` building the full property set (spec §5) and `@app.asset(node=NodeDef(...), …)` registration. Server node is the root/environment node; all others set `environmentid` to its id.

- [ ] Implement `as_node` for each, reading from DuckDB rows (via the convert pipeline's resources, or `self._lookup`). AD node name NetBIOS stripping. Conditional-property omission to match Go (only-present keys).
- [ ] Test `tests/unit/test_nodes.py`: feed representative rows → assert node id/kinds/properties match Go output for a known fixture.
- [ ] **Verify (live):** convert against the Stage-3 bucket; adapter (Stage 8) → count nodes per kind; compare to Go binary node counts for the same user.

---

## Stage 6 — Convert: edge derivation (the core port)

**Outcome:** All edges except the Stage-7 complex set are emitted with full property bags. This is the largest task — port `collector.go createEdges`/`createFixedRoleEdges` + `edges.go` generators faithfully.

> Decomposition: one task per edge family, each verified by the existing per-edge validator (`MSSQL_LIMIT_EDGE=<Edge> go test -tags integration -run TestIntegrationValidateZip`) against a convert run over a fixture or live bucket. Port logic from the named Go functions; do not invent rules.

### Task 6.1: Structural + membership + mapping edges
`MSSQL_Contains`, `MSSQL_MemberOf` (nested), `MSSQL_IsMappedTo`, `MSSQL_HasLogin`, `MSSQL_Owns` (+`ownerPrincipalID`).
- [ ] Port from collector.go emission (ps1 brief §4) + edges.go generators. Edge property bags (general/windowsAbuse/…); empties filtered.
- [ ] **Verify:** per-edge validator passes for each kind on a manufactured fixture; spot-check vs Go.

### Task 6.2: Server-level permission edges
`MSSQL_ControlServer`, `MSSQL_Control`/`ControlLogin`/`ControlServerRole`, `MSSQL_Alter`/`AlterServerRole`, `MSSQL_AlterAnyLogin`, `MSSQL_AlterAnyServerRole`, `MSSQL_ImpersonateAnyLogin`, `MSSQL_Impersonate`/`ImpersonateLogin`, `MSSQL_ExecuteAs` (server), `MSSQL_ChangePassword` (+CVE gate, Task 6.5), `MSSQL_Connect`/`ConnectAnyDatabase`, `MSSQL_AddMember` (server), `MSSQL_ChangeOwner`/`TakeOwnership` (server), `MSSQL_GrantAnyPermission` (securityadmin).
- [ ] Use `principalMap[TargetPrincipalID]` resolution (lookup) to pick the concrete target kind/edge — the Go logic keys on `TargetPrincipalID` (edge_test_helpers `targetPerm`).
- [ ] **Verify:** per-edge validators; the `securityadmin → GrantAnyPermission` and fixed-role implicit edges.

### Task 6.3: Database-level permission edges
`MSSQL_ControlDB`, `MSSQL_ControlDBRole`/`ControlDBUser`, `MSSQL_AlterDB`/`AlterDBRole`, `MSSQL_AlterAnyDBRole`/`AlterAnyAppRole`/`AlterAnyRole`, `MSSQL_ImpersonateDBUser`, `MSSQL_ExecuteAs` (db), `MSSQL_AddMember` (db), `MSSQL_ChangeOwner`/`DBTakeOwnership` (db), `MSSQL_Connect` (db), `MSSQL_GrantAnyDBPermission` (db_securityadmin).
- [ ] **Verify:** per-edge validators incl. cross-DB isolation negatives.

### Task 6.4: Fixed-role implicit edges
Port `createFixedRoleEdges`: sysadmin→ControlServer, db_owner→ControlDB, db_securityadmin→GrantAnyDBPermission/AlterAnyDBRole/AlterAnyAppRole, `##MS_DatabaseConnector##`→ConnectAnyDatabase, etc.
- [ ] **Verify:** ControlServer/ControlDB present via fixed roles; the negatives that members of those roles don't get the direct edge.

### Task 6.5: CVE-2025-49758 + ChangePassword gate
**Files:** `src/openhound_mssql/cve.py` (port `internal/collector/cve.go` version table)
- [ ] Port `TestParseSQLVersion`/`TestCVEVulnerability` cases as `tests/unit/test_cve.py`. Gate `MSSQL_ChangePassword` per spec §6.
- [ ] Verify: `uv run pytest mssql/mssql/tests/unit/test_cve.py -v`.

---

## Stage 7 — Complex edges: linked servers, credentials/proxies, service accounts, coercion

**Outcome:** The remaining edges + the 3 load-bearing exact counts.

### Task 7.1: Linked servers + recursion
`MSSQL_LinkedTo` (=10), `MSSQL_LinkedAsAdmin` (=8). Port the recursive linked-server discovery (ps1 step 20 / collector.go). `--collect-from-linked` enqueues discovered servers; `--skip-linked-servers` disables. Preserve unique `LocalLogin` per link so JSON-dedup doesn't collapse the count of 10.
- [ ] **Verify:** `MSSQL_LIMIT_EDGE=LinkedTo` validator (ExpectedCount 10) and `LinkedAsAdmin` (8) PASS.

### Task 7.2: Credentials + proxies
`MSSQL_HasMappedCred` (+credentialId), `MSSQL_HasDBScopedCred` (+credentialId), `MSSQL_HasProxyCred` (+credentialId,proxyId). SID resolution via `ad.resolve_principal`.
- [ ] **Verify:** per-edge validators.

### Task 7.3: Service accounts, host, coercion, sessions
`MSSQL_ServiceAccountFor` (=1), `MSSQL_HostFor`, `MSSQL_ExecuteOnHost`, `MSSQL_GetTGS`, `MSSQL_GetAdminTGS`, `MSSQL_ExecuteAsOwner`, `MSSQL_IsTrustedBy`, `MSSQL_CoerceAndRelayToMSSQL`, `HasSession`, native `MemberOf` (local groups). AD node creation gated by `--skip-ad-nodes`.
- [ ] **Verify:** `ServiceAccountFor` ExpectedCount 1; coverage now shows all 38 edge types Found on the manufactured environment.

---

## Stage 8 — Validation adapter + 3-user comparison harness

**Outcome:** The acceptance loop (D5–D7, D9) is automated and green for all 3 users.

### Task 8.1: OpenGraph → MSSQLHound zip adapter

**Files:** Create `src/openhound_mssql/output_adapter.py`; Test `tests/unit/test_output_adapter.py`
**Interfaces — Produces:** `to_mssqlhound_zip(opengraph_output_path, zip_path)` writing per-source JSON in the spec §7 envelope (MSSQL nodes/edges with `source_kind=MSSQL_Base`; AD objects with `metadata:{}`), dedup edges by full JSON.

- [ ] Reshape OpenHound's native convert entries → `{$schema, metadata, graph:{nodes,edges}}`; `start/end` → `{"value": <id>}`. **No property-key renaming (D11)** — names are already MSSQLHound's originals. OpenHound's base fields (`displayname`/`environmentid`/`last_seen`) may be left in place (harmless) or stripped for a closer match; default: leave them.
- [ ] Test: feed a tiny OpenGraph output, assert the zip's JSON parses with the Go `bloodhound.ReadFromFile` shape (node `{id,kinds,properties}`, edge `{start:{value},end:{value},kind,properties}`) and that MSSQLHound property names are present verbatim.
- [ ] Verify: `uv run pytest mssql/mssql/tests/unit/test_output_adapter.py -v`.

### Task 8.2: 3-user comparison harness

**Files:** Create `tests/integration/run_comparison.py`, `tests/integration/README.md`
**Interfaces — Produces:** a pure-Python orchestrator that (per D4) shells out to the oracle.

- [ ] **Setup once** as `MAYYHEM\domainadmin`: `go test -tags integration -run TestIntegrationSetup ./internal/collector/...` with `MSSQL_SERVER=ps1-db.mayyhem.com MSSQL_USER='MAYYHEM\domainadmin' MSSQL_PASSWORD=password MSSQL_DOMAIN=mayyhem.com MSSQL_DC=dc.mayyhem.com LDAP_USER='MAYYHEM\domainadmin' LDAP_PASSWORD=password` (creds also in `sccm/sccm/debug_epa_matrix.py`). Check 1433 reachable first.
- [ ] **Per user** {lowpriv, roanalyst, domainadmin}: run Python collect→preproc→convert as `MAYYHEM\<user>`; `to_mssqlhound_zip`; run `MSSQL_ZIP=<zip> go test -tags integration -run TestIntegrationValidateZip ./internal/collector/...` and capture pass/fail + coverage; run the Go binary as oracle for the same user, validate its zip, and **diff** total nodes / total edges / edge-type set.
- [ ] **Teardown:** `TestIntegrationTeardown`.
- [ ] Emit a per-user report (validators PASS? counts match Go?).
- [ ] **Verify (live):** `uv run python tests/integration/run_comparison.py --users lowpriv,roanalyst,domainadmin`. Expected: validators PASS for all 3; node/edge/edge-type counts match the Go binary per user. **If a discrepancy traces to a bug in the original** that blocks a passing test, fix it in all collectors and surface it (task brief).

---

## Stage 9 — Documentation + final verification

### Task 9.1: README
**Files:** `mssql/mssql/README.md`
- [ ] Write all CLAUDE.md-required sections (spec §13), copy-paste `mayyhem.com` examples, grouped CLI tables with status markers, per-kind node/edge reference tables documenting **all** properties. Code-truth: omit unimplemented nodes/edges, mark unimplemented CLI 🚧 (memory `readme-code-truth-scope`).

### Task 9.2: Final full validation
- [ ] `UV_PROJECT_ENVIRONMENT=/tmp/openhound-mssql-venv uv run pytest mssql/mssql/tests -v` (all unit tests PASS).
- [ ] `uv run ruff check mssql/mssql/src && uv run mypy mssql/mssql/src` (clean or justified).
- [ ] Re-run `tests/integration/run_comparison.py` for all 3 users — confirm green.
- [ ] Update tickets to done (`gtk`).

---

## Self-review checklist (run after drafting; see writing-plans skill)

- **Spec coverage:** every spec section maps to a stage/task (CLI→0.5; nodes→1.1/5.2; edges→6/7; IDs→1.2; auth→2; order→3.1; preproc→4; adapter→8.1; harness→8.2; README→9.1). ✔
- **Type consistency:** `server_oid`/`principal_oid`/`db_principal_oid` names consistent across 1.2, 5.2, 6; `MSSQLLookup` ctor `schema="mssql"` default (framework requirement). ✔
- **No placeholders:** derivation tasks reference exact Go functions + per-edge validators rather than restating 10k lines — intentional (the Go code is the spec); novel framework/auth/adapter code is concrete. Flag for the executor: read the named Go functions before porting each edge family.
