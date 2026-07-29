# Archived: ARCHITECTURE.md 15 — Direct BloodHound CE upload

Removed from `sccm/sccm/ARCHITECTURE.md` on 2026-07-29 with the feature itself, along with its
table-of-contents entry. Kept verbatim below.

One part of 15 did **not** go away and was rewritten in place rather than deleted: the
hand-registration of `convert sccm` on the framework's Typer group. That still exists, because
the command still carries its own options (`--lookup-file`, `--progress`) and the
`@app.convert()` decorator exposes no seam for them — so `app.converter` is still assigned in
`main.py`, and `openhound` is still a declared dependency for that reason.

---

## 15. Direct BloodHound CE upload, and hand-registering `convert sccm`

### The framework baseline

OpenHound's `convert` step writes OpenGraph JSON files to disk and stops there — getting them into
BloodHound is the operator's own job (drag them into the UI's **File Ingest**, or script it separately).
Each pipeline verb also gets exactly one flag-carrying entry point: the `@app.collect()`/`@app.convert()`
convenience decorators auto-register a **fixed** CLI signature (`input_path`, `output_path`, `lookup_file`,
`progress`, and nothing else) and, as a side effect, set the app's `collector`/`converter` in-process
callables that `run_end_to_end` ([§12](#12-one-command-end-to-end-a---run-all-flag-not-a-new-verb)) calls
directly. There is no seam on the decorator to add extra flags to the command it generates.

### Why it breaks for SCCM

The operator workflow this feature targets — one command from credentials to a queryable BloodHound
graph, and a second command to re-push an existing run without recollecting — needs BloodHound API
credentials and upload-mode switches on **both** `collect --run-all` and `convert`. `collect sccm` already
had room to grow: it was hand-registered directly on the framework's `collect` Typer group from the start
(so it could carry the CMBP-style flag surface — see
[§5](#5-an-active-directory-cli-surface-and-context-auto-detection)). `convert sccm`, however, had always
used the `@app.convert(lookup=SCCMLookup)` convenience decorator, which meant there was nowhere to attach
`-B`/`--upload-dir`/etc.

### The add-on

**(a) A shared uploader, `openhound_collector_common.bloodhound`.** A new, framework-agnostic subpackage —
no `openhound`/`dlt` import, so it is reusable by the MSSQL collector later (per the design's D2 decision:
wired into SCCM only for now):

- `auth.py` — `HMACAuth` (BloodHound CE's chained HMAC-SHA256 signing over method+URI / hour / body) and
  `BearerAuth` (a plain JWT header).
- `client.py` — `BloodHoundClient`, retrying HTTP 429/5xx with exponential backoff over the four BH CE
  endpoints: `PUT /api/v2/extensions` (schema) and the `POST /api/v2/file-upload/{start,{id},end}` job flow
  (results).
- `uploader.py` — `BloodHoundUploader` (push N schemas / push N files under one job, returning an
  `UploadSummary`), plus the credential plumbing: `parse_bloodhound_shorthand` (`<id>:<key>@<url>`),
  `resolve_credentials` (merges `-B` shorthand > discrete flags > `BLOODHOUND_*` env vars), `build_uploader`
  (picks HMAC vs. Bearer, or `None` if nothing was configured).
- `zip_bundle.py` — `bundle_graph_dir`, zips a convert output directory's `*.json` files (no `seed_data.json`
  — the schema `PUT` already registers every kind).
- `schema.py` — `disable_possible_edges`, a port of the Go tool's `SchemaJSONWithDisabledPossibleEdges`:
  flips named relationship kinds' `is_traversable` to `false` in a schema blob before it's uploaded.

**SCCM's own two files** sit on top of that shared package:

- [`bloodhound_schemas.py`](src/openhound_sccm/bloodhound_schemas.py) — `load_sccm_schemas(disable_possible)`
  reads and, if asked, mutates **both** `schema_SCCM.json` and `schema_MSSQL.json`. Both are loaded because
  this collector emits `MSSQL_*` kinds ([§11g](#11g-stage-5-mssql-node-merge-and-topology-inference))
  alongside its `SCCM_*` ones — pushing only the SCCM schema would leave the MSSQL nodes/edges without a
  registered kind to render under. `SCCM_POSSIBLE_EDGE_KINDS` / `MSSQL_POSSIBLE_EDGE_KINDS` name the
  coerce-and-relay ([§11h](#11h-stage-6-coerce-and-relay-possible-edges-and-the-synthetic-authenticated-users-node))
  kinds each schema mutation targets.
- [`bloodhound_upload.py`](src/openhound_sccm/bloodhound_upload.py) — `run_upload(...)` is the single
  dispatch point both CLI commands call, so the "which of schema/results to push, and from where" decision
  logic lives in exactly one place rather than being duplicated per command.

**CLI surface.** An identical **BloodHound Upload** help panel is added to both `collect sccm` and
`convert sccm` ([`main.py`](src/openhound_sccm/main.py)): `-B`/`--bloodhound`, `--bloodhound-url` /
`--token-id` / `--token-key` (+ matching `BLOODHOUND_*` env vars), `--upload-schema-only` /
`--upload-results-only` (mutually exclusive — `_resolve_upload_mode` raises `typer.BadParameter` if both are
set), `--skip-collection`, `--upload-dir`. A module-level `_dispatch_bloodhound_upload` helper (build the
uploader via `build_uploader`, load schemas via `load_sccm_schemas` if requested, call `run_upload`) is the
one call site both commands use — `collect_sccm` calls it from three places (the `--skip-collection`
short-circuit, after a `--run-all` chain finishes, and the "no `--run-all`, but `-B` was still given"
else-branch), `convert_sccm` from two (its own `--skip-collection` short-circuit, and after a normal
convert).

**(b) Hand-registering `convert sccm`.** Replaced the `@app.convert(lookup=SCCMLookup)` decorator with the
same manual-registration pattern `collect sccm` already used: the actual conversion logic stays a plain
function (`_sccm_convert_hook`, unchanged); a new `_run_convert(...)` replicates the ~10-line closure the
decorator used to generate on your behalf (open the lookup DB read-only, build a `Converter`, call the
hook, run it) and is assigned directly to `app.converter` — so `run_end_to_end`'s `--run-all` chain
([§12](#12-one-command-end-to-end-a---run-all-flag-not-a-new-verb)) keeps calling it exactly as before,
unaware anything changed; and the CLI command itself is hand-registered with the extra flags via
`_convert_typer.command(name="sccm")` on the framework's own `convert` Typer group (imported as
`_convert_typer` alongside `_collect_typer`). This is not a new pattern — it is the exact seam
`collect sccm` has used from the start — just the second place it was needed.

### Trade-offs

- `convert sccm`'s CLI signature and `_run_convert`'s body are now two related-but-separate things a future
  change to the framework's own convert-closure shape would require updating by hand — the decorator used
  to keep them in sync for free.
- The upload step runs with a bare `requests`-based HTTP transport that has no proxy wiring, and — in
  `collect --run-all` — it runs **after** the `socks_proxy_installed` context ([§13](#13-tunneling-all-collection-traffic-through-a-socks5-pivot))
  has already exited. So a `--proxy`-tunneled collection still uploads over the collector host's own local
  DNS/network path, not through the SOCKS5 pivot; an operator collecting through a pivot needs separate,
  direct (or VPN) reachability to the BloodHound instance for the upload step to succeed.
- `--skip-collection` means something different per command by design (skip collection entirely vs. skip
  just the conversion step) but shares one flag name and help panel across both, so it is only useful paired
  with `-B` and/or `--upload-dir` — on its own it is a no-op that does nothing and uploads nothing.

---

## Quick reference: which framework extension point each add-on uses

| Divergence | Framework extension point used | Where it would edit core (but doesn't) |
|---|---|---|
| Per-host phased pipeline | DLT "emit" resources draining the shared `StreamBridge`'s queues; `pipeline.run` + `extract_workers_for` | A native per-target scheduler |
| Recursive discovery | Custom `WorkQueue` + `register_target` funnel | A "collection discovers more work" primitive |
| Include-only targeting | Allow-list checked in `register_target` | A target-scoping config |
| AD CLI surface | Typer command registered on the framework's `collect` group + flag→env bridge | A richer `@app.collect()` signature |
| Windows auth (×5 protocols) | `clients/*` auth stacks — implementation in shared `openhound_collector_common.clients.*`, SCCM `clients/*` are thin adapters | Framework Negotiate/Kerberos/SMB/DCOM support |
| Logging & diagnostics | Filters + extra handlers + runtime mutation of live handlers — `log_context` machinery in shared `openhound_collector_common.logging`, SCCM re-exports + owns the file handlers | A pluggable logging/formatting API |
| Windows log-rollover fix | Runtime monkey-patch of core's handler instances | A Windows-safe `doRollover` in core |
| Convert from DuckDB | `preproc` coalesced tables + a second `convert`-time `dlt.pipeline` (Convert2-Read-DB) | `read_from="duckdb"` on `@app.convert` (proposed) |
| Tolerant coalesce vs. pinned load schema | `_safe` + `_ensure_columns` + `_arr` in the preproc transforms | Pinning full per-table schemas/types at load (rejected — brittle; it caused the `ldap_sites` freeze crash) |
| Persist-at-collect / gate-in-preproc (`disable_possible_edges`) | `collection_settings` one-row table written at collect; `_read_disable_possible` reads it in preproc | A first-class CLI flag shared across pipeline phases |
| Traversable allow-list + collection source | `TRAVERSABLE_EDGE_KINDS` frozenset in `kinds/edges.py`; `GraphEdge` sets `traversable` from it and `collection_source` from the `graph_edges` typed `VARCHAR[]` column; dedup pass array-unions `collection_source` per `(start_id, end_id, kind)` group | A graph-model-level traversability attribute; a typed array column on edges |
| Edge-endpoint stub-node backfill | `_node_backfill` + `StubNode` synthesise bare nodes for unresolved edge endpoints | An `Upsert-Node`-equivalent that creates nodes on demand |
| Split output (untagged AD payload) | A second `convert`-time emit pass through an extension `opengraph_file_untagged` destination (no `metadata`); preproc `_graph_edges_split` partitions edges | A `source_kind=None` / multi-source option on `@app.convert` |
| MSSQL node merge + topology inference | `_mssql_sql_servers` temp table + three-source `UNION`/`GROUP BY` coalesce in `_node_mssql_server`; Login/DatabaseUser inferred from SCCM sysadmin-computer topology in `_node_mssql_login` / `_node_mssql_database_user`; MSSQL nodes in `SCCM_NODE_SPECS`; edges auto-routed by the existing `_graph_edges_split` | No new framework extension point — extends the existing Convert2-Read-DB pipeline and output-split (§11f) |
| Coerce-and-relay possible edges + synthetic Authenticated Users node | Three relay edge builders in `_edge_coerce_relay_*`; `_node_authenticated_users` inserts lazily after relay builders; `SCCMRelayEdgeProperties` subclass for relay-only props; surgical `--disable-possible-edges` gate; `graph_edges` gains two `VARCHAR[]` coercion columns | No new framework extension point — extends §11b (persist-at-collect/gate-in-preproc), §11c (graph_edges + GraphEdge), and §11f (output-split routing) |
| One-command end-to-end ([§12](#12-one-command-end-to-end-a---run-all-flag-not-a-new-verb)) | A flag on the hand-registered `collect` Typer command + in-process calls to the app's registered `preproc`/`convert` hooks | A new top-level `run` verb in core (extensions load inside the root app's constructor and never get a reference to it, so they cannot mount a new verb) |
| SOCKS5 pivot ([§13](#13-tunneling-all-collection-traffic-through-a-socks5-pivot)) | Runtime mutation of the stdlib `socket` module (`socket.socket`/`create_connection`/`getaddrinfo`), installed only for the `collect` run | No extension point — there is no framework notion of tunneling traffic through a pivot at all, since a stock collector talks to one already-reachable REST endpoint |
| Integration testing + payload diff ([§14](#14-a-shared-integration-test-and-payload-diff-engine-invoked-off---run-all)) | Two flags on the hand-registered `collect` Typer command (`--run-integration-tests`, `--compare-to-zip`), both forcing `--run-all` and calling the shared engine in-process after convert | No extension point — there is no framework notion of asserting or diffing a collected graph at all |
| Direct BloodHound CE upload ([§15](#15-direct-bloodhound-ce-upload-and-hand-registering-convert-sccm)) | A new framework-agnostic `bloodhound` subpackage in `openhound-collector-common` (HTTP client + auth + zip bundler + schema mutation), invoked from an identical BloodHound Upload panel on both hand-registered CLI commands | A built-in "push to BloodHound" step on core's `Converter`/`Collector` |
| `convert sccm` hand-registration ([§15](#15-direct-bloodhound-ce-upload-and-hand-registering-convert-sccm)) | Manual `app.converter` assignment + `_convert_typer.command`, the same seam `collect sccm` already used | A flag-carrying seam on the `@app.convert()` decorator |

---

## Maintaining this document

**This file must stay true to the code, like the README.** When you change any of the subsystems above —
the phased pipeline, the auth stacks, the logging layer, the discovery/allow-list funnel, the Windows
fixes, or the preproc/convert design — **update the relevant section here in the same change**, and fix any
code references (`file:line`) you invalidate.

If you add a *new* category of divergence from a stock OpenHound collector (a new protocol, a new
framework workaround, a new platform fix), add a section for it following the same
*baseline → why it breaks → the add-on → trade-offs* spine.

This document is required reading per [`AGENTS.md`](AGENTS.md) and the project
[`CLAUDE.md`](../../CLAUDE.md): read it before working on any cross-cutting collector subsystem, and update
it as part of that work.

---
