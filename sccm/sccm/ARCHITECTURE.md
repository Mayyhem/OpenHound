# Architecture: How the SCCM Collector Diverges from a Stock OpenHound Collector

This document explains **how and why the SCCM collector's architecture had to depart from the shape
of a "normal" OpenHound collector** — the kind of collector OpenHound was designed for, which talks to
**one cloud service over one authenticated REST API** (Okta, GitHub, Jamf, …).

It is written for two readers:

- An **OpenHound framework maintainer** asking *"what does an on-prem collector need that the framework
  doesn't provide out of the box?"*
- A **contributor to this collector** asking *"why is the code shaped so differently from the
  reference collectors, and where does each unusual piece live?"*

Every section follows the same spine:

1. **The framework baseline** — what a stock REST collector assumes, and what OpenHound gives you for free.
2. **Why it breaks for SCCM** — the on-prem reality that violates that assumption.
3. **The add-on** — what this extension built on top, with code references.
4. **Trade-offs** — what the add-on costs.

> ### The one ground rule that shapes everything
>
> **We cannot modify OpenHound core.** Every divergence below is therefore an *add-on layered on the
> framework's public extension points* — a new Typer command, a DLT resource, a logging filter, a
> preproc transformer — or, where no extension point exists, a **runtime adjustment of live framework
> objects** (e.g. swapping a formatter on an already-attached log handler). Nothing here edits a file
> under `openhound/`. That constraint is *why* several of these solutions look indirect: when you can't
> change the framework, you wrap it, feed it, or mutate its instances at runtime.

> ### A second home, added later
>
> Several of the divergences below (the Windows auth stacks, the per-target logging layer, the
> push→pull streaming bridge, the DNS resolver) were originally built *inside this extension* and have
> since been **promoted into a shared library, `openhound-collector-common`, that both this collector
> and the MSSQL collector consume.** That library is still not `openhound/` core — the ground rule
> holds — but it means the *implementation* of those subsystems now lives one directory over, with
> SCCM's own files reduced to thin adapters. Read
> [Where this code lives](#where-this-code-lives-the-shared-collector-common-library) next; it explains
> what moved and why, and the sections that follow point back to it.

---

## Table of Contents

- [The big picture: one tenant vs. many hosts](#the-big-picture-one-tenant-vs-many-hosts)
- [Where this code lives: the shared collector-common library](#where-this-code-lives-the-shared-collector-common-library)
- [1. Pull-based DLT resources → a push-based per-host phased pipeline](#1-pull-based-dlt-resources--a-push-based-per-host-phased-pipeline)
- [2. Sequential phases per target, concurrent across targets — and a sequential debug harness](#2-sequential-phases-per-target-concurrent-across-targets--and-a-sequential-debug-harness)
- [3. Recursive target discovery and collection](#3-recursive-target-discovery-and-collection)
- [4. Targeted collection: an include-only allow-list](#4-targeted-collection-an-include-only-allow-list)
- [5. An Active Directory CLI surface and context auto-detection](#5-an-active-directory-cli-surface-and-context-auto-detection)
- [6. Windows authentication across five protocols](#6-windows-authentication-across-five-protocols)
- [7. Enhanced logging and diagnostics for blind remote environments](#7-enhanced-logging-and-diagnostics-for-blind-remote-environments)
- [8. Windows-isms: the platform fights back](#8-windows-isms-the-platform-fights-back)
- [9. Convert can't iterate DuckDB rows: the unified Computer-node problem](#9-convert-cant-iterate-duckdb-rows-the-unified-computer-node-problem)
- [10. dlt loads whatever the data contains; our SQL expects fixed columns](#10-dlt-loads-whatever-the-data-contains-our-sql-expects-fixed-columns)
- [11. Stage 2 preproc/convert add-ons](#11-stage-2-preprocconvert-add-ons)
  - [11a. Collect-side additions](#11a-collect-side-additions)
  - [11b. Persist-at-collect / gate-in-preproc for "possible" nodes](#11b-persist-at-collect--gate-in-preproc-for-possible-nodes)
  - [11c. Traversable allow-list and the generic GraphEdge model](#11c-traversable-allow-list-and-the-generic-graphedge-model)
  - [11d. Stage 4: client-device dedup and host-correlation edges](#11d-stage-4-client-device-dedup-and-host-correlation-edges)
  - [11e. Edge-endpoint stub-node backfill (new divergence category)](#11e-edge-endpoint-stub-node-backfill-new-divergence-category)
  - [11f. Split output: an untagged AD payload beside the SCCM source](#11f-split-output-an-untagged-ad-payload-beside-the-sccm-source)
  - [11g. Stage 5: MSSQL node merge and topology inference](#11g-stage-5-mssql-node-merge-and-topology-inference)
  - [11h. Stage 6: coerce-and-relay possible edges and the synthetic Authenticated Users node](#11h-stage-6-coerce-and-relay-possible-edges-and-the-synthetic-authenticated-users-node)
  - [11i. HTTP version fingerprint from ccmsetup.exe — a new HTTP-phase capability](#11i-http-version-fingerprint-from-ccmsetupexe--a-new-http-phase-capability)
  - [11j. AD-object attribute capture via the per-host resolution cache](#11j-ad-object-attribute-capture-via-the-per-host-resolution-cache)
- [12. One-command end-to-end: a `--run-all` flag, not a new verb](#12-one-command-end-to-end-a---run-all-flag-not-a-new-verb)
- [13. Tunneling all collection traffic through a SOCKS5 pivot](#13-tunneling-all-collection-traffic-through-a-socks5-pivot)
- [14. A shared integration-test and payload-diff engine, invoked off `--run-all`](#14-a-shared-integration-test-and-payload-diff-engine-invoked-off---run-all)
- [15. Direct BloodHound CE upload, and hand-registering `convert sccm`](#15-direct-bloodhound-ce-upload-and-hand-registering-convert-sccm)
- [Quick reference: which framework extension point each add-on uses](#quick-reference-which-framework-extension-point-each-add-on-uses)
- [Maintaining this document](#maintaining-this-document)
- [Changelog](#changelog)

---

## The big picture: one tenant vs. many hosts

A stock OpenHound collector models a **single environment reached through a single API endpoint**. The
framework's three-phase pipeline (`collect → preproc → convert`) is built around that:

| Phase | What the framework assumes |
|---|---|
| `collect` | Each **resource** is a Python generator that the DLT engine *pulls* from — it calls the API, paginates, and yields rows. One resource ≈ one API endpoint ≈ one table of JSONL on disk. |
| `preproc` | Optionally load the JSONL into DuckDB and build derived/lookup tables for cross-referencing. |
| `convert` | Read the JSONL back, and for each row emit one OpenGraph node or edge. One row ≈ one graph entity. |

Authentication is a single bearer/OAuth token attached to every request. Discovery is trivial — there is
one tenant, and you already have its URL. There is no notion of "the data I collect tells me about *more
things to collect*," no notion of "collect host A but not host B," and no need to run different *kinds* of
collection in a fixed order against the *same* target.

**SCCM violates every one of those assumptions:**

- It collects from **many on-prem Windows hosts**, not one API. The set of hosts isn't known up front —
  it's **discovered** from LDAP, DNS, and the responses of hosts already probed.
- Each host is collected by running an **ordered sequence of protocol phases** (registry → SQL →
  AdminService → WMI → HTTP → SMB), where a later phase is *skipped* depending on what an earlier phase
  achieved.
- It speaks **five wire protocols** (LDAP, SMB, WMI/DCOM, HTTP, TDS/MSSQL), each with **Windows
  authentication** (Kerberos, NTLM, current-user SSPI, pass-the-hash, pass-the-ticket) — not a bearer token.
- A single graph entity (a **Computer**) is assembled from **many** collected tables, not one row.

The rest of this document is the catalogue of what had to be built to bridge that gap. The reference
predecessor is the PowerShell tool **ConfigManBearPig** (`README-CMBP.md`); many add-ons exist to
reproduce a behavior the single-process PowerShell script got "for free" by sharing in-memory state.

---

## Where this code lives: the shared collector-common library

### The framework baseline

A stock OpenHound collector is **one self-contained Python package**. The framework gives you extension
points to build against, but it has no notion of *code shared between two collectors* — each REST
collector is small and stands alone, so there is nothing to share and nowhere to put it.

### Why it breaks for SCCM (and MSSQL)

On-prem collectors are not small, and they are not alone. This extension and the sibling **MSSQL
collector** both have to do the same hard, **security-critical** things: authenticate over Windows
protocols with the full credential toolkit (Kerberos / NTLM / SSPI / pass-the-hash / pass-the-ticket),
bridge a *pushing* worker pool to DLT's *pulling* extractor, tag every log line with which target and
phase produced it, and resolve a domain controller over DNS. Built independently, each collector would
carry its **own copy** of an NTLM/SPNEGO token minter, an EPA channel-binding probe, a bounded-queue
stream bridge, and a `contextvars` logging layer. Two copies of code this subtle **drift** — a
lockout-safety fix or a channel-binding correction lands in one and rots in the other.

### The add-on: a shared library, with the mature implementation promoted *up* into it

The shared code lives in **`openhound-collector-common`** — a separate package pulled in as an editable
path dependency (`[tool.uv.sources]` in [`pyproject.toml`](pyproject.toml)), so both collectors import
the *same* module objects, not copies. It is **not** part of `openhound/` core; the ground rule holds.

The direction of travel matters. These subsystems were **proven first in the SCCM collector**, then
**promoted up** into the shared library as a superset (SCCM's battle-tested behavior plus the
generalizations MSSQL needed), and both collectors were re-pointed at the shared implementation. Nothing
was cautiously re-written for the lowest common denominator — the richer, live-validated SCCM version
became the shared one. What moved:

| Subsystem (section) | Shared home (`openhound_collector_common.*`) | What SCCM keeps locally (the adapter) |
|---|---|---|
| Windows auth ladders + token minters ([§6](#6-windows-authentication-across-five-protocols)) | `clients/auth` (`choose_auth`, `is_ip`, `KerberosToken`, `SspiClient`, NTLM type-1/3), `clients/ad` (`AdClient` + lockout-safe bind waterfall), `clients/wmi` (impacket + pywin32 backends), `clients/mssql` (`detect_epa`) | `clients/ad.py` `ADClient(AdClient)` subclass + SCCM attribute maps; `clients/wmi.py` `WmiClient` wrapper; `clients/http_auth.py` negotiators wrapping `KerberosToken`/`SspiClient`; `clients/mssql_epa.py` thin `test_epa` adapter over `detect_epa` |
| Per-target/-phase/-resource logging ([§7](#7-enhanced-logging-and-diagnostics-for-blind-remote-environments)) | `logging/log_context` (the full superset: `[target][phase]` tagging, `with_log_context`, completion-callback registry, `VERBOSE`, the debug exc-info filter, `cached_with_log`, `trace_node/edge/...`) | `log_context.py` re-exports the shared machinery and binds the two collector-specific helpers (`cached_with_log`, `trace_*`) to SCCM's own logger names |
| Push→pull streaming bridge ([§1](#1-pull-based-dlt-resources--a-push-based-per-host-phased-pipeline)) | `dlt/source_bridge` (`StreamBridge`, `DONE`, `build_streams`, `broadcast_done`, `extract_workers_for`) | `phased_pipeline/streams.py` re-exports `DONE`/`build_streams`/`broadcast_done`; `source.py` plants a `StreamBridge` and its emit resources delegate their drain to it |
| DNS resolution ([§5](#5-an-active-directory-cli-surface-and-context-auto-detection)) | `discovery/dns` (`make_resolver`) | `main.py::_resolve_dc_via_dns` calls the shared `make_resolver`, keeps the SCCM-specific SRV query |
| End-to-end phase chaining ([§12](#12-one-command-end-to-end-a---run-all-flag-not-a-new-verb)) | `orchestration/run` (`run_end_to_end`, `derive_stage_paths`, `StagePaths`) | `main.py::_run_e2e_after_collect` maps `--progress` and delegates; the `--run-all` flag on `collect_sccm` triggers it |
| SOCKS5 pivot ([§13](#13-tunneling-all-collection-traffic-through-a-socks5-pivot)) | `proxy/patch.py` (process-wide `socket` interception), `proxy/socks.py` (dialer/handshake), `discovery/dns.py` (`force_tcp`) | `main.py` parse/validate (`_parse_proxy_or_exit`, `_require_dc_or_dns_for_proxy`) + the install-around-run wrap (`socks_proxy_installed`); the four proxy-aware DNS sites (`_resolve_dc_via_dns`, two sites in `collectors/dns.py`, `context.resolve_ip`) |
| Integration testing / payload diff ([§14](#14-a-shared-integration-test-and-payload-diff-engine-invoked-off---run-all)) | `integration_testing` (`graph.load_graph`, `matcher`, `cases.EdgeCase`/`NodeCase`, `runner.run_suite`, `compare.compare_graphs`, `coverage.report`) | `openhound_sccm/integration/` — mayyhem.com `fixtures/edges.py`+`fixtures/nodes.py` (61 `EdgeCase`, `NodeCase`s, two whole-graph invariants) and the `__init__.py` wiring (`run_integration_tests`, `compare_to_zip`) called from the two `collect sccm` **Testing** flags |

**Governance.** From an extension agent's point of view the shared library is **read-only** — an SCCM
change may not edit `openhound-collector-common`, exactly as it may not edit `openhound/` core. Promoting
new code up into the shared library is a deliberate, owner-approved act (it affects *both* collectors, so
both must be re-validated), not something done casually mid-feature.

**One relaxed invariant.** The phased engine ([§1](#1-pull-based-dlt-resources--a-push-based-per-host-phased-pipeline))
used to be provably self-contained: a test forbade *any* import of `dlt` / `ldap3` / `openhound` /
`openhound_sccm` in `phased_pipeline/*.py`. Adopting the shared stream primitives means the engine now
imports `openhound_collector_common.dlt.source_bridge` — so that test was relaxed to permit **exactly
that one** shared dependency, and nothing else ([`tests/test_pp_engine.py`](tests/test_pp_engine.py)).
The shared bridge is pure-queue standard-library code, so the engine stays free of the dlt library and
the framework.

### Trade-offs

- **A shared-library change is a two-collector change.** A fix in `clients/auth` or `logging/log_context`
  now lands in SCCM *and* MSSQL at once — good for consistency, but every such change must be validated
  against both, not just the collector that motivated it.
- **A third place to look.** Tracing an auth failure or a log-format quirk may lead out of `sccm/sccm/`
  into `openhound-collector-common/`. The adapter files above are deliberately thin so the jump is
  obvious, and each names its shared counterpart in its module docstring.
- **The behavior did not change — only its home.** The detailed descriptions in [§1](#1-pull-based-dlt-resources--a-push-based-per-host-phased-pipeline),
  [§6](#6-windows-authentication-across-five-protocols), and [§7](#7-enhanced-logging-and-diagnostics-for-blind-remote-environments)
  remain accurate about *what the code does*; they now describe code that lives in the shared library,
  reached through SCCM's adapters. Where a `file:line` reference in those sections points at a SCCM file
  that is now a re-export shim, the real implementation is the correspondingly-named module in
  `openhound_collector_common`.

---

## 1. Pull-based DLT resources → a push-based per-host phased pipeline

### The framework baseline

In a stock collector, `@app.resource` decorates a generator and DLT *owns the loop*: it calls your
generator, pulls rows, and writes them to disk. You never schedule anything — you just yield. DLT
interleaves several resource generators round-robin and runs them in a small worker pool it controls.

### Why it breaks for SCCM

SCCM collection isn't "iterate one API." It's "for each of N hosts, run an ordered list of phases, in a
worker pool, where the host list grows while you work." DLT's pull-the-generator model has no place to
express *per-host ordering*, *per-host fan-out across a thread pool*, or *a phase that decides at runtime
whether to run*. If we wrote each phase as a normal DLT resource, DLT would interleave them globally and
we'd lose the per-target ordering SCCM depends on.

### The add-on: a service-agnostic phased engine, bridged to DLT by streams

The extension ships its own miniature collection engine under
[`phased_pipeline/`](src/openhound_sccm/phased_pipeline/) — standard-library only, no DLT, no SCCM
knowledge, so it's independently testable:

| Piece | File | Role |
|---|---|---|
| `WorkQueue` | [`phased_pipeline/work_queue.py`](src/openhound_sccm/phased_pipeline/work_queue.py) | The to-do list of targets. Dedups, counts in-flight work, signals *quiescence* (see [§3](#3-recursive-target-discovery-and-collection)). |
| `Phase` + `run_one_target` + `run_pipeline` | [`phased_pipeline/engine.py`](src/openhound_sccm/phased_pipeline/engine.py) | A `Phase` is `(name, output-stream-names, generator)`. `run_one_target` runs one host through its phases **in declaration order** ([engine.py:70-81](src/openhound_sccm/phased_pipeline/engine.py#L70-L81)); `run_pipeline` drives a `ThreadPoolExecutor` over the queue ([engine.py:84-136](src/openhound_sccm/phased_pipeline/engine.py#L84-L136)). |
| `build_streams` / `DONE` / `broadcast_done` | [`phased_pipeline/streams.py`](src/openhound_sccm/phased_pipeline/streams.py) — a **re-export** of the shared `openhound_collector_common.dlt.source_bridge` primitives (see [Where this code lives](#where-this-code-lives-the-shared-collector-common-library)) | One **bounded** `queue.Queue` per output table. Bounded means a fast producer *blocks* until the consumer catches up — **backpressure** that keeps memory flat. `DONE` is the single end-of-stream sentinel. Re-exporting (not copying) means the engine broadcasts the *same* `DONE` object the shared bridge compares against — the marker is identity-compared, so producer and consumer must agree on one instance. |

The hard part is making DLT — which insists on *pulling* — consume rows that are *pushed* by a separate
thread pool. The bridge itself is the shared **`StreamBridge`** (`openhound_collector_common.dlt.source_bridge`):
it owns the bounded per-table queues, the blocking drain, and the `DONE` handling. SCCM keeps only the
glue that `StreamBridge` can't provide, in [`source.py`](src/openhound_sccm/source.py):

- For every per-host output table, the extension registers a one-line DLT **"emit resource"** whose entire
  body delegates to the planted bridge's drain — [`_drain_stream` / `_make_emit_resource`](src/openhound_sccm/source.py).
  The bridge's `drain_stream` does a blocking `get()`: "an empty queue is a *wait*, not an end." This turns
  each DLT resource into a **consumer** of the engine's output instead of a producer. SCCM must keep this
  registration glue local (rather than use `StreamBridge.build_emit_resources` directly) because a
  conformance guard checks `app.dlt_resources` at **import** time — earlier than any run-scoped bridge can
  exist — so the emit resources are registered up front with the queue **late-bound** through a planted
  bridge.
- The two halves run concurrently in [`_run_per_host_stage`](src/openhound_sccm/main.py): the **engine runs
  on a background thread** (producing rows onto `bridge.streams`, then closing them with `DONE` at
  quiescence) while **`pipeline.run(...)` drains those queues on the main thread**.
- Each emit resource is declared `parallelized=True` so DLT gives each its own extract thread. A
  single-threaded round-robin extractor would block on the first momentarily-empty queue while another
  filled to capacity — a deadlock. To guarantee a worker per table, `_run_per_host_stage` wraps the run in
  the shared **`extract_workers_for(len(tables))`** context manager, which raises the framework's
  `EXTRACT__WORKERS` env var to `len(tables) + 2` for the duration and restores it afterward. (Both this
  worker bump and the bridge were **generalized from this exact SCCM code**; see
  [Where this code lives](#where-this-code-lives-the-shared-collector-common-library).)

A second framework-shaped problem: DLT builds the source via **config injection** (every `source()`
parameter is a `dlt.config.value` / `dlt.secrets.value`, see [source.py:198-231](src/openhound_sccm/source.py#L198-L231)),
so there is **no constructor** through which to hand the source live Python objects (the shared work
queue, the AD-resolution cache, the stream registry). The extension threads them through **module-level
globals** planted just before each `pipeline.run` and cleared after —
[`set_shared_queue` / `set_bridge` / `get_last_ctx`](src/openhound_sccm/source.py) (`set_bridge` plants the
run-scoped `StreamBridge` the emit resources drain). It's a handshake, not elegance, but it's the only
channel the injection model leaves open.

Finally, collection is explicitly **two-staged** in [`collect_sccm`](src/openhound_sccm/main.py#L842-L1009):

```
Stage 1 — Discovery (DLT-scheduled, runs once)
  ldap_* / dns_* / local_*  resources  →  register_target()  →  seeds the WorkQueue
                                   │
Stage 2 — Per-host (engine thread pool + emit-resource drain)
  drain WorkQueue → run_one_target(host) per worker → stream rows → emit resources write JSONL
```

Stage 1 is selected with `src.with_resources(*DISCOVERY_RESOURCE_NAMES)`
([main.py:957-959](src/openhound_sccm/main.py#L957-L959)); Stage 2 is the engine + emit pass.

### Trade-offs

- `_run_per_host_stage` installs **process-global** state (the planted `StreamBridge`, the bumped
  `EXTRACT__WORKERS`), so it assumes **one collect run per process** — true for the CLI, documented as
  "not reentrant" in the function docstring.
- The `finally` block must empty the queues (`bridge.drain_to_unblock()`) while joining the engine thread
  so a crashed `pipeline.run` can't leave a worker blocked forever on a full queue.
- We pay the cost of running two cooperating schedulers (our engine + DLT's extractor) instead of one.

---

## 2. Sequential phases per target, concurrent across targets — and a sequential debug harness

### The framework baseline

A stock collector has no concept of "phases that must run in a fixed order against the same target."
Resources are independent; DLT may run them in any interleaving. There is also no built-in way to run a
*single unit of collection* deterministically for debugging — you'd run the whole `collect` command.

### Why it breaks for SCCM

Order matters. ConfigManBearPig probes a host RemoteRegistry-first, then MSSQL, then the privileged
AdminService API, then WMI **only if** AdminService failed, then unauthenticated HTTP/SMB **only if**
nothing privileged succeeded. That ordering and the "fall back only if the better method didn't work"
logic is core to both correctness and operational stealth. And because these phases make real network
calls to real customer infrastructure, a developer needs to step through **one host, one phase, on one
thread** without the noise of a 10-way thread pool.

### The add-on: ordered phases + a runtime `should_run` gate + a standalone harness

- **Ordering** is just the declaration order of [`PER_HOST_PHASES`](src/openhound_sccm/per_host_phases.py#L19-L89);
  `run_one_target` honors it strictly ([engine.py:70-81](src/openhound_sccm/phased_pipeline/engine.py#L70-L81)).
- **Concurrency vs. sequence** are separated cleanly: the *engine* runs many targets at once
  (`max_workers = --threads`, default 10) but each target's phases run *in order* on a single worker.
- **The fallback logic** lives in [`should_run_phase`](src/openhound_sccm/per_host_phases.py#L96-L121),
  the engine's `should_run` hook. It does two things: enforce `--collection-methods` gating
  (`ctx.method_enabled(phase.name)`) and skip the fallback phases. WMI is skipped on a host whose
  `TargetEntry.completed_phases` already contains `"AdminService"`; HTTP and SMB are skipped once
  `{"AdminService", "WMI"}` collected the host. This keeps each collector a plain "collect everything"
  function — the *decision* to run lives in one pipeline-native place, mirroring CMBP's
  `$CollectionTargets[$target]['Collected']` skip checks.

- **The sequential debug harness** is [`debug_per_host.py`](debug_per_host.py) (one of three lab
  harnesses, alongside `debug_epa_matrix.py` and `spike_smb_sso.py`). It seeds the work queue by hand and
  drives `run_pipeline` directly — **no DLT** — so the whole per-host engine can be single-stepped under a
  debugger. Its knobs map 1:1 to CLI flags:
  - `MAX_WORKERS = 1` ([debug_per_host.py:74](debug_per_host.py#L74)) forces a single worker thread so the
    debugger never jumps between targets — the deterministic-sequential mode. `= 10` reproduces real
    concurrency.
  - `COMPUTERS` mirrors `--computers` (seed + allow-list); `COLLECTION_METHODS` mirrors
    `-m/--collection-methods`; `MAXSIZE` (the bounded-stream depth, default 1000) set to `1` lets you
    watch backpressure block a producer.

  The same determinism is reachable from the real CLI with `--threads 1 -c <one-host> -m <one-method>` —
  the engine's `run_one_target` is a public, standalone entry point precisely so a single target can be
  run in isolation.

### Trade-offs

A phase that raises is **logged and skipped**, and the remaining phases still run
([engine.py:77-81](src/openhound_sccm/phased_pipeline/engine.py#L77-L81)) — one flaky host or protocol
never aborts the collection, but it does mean failures are surfaced through logs (see [§7](#7-enhanced-logging-and-diagnostics-for-blind-remote-environments))
rather than by crashing.

---

## 3. Recursive target discovery and collection

### The framework baseline

A REST collector's "targets" are fixed: the tenant's endpoints. Collection never *grows* the work it has
to do. There is no framework primitive for "the data I just collected revealed another host I must now go
collect."

### Why it breaks for SCCM

SCCM topology is self-describing and only partially visible from any one vantage point. A management point
queried over HTTP returns an `MPLIST` naming **sibling** management points; LDAP and DNS each reveal a
different slice of the site systems. ConfigManBearPig handles this by appending to a live target list that
every subsequent phase re-reads (`Add-DeviceToTargets`). New hosts found mid-run must themselves be
collected — **recursion**.

### The add-on: a quiescence-aware work queue with a strict ordering contract

[`WorkQueue`](src/openhound_sccm/phased_pipeline/work_queue.py) is the recursion engine. Producers (any
phase, via the context) call `submit(host)`; the dispatcher calls `next()`/`complete()`. The subtle part
is knowing **when collection is actually finished** when new work can appear at any moment. The queue
tracks *in-flight* work (handed out but not completed) and declares **quiescence** — `next()` returns
`None` — only when *nothing is pending and nothing is in flight*
([work_queue.py:55-68](src/openhound_sccm/phased_pipeline/work_queue.py#L55-L68)).

The race-free guarantee rests on an **ordering contract** spelled out in the module docstring
([work_queue.py:15-21](src/openhound_sccm/phased_pipeline/work_queue.py#L15-L21)) and enforced in the
engine's worker: a worker that discovers a new target must `submit` it *before* the discovering target's
slot is released. `run_pipeline`'s worker calls `on_target_complete` (and any submits) **while the target
is still counted in flight**, then calls `complete` last ([engine.py:110-123](src/openhound_sccm/phased_pipeline/engine.py#L110-L123)).
Because of that ordering, the dispatcher can never observe "empty and idle" while a discovery is mid-flight,
so it can't stop early.

Two more pieces wire discovery into this loop:

- [`SourceContext.register_target`](src/openhound_sccm/context.py#L260-L358) is the single funnel every
  discovery path calls. It resolves the identifier against AD (best-effort), applies the allow-list (see
  [§4](#4-targeted-collection-an-include-only-allow-list)), dedups by SID then hostname (with an FQDN
  upgrade path), merges sources/site-codes onto an existing `TargetEntry`, and — for a genuinely new host —
  calls `work_queue.submit(...)` ([context.py:355-356](src/openhound_sccm/context.py#L355-L356)). Both
  Stage-1 discovery resources (which call it from inside `collectors/*`) and the CLI's `--computers`
  seeds ([main.py:963-965](src/openhound_sccm/main.py#L963-L965)) go through this *same* funnel, so dedup
  and filtering are identical.
- [`target_hosts_snapshot`](src/openhound_sccm/context.py#L361-L369) lets phases read the *current* target
  set at iteration time, so a host discovered after a phase started is still picked up — the OpenHound
  equivalent of CMBP's "iterate the updated list."

One discovery path recurses on its own, one level below `register_target`:
[`_expand_group_targets`](src/openhound_sccm/collectors/ldap.py#L618-L661) (ope-e191). When
`ldap_system_management_dacl` finds a **group** holding GenericAll on the System Management container,
the group's members effectively inherit that Full Control too — so a group holder used to be only logged,
silently missing every computer that controlled the container through membership. The helper fetches the
group's `member` attribute with a direct BASE-scope search on its DN, resolves each member, registers
computer members as targets (source `LDAP-GenericAllSystemManagement`, same as a direct-computer holder),
logs user members (modeled, not scanned), and recurses into nested groups — a `visited` set keyed on
group DN stops circular nesting (`G1 → G2 → G1`) from recursing forever. Huge group memberships are paged
transparently by the shared client's `ldap3` `Connection`, which is opened with `auto_range=True`: ldap3
itself fetches every `member;range=N-M` chunk and merges them under the plain `member` key before this
code ever sees the entry, so a normal huge group already arrives with its complete membership. The
collector does not follow ranges itself — it only checks for a **residual** `member;range=` key, which
can appear solely when auto_range failed to complete, and logs a **warning** in that case rather than
silently under-collecting.

### Trade-offs

The whole queue is guarded by one `threading.Condition`, which is simple and correct but serializes
submit/next/complete. At SCCM target counts that's a non-issue. The dedup set is process-lifetime, so a
host is collected at most once per run even if discovered by three different paths.

---

## 4. Targeted collection: an include-only allow-list

### The framework baseline

A REST collector collects *the whole tenant*. "Collect only part of it" isn't a first-class idea, and
certainly not "discover the topology but only actually touch these specific hosts."

### Why it breaks for SCCM

Operators routinely need to (a) probe a single named host they already care about, or (b) let discovery
map the environment but **only authenticate against an approved subset** — for scoping, for stealth, or
because they only have rights against certain machines. Discovery and the *decision to touch a host* must
be decoupled.

### The add-on: an allow-list applied at the registration funnel

- `--computers` and `--computer-file` feed [`_expand_allowed_targets`](src/openhound_sccm/source.py#L41-L58),
  which lowercases each name **and** adds its short-name form so a host matches whether it's later seen as
  an FQDN or a NetBIOS name. The lowercased, short-name-expanded set is assembled at
  [source.py:244-248](src/openhound_sccm/source.py#L244-L248) and handed to `SourceContext.allowed_targets`
  ([source.py:267](src/openhound_sccm/source.py#L267)).
- [`_is_allowed_target`](src/openhound_sccm/context.py#L239-L258) (CMBP's `Test-AllowedTarget`) is checked
  inside `register_target`: an **empty** allow-list means *allow all* (pure discovery mode), and a
  non-empty one rejects any host whose candidate name forms don't intersect it — logging the skip rather
  than silently dropping it ([context.py:296-297](src/openhound_sccm/context.py#L296-L297)).

Because the gate sits at the single registration funnel, the same filter governs LDAP-discovered hosts,
DNS-discovered hosts, mid-run HTTP-discovered siblings, and CLI seeds alike. `--computers` therefore does
**double duty**: every listed host is both a *seed* (collected) and the *allow-list* (nothing else is
touched) — the behavior `debug_per_host.py` documents explicitly.

### Trade-offs

The allow-list is name-based, not SID-based, so it relies on consistent name forms (mitigated by the
short-name expansion). A host that can't be resolved to a name at all can't be matched against a non-empty
allow-list.

---

## 5. An Active Directory CLI surface and context auto-detection

### The framework baseline

OpenHound gives you a generic `openhound collect <source> <output>` command and resolves configuration via
DLT's layered config system (`SOURCES__<SOURCE>__*` env vars, `.env`, `secrets.toml`). The convenience
decorator `@app.collect()` registers a *minimal* command. A REST collector typically needs one secret (an
API token) and one config value (a base URL).

### Why it breaks for SCCM

SCCM operators think in **CMBP flags**: `-d/--domain`, `--dc`, `-u/-p`, `--nt-hash`, `--ticket`,
`-m/--collection-methods`, `-c/--computers`, `--site-codes`, `--threads`, and more. They also expect the tool to
**auto-detect** the AD domain and a domain controller when run on a domain-joined Windows box — the way the
PowerShell tool does — rather than demanding flags. None of that fits a one-token REST command.

### The add-on: a hand-registered Typer command + a flag→env bridge + context discovery

Rather than use `@app.collect()`, [`main.py`](src/openhound_sccm/main.py) registers
[`collect_sccm`](src/openhound_sccm/main.py#L842-L1009) **directly on the framework's public Typer group**
(`from openhound.cli.collect import collect as _collect_typer`) so it can expose the full CMBP flag surface
([main.py:842-885](src/openhound_sccm/main.py#L842-L885)). It then assigns `app.collector = collect_sccm`
([main.py:1057](src/openhound_sccm/main.py#L1057)) so the framework's import-time
`validate_extension` still sees a registered hook.

Because the DLT `source()` factory only reads configuration through injection, the command **translates
every flag into the env var the source expects** before the source is built:

- [`_FLAG_TO_ENV`](src/openhound_sccm/main.py#L59-L90) maps each flag to its `SOURCES__SCCM__*` name;
  [`_apply_env_overrides`](src/openhound_sccm/main.py#L227-L248) sets them last (so an explicit flag wins
  over an env/`.env` value), and [`_drop_empty_dlt_env_values`](src/openhound_sccm/main.py#L103-L111)
  removes empties so an unset flag can't clobber a higher-priority source.
- [`_suspicious_cli_argument_warnings`](src/openhound_sccm/main.py#L168-L218) catches a real foot-gun:
  Click parses `-dc 10.0.0.1` as `-d c` (because `-d` takes a value), silently turning the intended DC
  into a stray positional. The collector warns on these, masking sensitive values.
- **Context auto-detection** mirrors CMBP's order: [`_detect_windows_domain`](src/openhound_sccm/main.py)
  reads `USERDNSDOMAIN` then the FQDN suffix (Windows only); [`_resolve_dc_via_dns`](src/openhound_sccm/main.py)
  finds a DC via the `_ldap._tcp.dc._msdcs.<domain>` SRV record (cross-platform), building its resolver
  with the shared `openhound_collector_common.discovery.dns.make_resolver` (see
  [Where this code lives](#where-this-code-lives-the-shared-collector-common-library)) and keeping the
  SCCM-specific SRV query. When neither yields a domain,
  [`_require_domain_or_explain`](src/openhound_sccm/main.py) fails fast with a platform-specific message
  *before* DLT's config resolver throws a noisy `ConfigFieldMissingException`.

### Trade-offs

- The flag→env round-trip is indirection the framework doesn't need for REST collectors, but it's the
  price of keeping the source DLT-injectable while presenting a rich CLI.
- `extension.yaml`'s `credentials`/`parameters` blocks are still framework boilerplate
  ([extension.yaml:15-24](extension.yaml#L15-L24)) — configuration flows through the flags/env above,
  not through them. (Documented as a limitation in the README.)

---

## 6. Windows authentication across five protocols

### The framework baseline

OpenHound's auth story is REST auth: attach an OAuth/bearer token (or basic auth) to an HTTPS request.
One scheme, one header, stateless, cross-platform, and the framework/`requests` handle it. There is **no
framework support** for Windows-network authentication — Kerberos, NTLM, SSPI, channel binding, DCOM, or
SMB session setup — because no REST collector needs it.

### Why it breaks for SCCM

SCCM lives entirely on Windows authentication. The collector must authenticate over **five different wire
protocols**, each supporting the operator's full credential toolkit: the **current Windows user** (no
password — single sign-on via SSPI), explicit **username/password** (NTLM and Kerberos), **pass-the-hash**
(an NT hash instead of a password), and **pass-the-ticket** (a base64 Kerberos `.kirbi`). This is the
bulk of the divergence and lives under [`clients/`](src/openhound_sccm/clients/).

### The add-on: per-protocol auth stacks with a shared credential-precedence idea

> **Now in the shared library.** The auth realizers below — `choose_auth`, the NTLM/SPNEGO token
> minters (`KerberosToken` / `SspiClient` / NTLM type-1/3), the lockout-safe LDAP `AdClient`, the WMI
> impacket/pywin32 backends, and the MSSQL EPA `detect_epa` probe — were **promoted into
> `openhound-collector-common`** and are now shared with the MSSQL collector (see
> [Where this code lives](#where-this-code-lives-the-shared-collector-common-library)). The SCCM files
> named in the table are the thin **adapters** (`ADClient(AdClient)`, the `WmiClient` wrapper, the
> `http_auth` negotiators over `KerberosToken`/`SspiClient`, the `mssql_epa.test_epa` adapter over
> `detect_epa`); the implementation lives in the correspondingly-named `clients/*` modules under
> `openhound_collector_common`. The precedence philosophy and per-protocol behavior described here are
> unchanged by that move.

There is no single universal selector — each protocol family has its own realizer — but they share the
same **credential precedence philosophy**: *explicit credentials win (Kerberos first, NTLM fallback),
then current-user SSO, then (where the protocol allows) anonymous.*

| Family | Where the ladder lives | Schemes (in precedence order) | Key libraries |
|---|---|---|---|
| **HTTP / AdminService** | shared `choose_auth` in [`clients/http_auth.py:134-168`](src/openhound_sccm/clients/http_auth.py#L134-L168), driven by [`clients/http.py`](src/openhound_sccm/clients/http.py) | pass-the-ticket → explicit (Kerberos→NTLM) → current-user SSPI → **anonymous** | `impacket` (krb5/ntlm/spnego), `pywin32` (SSPI), `requests` |
| **WMI (AdminService fallback)** | reuses the **same** `choose_auth` ([`clients/wmi.py:333-353`](src/openhound_sccm/clients/wmi.py#L333-L353)) | pass-the-ticket → explicit (Kerberos→NTLM) → current-user SSPI → ~~anonymous~~ (skipped — DCOM requires auth) | `impacket` (DCOM), `pywin32` (`win32com`) |
| **LDAP / AD** | attempt plan in [`clients/ad.py`](src/openhound_sccm/clients/ad.py) (`_build_attempt_plan`), credential precedence in the shared `AdClient._select_auth_modes` | pass-the-ticket (GSSAPI via a private ccache) → pass-the-hash (`ntlm_hash`, ldap3 `LM:NT`) → explicit NTLM → integrated Kerberos (GSSAPI) → current-user SSPI-NTLM → anonymous — each over an auto-detected transport | `ldap3`, `impacket` (krb5 ccache), `pywin32` (SSPI), `winkerberos`/`gssapi` |
| **SMB (RemoteRegistry + SMB phases)** | inline ladder in `connect_smb` ([`clients/smb_sso.py:215-279`](src/openhound_sccm/clients/smb_sso.py#L215-L279)) | pass-the-ticket → pass-the-hash → explicit password → current-user SSPI Negotiate → null session | `impacket` (SMBConnection, krb5 CCache), `pywin32` (SSPI) |
| **MSSQL EPA probe** | `impacket_prober` / `sspi_prober` in [`clients/mssql_epa.py`](src/openhound_sccm/clients/mssql_epa.py) | explicit creds (incl. pass-the-hash) → current Windows user (SSPI); a **ticket-only** credential yields a WARNING+skip — pass-the-ticket can't forge the channel-binding AV pairs the probe needs | `impacket` (tds/ntlm), `pywin32` (SSPI) |

A few specifics worth calling out, because they show how much harder this is than a bearer token:

- **HTTP is a multi-leg challenge/response, not a header.** `http.py` runs the SPNEGO `401 →
  WWW-Authenticate: Negotiate <token> →` re-request loop itself, minting tokens with impacket/SSPI and
  carrying them in `Authorization: Negotiate <b64>` ([http.py:215-227](src/openhound_sccm/clients/http.py#L215-L227)).
  Kerberos needs a **Service Principal Name** (`HTTP/<fqdn>`); a bare-IP target can't form one, so the
  ladder skips Kerberos and uses NTLM directly. The GSS checksum deliberately omits the DCE-style flag
  because IIS/http.sys rejects it.
- **WMI realizes the *same* credential rungs over a completely different transport** — DCOM via impacket
  (one connection per WMI namespace, because a second `IWbemLevel1Login` over one connection is rejected)
  or `win32com` for the current user. The anonymous rung is dropped because DCOM always requires
  authentication. The payoff: `-u/-p/--nt-hash/--ticket` and passwordless collection behave identically
  whether a host answers over AdminService or only over WMI.
- **LDAP auto-detects transport *and* signing** and is **lockout-safe**. `ad.py` tries
  LDAPS:636 → StartTLS:389 → LDAP:389-with-sign-and-seal, varying by auth mode, and adds a TLS
  channel-binding token where the scheme supports it. Crucially, [`_is_credential_failure`](src/openhound_sccm/clients/ad.py)
  inspects the LDAP *result-49 subcode* and only treats genuine bad-password codes (`52e`, `532`, `533`,
  `701`, `773`, `775`) as credential failures — every other error (signing required, CBT mismatch, TLS
  failure) falls through to the next transport **without incrementing `badPwdCount`**, so the fallback
  chain can't lock out the account. A REST API has no such hazard.
- **The MSSQL EPA probe authenticates *in order to misbehave*.** It can't read Extended Protection
  enforcement directly, so it sends **deliberately malformed** NTLM channel-binding and service-binding
  values and watches how SQL Server reacts ([`mssql_epa.py`](src/openhound_sccm/clients/mssql_epa.py),
  `determine_epa`/`_classify_binding`). The impacket explicit-credential path can omit/corrupt those AV
  pairs independently and so can distinguish **Allowed** from **Required**; the current-user SSPI path
  *cannot* (Windows always inserts the channel-binding and target-name AV pairs), so it honestly reports
  the literal `Allowed/Required`.

### Trade-offs

- **Platform split.** Current-user SSO (SSPI) is Windows-only across every protocol (gated by
  `sys.platform == "win32"` + import probes). Kerberos is cross-platform but needs different backends
  (`winkerberos` on Windows, `gssapi` on Linux, the latter not bundled). Explicit credentials and
  pass-the-hash/ticket work everywhere via impacket. This is why the README's System Requirements draw a
  hard Windows-vs-Linux line.
- **Heavy dependencies** the framework never pulls in: `impacket`, `ldap3`, `winkerberos`, `pywin32`,
  `cryptography`. Each is load-bearing (see [`pyproject.toml:10-42`](pyproject.toml#L10-L42)).
- The EPA `Allowed/Required` ambiguity under SSPI is an unavoidable consequence of how Windows builds the
  NTLM type-3 message — a genuine limitation, not a bug.

---

## 7. Enhanced logging and diagnostics for blind remote environments

### The framework baseline

OpenHound configures one logging stack at import time — a `RichHandler` (or a plain stream handler in
container mode) plus a rotating file handler, fed by the root and `dlt` loggers
(`openhound/core/logging.py`). For a REST collector that you run locally and can re-run at will, that's
enough.

### Why it breaks for SCCM

This collector runs **in someone else's network**, against infrastructure we can't see and can't re-probe
on a whim, often once. When something fails on host #47 of 200, "re-run with a breakpoint" isn't an
option. The logs *are* the debugger. They have to answer, after the fact: *which host, which phase, what
went wrong, and what was the exception?* DLT also interleaves resource output, so a naive log is an
unreadable braid of 10 hosts' lines.

### The add-on: a context-tagging, ordered, diagnostics-capturing logging layer

> **Now in the shared library.** The whole `log_context` machinery — `[target][phase]` tagging,
> `with_log_context`, the completion-callback registry, `VERBOSE`, and the debug exc-info filter — was
> **promoted into `openhound_collector_common.logging.log_context`** as a superset and is now shared with
> the MSSQL collector (see [Where this code lives](#where-this-code-lives-the-shared-collector-common-library)).
> SCCM's [`log_context.py`](src/openhound_sccm/log_context.py) re-exports it and binds the two
> collector-specific helpers (`cached_with_log`, `trace_*`) to SCCM's own logger names. The two
> file-handler classes below (`_DiagnosticFileHandler`, `_OrderedLogFileHandler`) stay in SCCM's
> [`main.py`](src/openhound_sccm/main.py) — they are the SCCM CLI's output artifacts, not shared infra.
> The behavior described here is unchanged by the move; where a `log_context.py#Lxx` reference below points
> at what is now a re-export, the implementation is the same-named symbol in the shared module.

All in [`log_context.py`](src/openhound_sccm/log_context.py) and the handler classes in
[`main.py`](src/openhound_sccm/main.py), built *without editing the framework's handlers* — only by adding
filters/handlers and mutating live handler instances at runtime:

- **`[target][phase]` tagging.** [`target_context`](src/openhound_sccm/log_context.py#L152-L167) /
  [`phase_context`](src/openhound_sccm/log_context.py#L170-L183) push the current host/phase onto
  `contextvars`, and [`LogContextFilter`](src/openhound_sccm/log_context.py#L189-L220) folds them into
  every record's message — so the framework's own Rich handler renders `[ps1-mp.mayyhem.com][SMB] ...`
  with no formatter change. The decorator [`with_log_context`](src/openhound_sccm/log_context.py#L301-L394)
  even pushes/pops the context **per `next()` call** of a DLT resource generator, because DLT interleaves
  generators and a once-around-the-generator context would leak across hosts.
- **A `VERBOSE` tier between INFO and DEBUG** ([log_context.py:48-59](src/openhound_sccm/log_context.py#L48-L59)),
  surfaced by `-v`, gives CMBP's `[Verbose]` per-resolution/per-node traces without DLT/ldap3 internal
  noise (that's `--debug`). The console ladder is `(none)`=INFO → `-v`=VERBOSE → `--debug`=DEBUG,
  applied in [`_apply_log_level`](src/openhound_sccm/main.py) by lowering the console handlers.
- **A console-only mute, `--silent`.** The console handlers and the file handlers are two independent
  audiences (see the Rich handler vs. the rotating/`_Diagnostic`/`_Ordered` file handlers), so `--silent`
  gags the terminal *without* darkening the on-disk logs: [`_silence_console_handlers`](src/openhound_sccm/main.py)
  raises only the console handlers above `CRITICAL` (identified by [`_is_console_handler`](src/openhound_sccm/main.py):
  not a `FileHandler`, and either a `StreamHandler` or a duck-typed Rich handler with a `.console`), while
  the **root logger stays at the requested detail level**. That separation is what lets `--silent` *compose*
  with the verbosity flags — `--silent --debug` is a quiet terminal with DEBUG-level file logs. It's the
  mirror image of the normal path: same "mutate live handler instances" technique, raising instead of
  lowering. `--silent` also forces `--progress off`, since the progress tracker renders straight to the
  console and bypasses logging.
- **A per-run issues file** (`collect_issues_<ts>.log`, [`_DiagnosticFileHandler`](src/openhound_sccm/main.py)) captures
  every WARNING+ **with full traceback** — even when the warning was logged without one, by injecting
  `sys.exc_info()` if a live exception is in flight, then restoring the record so the console isn't
  affected. The companion [`_DebugExcInfoFilter`](src/openhound_sccm/log_context.py) does the
  same on the console in `--debug`. (A clean run writes no issues file — the handler opens lazily.)
- **A complete, human-ordered full log** (`collect_full_<ts>.log`, [`_OrderedLogFileHandler`](src/openhound_sccm/main.py))
  is **always written at DEBUG**, independent of the console level: for the duration of a run the collector's
  own namespaces (`openhound_sccm` + `openhound_collector_common`) are pinned to DEBUG and this handler's level
  is DEBUG, so a finished collection always has the full trace on disk without a re-run (`--debug` additionally
  folds `dlt`/`ldap3` internals in, via the root logger). It solves the interleaving problem by **buffering**
  records keyed by the active resource *or* host, flushing each group as one labelled block the moment that
  resource/host *completes* — driven by completion callbacks fired from the DLT generator wrapper and the
  engine's `on_target_complete`. The result is a log you can read host-by-host even though collection ran 10-wide.

  **The two grouping keys — and why the per-host collectors are *not* `@with_log_context`-decorated.** The
  handler buckets by *resource* when a resource context is set, else by *host*. That split maps onto the two
  schedulers ([§1](#1-pull-based-dlt-resources--a-push-based-per-host-phased-pipeline)): Stage-1 discovery
  resources (`ldap_*`, `dns_*`, `local_*`) are DLT generators driven **interleaved**, so they carry
  `@with_log_context(...)`, which pushes a *resource* context per `next()` and fires the resource-complete
  callback on exhaustion — one clean per-resource block. The Stage-2 per-host collectors (`collect_registry`,
  `collect_mssql`, `collect_adminservice`, `collect_wmi`, `collect_http`, `collect_smb`) are the opposite:
  the engine runs each to exhaustion **inside a `phase_scope(target, phase)` block on one worker thread**
  ([§2](#2-sequential-phases-per-target-concurrent-across-targets--and-a-sequential-debug-harness)), so
  `phase_scope` already supplies `[target][phase]`. Decorating them too was an active bug: `with_log_context`
  set a *resource* context (`func.__name__`, e.g. `"collect_registry"`) that hijacked the bucket key and fired
  resource-complete **once per (host, phase)** — so the full log filled with repeated `# collect_registry`
  blocks, each an interleaved fragment, while the intended per-host `flush_host` was a no-op. The fix is to
  **not** decorate the per-host collectors: with no resource context their records bucket by host and flush
  once, when the host finishes all its phases. Guarded by [`tests/test_per_host_log_blocks.py`](tests/test_per_host_log_blocks.py).
- **Runtime tidy-ups of the framework's Rich handler** ([`install_filter`](src/openhound_sccm/log_context.py#L253-L292)
  and [`_strip_version_suffix_from_handlers`](src/openhound_sccm/main.py#L317-L335)): turn off Rich markup
  parsing (so `[mayyhem.com]` isn't eaten as a malformed tag), drop the `file.py:line` column, and swap
  out the formatter that appends `(openhound_version=…)` — all by writing attributes on the *existing*
  handler instances, never by editing core.

### Trade-offs

This is a lot of logging machinery for an extension to carry, and it reaches into framework handler
internals by **class name and attribute** (e.g. matching `"OpenHoundRichFormatter"` /
`"RotatingFileHandler"`). That's deliberate — it means a framework change to those internals shows up as a
*visible* loss of behavior rather than a crash — but it is a coupling to watch on every OpenHound upgrade.

---

## 8. Windows-isms: the platform fights back

A scattering of fixes exist purely because the collector runs Python on Windows against Windows services.
A stock REST collector on Linux CI never meets any of these.

- **Log rollover crashes at midnight (WinError 32).** OpenHound core attaches its rotating file handler to
  **both** the root and `dlt` loggers, pointed at the *same* file. The first record after midnight (or past
  the size cap) triggers a rollover that `os.rename`s the open log — which **fails on Windows** because the
  sibling handler still holds the file open. The extension can't edit core, so
  [`_make_core_rotation_windows_safe`](src/openhound_sccm/main.py#L382-L409) (run once at import) mutates
  the live handler instances: it repoints each to a **per-run timestamped file** and replaces `doRollover`
  with [`_copytruncate_rollover`](src/openhound_sccm/main.py#L356-L379) — *copy the file to a dated sibling,
  then truncate in place* — so rotation never needs exclusive access to the open handle. It's a no-op off
  Windows, where rename-based rotation works.
- **dlt's pipeline storage gets locked under the user profile (WinError 32, again).** A *second* WinError 32,
  unrelated to logging. dlt keeps each pipeline's working state under `~/.dlt/pipelines/<name>/` and moves
  files with **atomic rename/remove** (`os.replace` during `extract`, `os.remove` during `load`). On Windows
  a file freshly written under the **user profile** is briefly held open by the **Search Indexer** (which
  indexes `C:\Users\<you>` by default) or an endpoint-security agent — so dlt's rename/remove
  **intermittently fails with WinError 32**, and worse, leaves a **stuck "pending package"** that re-trips
  the next run. (Seen at convert time at both `extract` and `load`; Defender real-time protection was *off*,
  which rules out its scanner and points at the indexer/agent.) Unlike the log handler above, this isn't a
  core handler instance we can mutate at runtime — it's dlt's own storage — so the fix is dlt's built-in
  knob: **relocate the pipeline dir off the indexed profile via the `DLT_DATA_DIR` environment variable**
  (dlt reads it in its run-context resolver and places pipelines under `<DLT_DATA_DIR>/pipelines`). The
  Stage-1 code tour sets it **in-process to a fresh per-run temp dir** before importing dlt
  ([`tour_driver_stage1.py`](tour_driver_stage1.py)); the real CLI sets it to a stable off-profile path
  (`C:\dlt-home`) via the `Debug: openhound collect sccm` launch profile's `env` block and/or a user-level
  `setx DLT_DATA_DIR`. A fresh, un-indexed location both dodges the lock and avoids inheriting a stuck
  pending package. `~/.dlt` is fine on Linux CI, so this is Windows-only.
- **uv-managed Python aborts every TLS handshake.** [`pyproject.toml`](pyproject.toml#L47-L52) sets
  `python-preference = "only-system"` because the `python-build-standalone` builds uv installs ship a
  `libcrypto` without the `OPENSSL_Applink` cross-CRT shim — which aborts the process mid-handshake on
  Windows. Harmless on Linux, but on Windows the collector deliberately prefers an official/system Python.
- **Single-label (NetBIOS) domains have no valid LDAP naming context.** `DC=MAYYHEM` doesn't exist, so AD
  answers with a referral that ldap3 chases into "invalid server address." [`_ldap_resolve`](src/openhound_sccm/context.py#L210-L237)
  detects the dot-less domain and skips it, deferring to an FQDN domain in the try-list — which is why only
  NetBIOS-prefixed principals (NAA, `sccm_push`) ever hit that path.
- **Dependency pins that exist only for Windows auth:** `ldap3>=2.10.2rc4` is the first release exporting
  the `ENCRYPT` and `TLS_CHANNEL_BINDING` constants needed for NTLM sign-and-seal and LDAP channel binding
  against signing-required DCs; `winkerberos` and `pywin32` are `sys_platform == 'win32'`-gated
  ([pyproject.toml:10-42](pyproject.toml#L10-L42)).

---

## 9. Convert can't iterate DuckDB rows: the unified Computer-node problem

> **Status — Stages 1–2 shipped.** The previous preproc/convert layer (`graph.py`, `lookup.py`, `transforms.py`,
> `models/computer.py`, `models/sccm_site.py`) was **deleted** in commit `6af5cc0 "Delete preproc/convert
> data"` pending a rebuild. The chosen design is recorded in
> [`docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md`](docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md)
> (authoritative) with rationale in the two proposals cited below. Stages 1 and 2 of the Convert2-Read-DB
> pipeline are now implemented; this section describes the divergence and the shipped design.

### The framework baseline

OpenHound's `convert` reads **JSONL driver files from the collected-data bucket** and emits one
node/edge per row. The model is *one API resource == one graph entity* (an Okta user row → a User node, a
GitHub repo row → a Repository node). `preproc` can build correlation tables in DuckDB, but `convert` can
reach those tables **only** through `self._lookup` — *point* and *list* queries
(`_find_single_object` / `_find_all_objects`), used to *enrich* a node or *fan out* edges. There is **no
code path that lets `convert` iterate a DuckDB table to emit one node per row** — the OpenGraph reader is
hardwired to a filesystem JSONL glob. (Full code evidence is in the proposal below.)

### Why it breaks for SCCM

The SCCM **Computer** node has no single driver file. One computer's properties are spread across *many*
collected tables — `ldap_computers`, AdminService/`SMS_R_System`, `remoteregistry_computers`,
`smb_computers`, site-definition servers, WMI — all keyed by **AD SID**, with array properties
(site-system roles, resource IDs) that must be **unioned**. ConfigManBearPig does this with an in-memory
`Upsert-Node` merge. The natural OpenHound equivalent is a DuckDB `GROUP BY sid` in `preproc` that yields
**one coalesced row per computer** — but then `convert` has *no supported way to iterate that coalesced
table*. This is the framework gap that most directly blocks a clean port.

Discussion: https://specterops.slack.com/archives/C09LBVA5T1N/p1781633877476619

### The add-on / design direction

Two routes out of this gap were written up. The first is a proposed **core** fix, for the framework
maintainers, in
[`docs/proposals/2026-06-16-convert-read-from-duckdb.md`](docs/proposals/2026-06-16-convert-read-from-duckdb.md):
an opt-in `read_from="duckdb"` selector on `@app.convert` that makes the convert reader iterate the
preproc tables through the already-open lookup connection (using an **independent cursor** so per-row
`self._lookup` calls don't clobber the in-flight scan).

Because we can't depend on a core change landing, the **chosen approach needs no core edit**. It is
recorded in the spec as the **Second Convert Pipeline with DuckDB Read** (`Convert2-Read-DB`):

1. **`preproc`** loads the raw JSONL into DuckDB and builds **coalesced, one-row-per-entity** node tables
   (`node_*`) plus a derived `graph_edges` table with set-based SQL — `UNION` every contributing table
   normalized to a common shape, then `GROUP BY sid` (scalars coalesce via `any_value`, arrays union via
   `list_distinct(flatten(...))`). This `GROUP BY` is the in-DuckDB equivalent of CMBP's `Upsert-Node`, and
   the only construct that does a true column-and-array union across the per-source tables.
2. **`convert`** then runs its **own explicit `dlt.pipeline`** that reads those coalesced DuckDB tables
   directly and emits to the `opengraph_file` destination, instantiating a trivial typed model per table
   (`row → node` / `row → edge`). Reading DuckDB straight from the manual pipeline — rather than first
   writing the coalesced rows back out to JSONL — is the more DLT-native of the two patterns, confirmed
   with the OpenHound author. Each entity is therefore emitted **exactly once** (flat 1×).

Two alternatives were considered and **rejected**, recorded so the mechanism isn't re-litigated:

- **Multi-driver emit + merge-by-id — rejected on scale.** One trivial `convert` driver per contributing
  table, each emitting the *same* `Computer` node id so BloodHound coalesces the byte-identical duplicates
  by `ObjectIdentifier` on ingest. It stays within public extension points, but in the common worst case
  (every domain computer is a client, found by *both* LDAP and the privileged `r_system`) each computer
  emits ~2×, with further multiples on per-host-probed infrastructure — where Convert2-Read-DB's one-row-per-entity
  coalescing stays flat 1×. Sketched, as history, in
  [`docs/proposals/2026-06-16-computer-node-multi-driver-merge.md`](docs/proposals/2026-06-16-computer-node-multi-driver-merge.md).
- **JSONL writeback — kept as the documented fallback.** `preproc` `COPY`s each coalesced table back to
  `<bucket>/sccm/<table>/data.jsonl.gz`, and `convert` reads it with the framework's stock filesystem
  reader. Fully idiomatic on the read side, but a filesystem side-channel: the preproc transformer must
  learn the bucket path and write into it (coupling the preproc/convert path args), and it doubles IO.
  Held in reserve if Convert2-Read-DB hits a wall.

### Group identity: a collected `SMS_R_UserGroup` class replaces CMBP's live AD lookup *(shipped)*

CMBP turned each `SecurityGroupName` membership on an `SMS_R_System` / `SMS_R_User` record into a Group
node by calling `Resolve-PrincipalInDomain` — a **live Active Directory lookup, per group name, at
collection time** (`ConfigManBearPig.ps1:459`, `:7368`, `:7462`). An offline coalesce can make no AD
calls, and the membership strings carry only names, so a naive port produced **zero Group nodes** on real
lab data: `SMS_R_System` / `SMS_R_User` list groups by *name* only, and the offline `principal_by_name`
table (built from user/computer/admin records) has no entry for an ordinary AD group such as
`DOMAIN\Domain Users`.

The divergence: we collect **`SMS_R_UserGroup`** (`collectors/privileged.py::_user_group` →
`adminservice_user_group` / `wmi_user_group` tables) — a class CMBP never queried. AD Security Group
Discovery mirrors each security group into that class **with its own SID** and a `UniqueUsergroupName` in
the exact `DOMAIN\name` form the membership strings use. `preproc` folds `(unique_usergroup_name, sid)`
into `principal_by_name`, so `transforms._node_group`'s case-insensitive name→SID join resolves every
membership **offline and set-based**, instead of one AD round-trip per name. This is strictly more
scalable than CMBP and needs no live AD at convert time. (Inherent limit: a `SecurityGroupName` string
can't disambiguate two groups that share a name — both resolve — exactly the ambiguity CMBP's by-name AD
lookup also had.)

### Role columns arrive in heterogeneous shapes; preproc normalises them *(shipped)*

`sccm_site_system_roles` is contributed by several collectors that disagree on wire shape: AdminService
`system_roles` is a JSON array; `site_definitions_computers` / HTTP emit a bare `role@site` scalar; SMB /
RemoteRegistry emit a list that dlt + DuckDB's `read_json` can surface as JSON-array *text inside a
VARCHAR*. `transforms._arr` normalises all four shapes (NULL / JSON-array-text / scalar / native array) to
`VARCHAR[]` before the array-union, so a JSON-array string is *parsed* rather than comma-split into
bracket/quote garbage. The collectors were also made internally consistent (RemoteRegistry now always
emits a list via `_roles(...)`, matching SMB) so the source data is well-typed going forward — the preproc
normaliser is the belt, the collector fix the braces.

### Trade-offs

Convert2-Read-DB keeps each entity to a single emission — no duplicate-node disk cost and no dependence on BloodHound's
merge-by-id — at the price of `convert` carrying its **own** `dlt.pipeline` that reads DuckDB and re-shapes
nodes itself instead of using the stock JSONL reader. The exact DuckDB read-implementation (a custom
`@dlt.resource` over the open lookup connection vs. DLT's `sql_database` source) is **deferred to the
implementation plan**, where both are prototyped against the real `lookup.duckdb`. If Convert2-Read-DB proves
unworkable, the JSONL-writeback fallback above is the documented escape hatch.

---

## 10. dlt loads whatever the data contains; our SQL expects fixed columns

### The framework baseline

In `preproc`, **dlt** is the piece that turns the collected JSONL files into DuckDB tables. It does this
by **looking at the data and guessing the shape** — a "figure it out from whatever showed up" approach:

- It creates **only the columns it actually sees** in the rows.
- If a column is **empty (NULL) in every row** of a load, dlt **drops that column entirely**.
- It stores list-like fields (a list of group names, a list of roles) as **JSON**, not as a real list.

For a normal OpenHound collector — one tidy API where every row has the same shape — this is fine. The
data is uniform, so what dlt infers is exactly what you expect, every time.

### Why it breaks for SCCM

SCCM data is the opposite of uniform. It is **sparse and irregular**:

- Many source tables are **optional** — run LDAP only, or skip WMI, and whole tables simply don't exist on
  a given run.
- Many **columns are optional** — a registry flag like `disable_loopback_check` is often NULL on every host,
  so dlt drops the column.
- The **same kind of host seen over different protocols reports different columns** — an SMB-discovered
  computer and an LDAP-discovered computer don't carry the same fields.
- **List fields** (group memberships, site-system roles) come back as JSON — sometimes even as JSON *text
  sitting inside a plain-text column*.

Meanwhile our `preproc` coalesce SQL (the queries that merge many source tables into one
`node_*` row) is written the **opposite way**: it asks for a **fixed, known list of columns by name**
(`SELECT sid, sccm_site_system_roles, disable_loopback_check, …`). When the real data is missing one of
those columns, the SQL **can't even compile** — it fails before reading a single row. And because every
source-load is wrapped in `_safe` (which logs the error and moves on), one missing column **silently drops
the entire source**, so the finished graph is quietly incomplete.

Put simply: **dlt hands us "whatever the data happened to contain," but our SQL demands "exactly this set
of columns."** On real SCCM data those two expectations collide constantly.

### The add-on: three small defenses that make the SQL tolerant

All three live in [`transforms.py`](src/openhound_sccm/transforms.py) and run during `preproc`, *after* dlt
has loaded the tables. The easy way to remember them: **`_safe` keeps the pipeline alive, `_ensure_columns`
makes the columns exist, `_arr` makes the values the right shape.**

1. **`_safe` — the safety net** ([transforms.py:90](src/openhound_sccm/transforms.py#L90)). Each "load
   source X into table Y" step runs as its own statement. If it fails, `_safe` **logs it and keeps going**
   instead of aborting the whole preproc. This is what lets a run that used only some collection methods
   still build a graph from whatever *was* collected. It mainly catches the missing-*table* case (a table
   that doesn't exist at all).

2. **`_ensure_columns` — fill the gaps** ([transforms.py:101](src/openhound_sccm/transforms.py#L101)). Right
   before each coalesce, it looks at the source table and **adds any missing columns the SQL needs as empty
   (NULL) columns**. So whether a column vanished because dlt dropped it (all-NULL) or because that source
   never had it, the column now exists and the SQL compiles. Adding a column the SQL doesn't actually read
   is harmless; a column that's already there keeps its real values. This is the piece that stops `_safe`
   from silently dropping a source just because one optional column went missing.

3. **`_arr` (and `CAST(... AS VARCHAR[])`) — fix the shapes**
   ([transforms.py:124](src/openhound_sccm/transforms.py#L124)). List-like columns arrive in several shapes:
   a native list, a JSON array, JSON-array *text* inside a plain column, or a single scalar string. `_arr`
   turns **all of them into a real list** so DuckDB operations like `UNNEST` and array-union work. Without
   it, `UNNEST` on a JSON value errors out with "requires a single list as input." (The specific role-column
   case is detailed in [§9](#9-convert-cant-iterate-duckdb-rows-the-unified-computer-node-problem).)

### Why we defend in the SQL instead of pinning the schema at load

dlt *can* be told the opposite: pin an **explicit, complete column list and types** for every table at load
time, so nothing is ever missing or mis-typed. If we did that, `_ensure_columns` and most of `_arr` wouldn't
be needed.

We deliberately **didn't**, because pinning is **rigid**: the moment the real data drifts from the pinned
shape, dlt **refuses the entire load**. That is exactly the failure we already hit — the `ldap_sites` table
was pinned to a model, the real data's `site_code` came back slightly different (allowed to be empty), and
dlt's "freeze" rule **crashed the whole collect** instead of adapting (the `ldap_sites` decoupling fix).

So there is a real fork in the road, and we chose the tolerant side:

- **Pin at load** → strict and tidy, but any unexpected real-world shape is a **hard crash**.
- **Defend in the SQL** (our choice) → flexible; an unexpected shape becomes a **logged, survivable skip**
  — or, with `_ensure_columns`, no problem at all.

Given how much SCCM environments vary, the tolerant approach is the safer default.

### Trade-offs

- The defenses are **spread across every coalesce**. Each new node/edge stage must remember to list its
  optional columns for `_ensure_columns` and route every list column through `_arr`. Forget one and a source
  can silently drop on some future data. This is guarded by tests and by the log lines below.
- **`_safe` is a double-edged sword.** It keeps the run alive, but it can also *hide* a real problem by
  dropping a source. `_ensure_columns` exists largely to stop `_safe` from catching things it shouldn't.
- **Reading the log is the diagnostic.** `WARNING … skipped (missing source)` means a table that was never
  collected — usually a method you simply didn't run, which is normal. `ERROR … failed` means a table that
  *was* collected but still didn't load — that's the one worth chasing.
- **Expected misses are demoted to DEBUG** by [`_sccm_expected_miss`](src/openhound_sccm/transforms.py), the
  `expected_miss` predicate injected into `safe_execute`, so routine emptiness doesn't masquerade as a
  warning. Two cases qualify: **(1) transport mirror** — the collector emits EITHER `wmi_<X>` OR
  `adminservice_<X>` per data type, so a missing one whose sibling exists is normal; **(2) fallback-phase
  skip** — HTTP and SMB are fallback phases that `should_run_phase` skips for any host a privileged transport
  (AdminService/WMI) already collected ([§2](#2-sequential-phases-per-target-concurrent-across-targets--and-a-sequential-debug-harness)),
  so an absent `http_*`/`smb_*` role table is expected *whenever any privileged transport ran this
  collection*. The canonical example: the SMS Provider **is** the AdminService host, so it is
  privileged-collected and its HTTP probe is skipped — leaving `http_smsproviders` empty (and its transform
  a DEBUG skip) in every normal authenticated run. In an HTTP-only / SMB-only run no privileged table exists,
  so those fallback misses correctly stay a WARNING.

### The downstream consequence: convert must omit null properties on output

The NULL handling above is deliberate — `_ensure_columns` *creates* all-NULL columns on purpose so the SQL
compiles, and many optional attributes (`disable_loopback_check`, `dNSHostName`, the SCCM client flags) are
genuinely NULL on most rows. Those NULL columns flow into the typed node/edge models, whose optional fields
default to `None`. If we emitted them as-is, `dataclasses.asdict()` + the destination's plain `json.dumps`
would write each as JSON `null`.

**BloodHound's OpenGraph ingest rejects that.** A property value must be `string`/`number`/`boolean`/`array`
(an `anyOf` over those four) — `null` is not a member, so a single null-valued property fails the *entire*
file's schema validation and the ingest is refused. (The framework's other, Pydantic, serialization path
strips nulls via `exclude_none=True`; the dataclass + `asdict` path the convert pipeline uses does not, so
the responsibility lands here.)

So the convert emit step omits any property whose value is `None` before writing —
[`_without_null_properties`](src/openhound_sccm/convert_pipeline.py) runs on every node and every edge, the
single point all graph content flows through. This matches BloodHound's convention that an absent attribute
is *missing*, not `null`. Empty lists are kept (an array is a valid value); only `None` is dropped.

---

## 11. Stage 2 preproc/convert add-ons

Stage 2 of the Convert2-Read-DB pipeline ships four design additions beyond the Stage 1 baseline. Three of them extend the collect → preproc → convert contract; one is a new category of divergence that gets its own subsection below.

### 11a. Collect-side additions

Two small additions land in the `collect` phase to carry information forward to the decoupled `preprocess` and `convert` runs.

**`host_object_sid` on the RemoteRegistry current-user row** ([collectors/registry.py](src/openhound_sccm/collectors/registry.py)). The `remoteregistry_users` row for the current logged-on user now includes the host machine's own AD SID (`host_object_sid`). This gives the `graph_edges` builder a stable start-node id for the `HasSession` edge — without it, the edge could not connect the computer to the session user because the raw row carries only the user's SID. The field is `None` when the target's AD object could not be resolved; downstream, the edge builder drops the row with a warning rather than emitting a malformed edge.

**`collection_settings` table — one-row flag persistence** ([collectors/local.py](src/openhound_sccm/collectors/local.py)). A discovery-phase resource called `collection_settings` writes a single row carrying `disable_possible_edges` and `enable_bad_opsec` — the two CLI flags whose effects are decided at collect time but must be respected by the separate `preprocess` run. The `preprocess` step reads this row via `_read_disable_possible` ([transforms.py](src/openhound_sccm/transforms.py)) and uses it to gate possible-client rows and future Stage 6 relay edges. If the table is absent (older collection without the row), `_read_disable_possible` defaults to `False` — possible nodes are emitted.

### 11b. Persist-at-collect / gate-in-preproc for inferred client nodes

CMBP emits "possible" client nodes for devices that have a `CmRcService` SPN in AD (indicating the Remote Control client) but no confirmed SCCM enrollment (`SMS_R_System is_client = True`). The flag that gates this behaviour (`--disable-possible-edges`) is a CLI argument on `openhound collect sccm`, but the separate `openhound preprocess sccm` run has no access to the CLI that produced the raw data.

The solution is the `collection_settings` table described above. `_read_disable_possible` in [transforms.py](src/openhound_sccm/transforms.py) reads `bool_or(disable_possible_edges)` from that table and passes the result to `_node_client_device_possible`, which appends inferred client rows (`is_confirmed_active_client = False`) to `node_client_device` only when the flag is `False`. The inferred-client node id is `upper(object_sid)@root_site_code` — a deterministic, namespaced id that avoids merging with the `Computer` node (raw SID) yet allows the Stage 4 `SCCM_SameHostAs` edge to link it back to the AD computer object.

CMBP used a random GUID as the id for possible-client nodes; we use `object_sid@root_site_code` instead so id assignment is stable across repeated collections.

**Which site owns an inferred client — the Primary, never the CAS.** The `SCCM_HasClient` edge starts from the client's `site_code`, so that column decides which site "owns" the inferred client. A Central Administration Site cannot own clients, so this must be a **Primary** site. CMBP picks "the first primary site code published to AD" (`ps1:3253-3254`, filtering `siteType -eq "Primary Site"`). Two places cooperate to reproduce that, because the id keeps the `@root_site_code` suffix (which resolves to the CAS in a CAS-topped hierarchy) purely for namespacing:

- **Preproc (authoritative).** `_node_client_device_possible` sets `site_code` to `_first_primary_code` — `MIN(site_code) WHERE site_type = 2` from `site_hierarchy` (`site_type` comes from privileged AdminService/WMI site definitions, which are also what makes a hierarchy root exist at all, so the Primary/CAS distinction is always available when a possible-client is created). It falls back to the root only in the degenerate case of a hierarchy with no Primary, so the edge is never dropped. The deterministic `MIN` replaces CMBP's order-dependent `Select -First 1`.
- **Collect (raw-data hygiene).** `ldap_cmrc_devices` stamps the raw row's `site_code` via `_pick_client_device_site_code`, preferring a site the MP-capabilities parse classified as `"Primary Site"` (recorded on `ctx.primary_site_codes` during `ldap_management_points_raw`, which runs first). A CAS publishes an `mSSMSSite` object like any other site but has no management point, so without this it would sort into `ctx.site_codes` and could be picked as the client's site. This raw value is not consumed by the preproc builder above (which derives its own Primary from `site_hierarchy`); it exists so the collected artifact is itself coherent.

Earlier the port attached these to `_root_code` (the CAS in a CAS hierarchy), producing an impossible `CAS → SCCM_ClientDevice` edge — a port-parity bug against CMBP's explicit Primary-site filter (`ope-e739`).

### 11c. Traversable allow-list and the generic GraphEdge model

CMBP maintains a hard-coded list of edge kinds whose `traversable` property is `True` — the set that BloodHound's attack-path engine follows when building attack paths (`ConfigManBearPig.ps1:2216-2249`). Kinds outside the list are stored but not traversed (e.g. `SCCM_HasMember`).

In OpenHound the list lives in `TRAVERSABLE_EDGE_KINDS` in [kinds/edges.py](src/openhound_sccm/kinds/edges.py). It is a `frozenset` covering current and future (Stage 3–6) kinds so later stages can add edges without updating the traversability logic.

All edges — regardless of kind — are emitted by the single generic [`GraphEdge`](src/openhound_sccm/models/graph_edge.py) model. It reads the `graph_edges` preproc table and sets both `SCCMEdgeProperties.traversable = kind in TRAVERSABLE_EDGE_KINDS` and `SCCMEdgeProperties.collectionSource` from the row's `collection_source` array (defaulting to `[]`). The `collection_source` column is a typed `VARCHAR[]` array — **not** a JSON string. Storing it as JSON was a Stage-2 bug (DuckDB returns JSON columns as plain strings, which would have required manual parsing in convert); the typed array avoids that entirely. This keeps the edge model trivially thin and `graph_edges` a uniform table — new edge kinds only require rows in the table plus an entry in the allow-list if they should be traversable.

**`graph_edges` columns (as of Stage 6):**

| Column | Type | Description |
|---|---|---|
| `start_id` | `VARCHAR` | Start node id |
| `end_id` | `VARCHAR` | End node id |
| `kind` | `VARCHAR` | Edge kind string |
| `collection_source` | `VARCHAR[]` | Provenance tags array-unioned across duplicate rows |
| `coercion_victim_and_relay_target_pairs` | `VARCHAR[]` | Human-readable `"Coerce <victim>, relay to <target>"` strings; populated only by the three `CoerceAndRelay*` builders; `NULL` (coalesced to `[]` by dedup) for every other edge kind. |
| `coercion_victim_hostnames` | `VARCHAR[]` | FQDNs of coercion victim hosts; populated only by `_edge_coerce_relay_smb`; `NULL` (coalesced to `[]` by dedup) for all other kinds. |

The three `CoerceAndRelay*` edge kinds carry additional context via the `SCCMRelayEdgeProperties` subclass of `SCCMEdgeProperties` (defined in [graph.py](src/openhound_sccm/graph.py)), which adds `coercionVictimAndRelayTargetPairs` and `coercionVictimHostnames` fields. `GraphEdge` emits these relay-only properties when the edge's kind is one of the three relay kinds; every other edge uses the lean base `SCCMEdgeProperties` with only `collectionSource` and `traversable`. Field names in both classes mirror ConfigManBearPig's exact casing.

A final dedup pass (`_graph_edges_dedup`) in the `graph_edges` preproc query groups by `(start_id, end_id, kind)` and array-unions both `collection_source` and the two coercion columns via `list_distinct(flatten(list(...)))` — matching CMBP's `Upsert-Edge` array-merge behaviour (`ps1:2155-2158`).

**`node_computer.smb_signing_source` — SMB-signing probe provenance.** `node_computer` carries a `smb_signing_source VARCHAR[]` column that records which probe(s) observed the host's SMB-signing state: `["SMB-Negotiate"]` (from the unauthenticated SMB2-negotiate check in `smb_computers`), `["RemoteRegistry-SMBSigningCheck"]` (from the registry-based check in `remoteregistry_computers`), or both. This array is array-unioned across sources during the `GROUP BY sid` collapse and is consumed directly by `_edge_coerce_relay_smb` as the `collection_source` for the `SCCM_CoerceAndRelayToSMB` edge (filtered to the two SMB-signing probe tags). It is not emitted as a node property.

### 11d. Stage 4: client-device dedup and host-correlation edges

Stage 4 adds two new edge kinds and a pre-edge dedup pass, all of which interact closely with the `node_client_device` table built by Stages 2–3.

**`_dedup_client_device` — merge real+inferred twins before edges are built.** After `_enrich_client_device` resolves `ad_domain_sid` on real clients (from `SMS_R_System`) and inferred clients carry it from the CmRcService SPN's `object_sid`, the table can contain two rows for the same physical host: a real client (`is_confirmed_active_client = True`, id = SMSID) and its inferred twin (`is_confirmed_active_client = False`, id = `<SID>@root`). `_dedup_client_device` ([transforms.py:1531](src/openhound_sccm/transforms.py#L1531)) groups by `ad_domain_sid` (with a NULL-isolation guard so unresolved real clients are never grouped together), ranks the real client first, and keeps only the top-ranked row. Array columns (`collection_ids`, `collection_names`) are unioned across the group before the inferred row is discarded, so no data is lost. Critically, this runs **before** `_graph_edges_init` and all edge builders — so every edge is built from the deduped table and references only survivors, with no `graph_edges` rewrite needed afterward. This is a deliberate divergence from CMBP's order, where the merge happens after edges are built (`ps1:2269-2311`).

**`_edge_same_host` — bidirectional Computer ↔ SCCM_ClientDevice.** After dedup, each surviving `SCCM_ClientDevice` row whose `ad_domain_sid` matches a `Computer` node's `sid` gets two `SCCM_SameHostAs` edges (one in each direction). This gives BloodHound paths in both directions (CMBP `ps1:2314-2320`). Because dedup runs first, the edge builder always sees the canonical survivor, never the discarded inferred twin.

**`_edge_local_admin_required` — site server → peer site systems.** A computer hosting `SMS Site Server@<site>` is granted local-administrator rights on every other site system in that site. The edge is built set-based from `site_system_roles`, with self-edges and secondary sites excluded (CMBP `ps1:1882-1909`). Both edge kinds carry `collection_source = ['SCCM_Invoke-PostProcessing']` for entity-panel provenance.

### 11e. Edge-endpoint stub-node backfill (new divergence category)

*This is a new category of divergence from a stock OpenHound collector.*

#### The framework baseline

In a stock collector, every node is produced by an explicit `@app.asset` model whose driver file contains a row for each entity. Edges reference nodes that are guaranteed to exist because both sides are collected from the same API. There is no provision for "an edge references a node that has no row in any driver table."

#### Why it breaks for SCCM

SCCM's data is inherently cross-referencing: an `SMS_R_System` record names the primary user's SID, but that SID may not appear in any `SMS_R_User` record — the user exists in AD but has never logged on interactively via SCCM. An `SMS_CollectionMember` names a device that was enrolled but later removed. CMBP handles this with `Upsert-Node` — an in-memory call that creates a bare node on the fly whenever an edge references an id with no existing node. OpenHound has no equivalent: if a `HasPrimaryUser` edge's end SID has no User node in the `node_user` table, the edge will silently point to a missing node in the OpenGraph output.

#### The add-on: node_backfill + StubNode

After all `node_*` tables are built and `graph_edges` is finalised, `preprocess` runs `transforms._node_backfill` ([transforms.py](src/openhound_sccm/transforms.py)). This function:

1. Collects every `end_id` from `graph_edges` whose kind is in `BACKFILL_END_KIND` (the edges whose end must be a resolvable node).
2. LEFT JOINs against every `node_*` table to find ids with no matching node.
3. Infers the kind for each missing end from `BACKFILL_END_KIND` (defined in [graph.py](src/openhound_sccm/graph.py)): `HasSession`→`User`, `MemberOf`→`Group`, `SCCM_HasMember`/`SCCM_HasStoredAccount`→`Base` (ambiguous principal). Writes the results to a `node_backfill` table.

The `node_backfill` table is read by the [`StubNode`](src/openhound_sccm/models/stub_node.py) convert model. `StubNode` emits a minimal node — just `id`, `kinds` (with `Base` appended for AD-principal kinds), and `environmentid` (domain SID for SID-keyed ids, else the id itself). It never carries SCCM-specific properties; those are populated if a future collection brings in the matching row.

This mirrors CMBP's `Upsert-Node` semantics: **every edge endpoint gets a node**, even if only a stub. The stub is later enriched or deduplicated if the real node arrives from SharpHound or a subsequent collection.

#### Trade-offs

- `BACKFILL_END_KIND` must be updated whenever a new edge kind is added whose end may lack a full node. Forgetting to add an entry leaves orphan edge endpoints in the graph. This is guarded by the `graph_edges_dedup_test.py` and `graph_edge_test.py` test files.
- `Base`-kind stubs (for `SCCM_HasMember` / `SCCM_HasStoredAccount` ends) have no `User` or `Group` label — they merge with a SharpHound node if the SID is ever resolved, but until then they appear as plain `Base` nodes in the graph.

---

### 11f. Split output: an untagged AD payload beside the SCCM source

*This is a new category of divergence from a stock OpenHound collector.*

#### The framework baseline

A stock collector emits one OpenGraph dataset under a single `source_kind`. Core's
`opengraph_file` destination takes `source_kind` as a required `dlt.config.value` and stamps
`{"metadata": {"source_kind": ...}}` into every file. There is no provision for emitting part
of the graph under a *different* source — or under *no* source at all.

#### Why it breaks for SCCM

The SCCM graph mixes two ownership domains. `SCCM_*` nodes are genuinely SCCM-owned and should
register under the `SCCM` source. But `Computer` / `User` / `Group` (and the backfill stubs) are
**Active Directory** objects — the same objects SharpHound collects. Tagging them with
`source_kind="SCCM"` makes the SCCM source *own* native AD nodes, so re-ingesting or deleting the
SCCM source would touch AD data it shouldn't. We want the AD nodes (and the edges touching them)
to merge into BloodHound's **native AD graph** by SID, augmenting SharpHound rather than shadowing
it — which means emitting them with **no `source_kind` at all**.

#### The add-on: a second emit pass + an untagged extension destination

- **Node routing needs no preproc step.** The coalesced `node_*` tables are already segregated by type, so the
  convert spec list is just split into `SCCM_NODE_SPECS` (`node_site`/`collection`/`security_role`/
  `admin_user`/`client_device`) and `AD_NODE_SPECS` (`node_computer`/`user`/`group`/`backfill`) in
  [main.py](src/openhound_sccm/main.py).
- **Edge routing is one preproc step.** `transforms._graph_edges_split` runs *after*
  `_node_backfill` and partitions `graph_edges` into `graph_edges_ad` (either endpoint id is in
  `node_computer ∪ node_user ∪ node_group ∪ node_backfill`) and `graph_edges_sccm` (the EXISTS/NOT
  EXISTS complement). Every backfill stub id counts as AD, so the `SCCM_HasMember` /
  `SCCM_HasStoredAccount` edges to bare-`Base` principals follow their stub into the AD payload.
- **Two emit passes.** `_emit_split_graph` calls `emit_graph_from_duckdb` twice into the same
  directory: the SCCM pass (`source_kind="SCCM"`, `resource_prefix="sccm"`) through core's
  `opengraph_file`, and the AD pass (`source_kind=None`, `resource_prefix="ad"`) through the
  extension's [`opengraph_file_untagged`](src/openhound_sccm/opengraph_untagged.py) — a sibling of
  core's writer that omits the `metadata` block entirely. Distinct resource prefixes give distinct
  file basenames (`sccm_*` vs `ad_*`), so two pipelines writing to one directory never collide.

#### Trade-offs

- An AD↔SCCM edge lives in the untagged file but references an `SCCM_*` node defined in the tagged
  file; this is safe only because BloodHound resolves edge endpoints by id across all ingested
  files — so both file sets must be uploaded together.
- `opengraph_file_untagged` duplicates core's writer logic (a coupling to watch on OpenHound
  upgrades), because core's destination can't express "no metadata" and core is off-limits.
- `_graph_edges_split` must run after `node_backfill`; a future reordering of `transforms()` that
  breaks that would silently route stub-edges to the wrong file. Guarded by
  [`graph_edges_split_test.py`](tests/graph_edges_split_test.py).

---

### 11g. Stage 5: MSSQL node merge and topology inference

Stage 5 adds six `MSSQL_*` node tables and ~15 edge kinds, all built entirely in `preproc`
(`transforms.py`) and emitted through the existing Convert2-Read-DB pipeline. No new framework
divergence categories are introduced; the MSSQL work is an extension of the preproc node-coalesce
design from §9 and the output-split routing from §11f.

**`MSSQL_Server` merge — one row per `host_sid:port`.** `node_mssql_server` is built like
`node_computer`: three `INSERT` arms into a staging table, then collapsed by
`GROUP BY upper(host_sid), host_sid, port` with `any_value` for scalars (the raw `host_sid`
is carried alongside `upper(host_sid)` in the GROUP BY so the non-uppercased value stays
selectable):

- `mssql_server_instances` — the EPA scan; supplies `extendedProtection`, `forceEncryption`,
  `strictEncryption`.
- `remoteregistry_mssql_servers` — the registry walk; supplies port, `forceEncryption`,
  `instanceNames`.
- `_mssql_sql_servers` — a staging table resolved per `(site, SQL-host)` role row from
  `sccm_site_system_roles` joined through `node_computer`; supplies `SCCMSite`, `SCCMInfra`,
  `dnsHostName`, `SQLServicePort`, and the SQL service-account fields.

Using the per-`(site, SQL-host)` role rows (not `node_site`'s single `any_value` per site) means
a site with **multiple SQL hosts** gets one `MSSQL_Server` row per host. Scan/registry rows with
no SCCM match still produce a bare `MSSQL_Server` (plus `MSSQL_HostFor` / `MSSQL_ExecuteOnHost`);
their `SCCMSite` / `SCCMInfra` columns stay null/false. This directly mirrors CMBP's
`Add-MSSQLServerNodesAndEdges` (ps1:6050-6186) while capturing non-SCCM SQL servers that CMBP
skips.

**Login / DatabaseUser topology inference.** CMBP never queries SQL for user identity.
Instead it infers the `sysadmin` logins from the machine accounts of the site's Primary Site
Server and SMS Provider computers — the hosts SCCM architecturally grants `sysadmin` on the site
database (`Invoke-ProcessMssqlNodesAndEdgesForSysadminComputer`, ps1:6187-6292). The port uses the
same pattern: login name and id use `upper(split_part(dnshostname, '.', 2)) || '\' || sam_account_name`
from the **sysadmin computer's own** DNS domain (`dnshostname` second label), which is correct for
cross-domain Site Server / SMS Provider hosts (a refinement over CMBP's `$Domain.Split('.')[0]`
which read the **collector's** domain). Database, `sysadmin` ServerRole, and `db_owner`
DatabaseRole nodes follow from the same SCCM topology: the database is always `CM_<siteCode>` and
the roles always exist. Stage 5 fixes one CMBP scope bug: CMBP left `sysadmin`/`db_owner` `members`
arrays empty (undefined variable, ps1:6105/6155); the set-based port fills them from the joined
logins/database-users.

**`environmentid`.** All six MSSQL node kinds use `domain_environment_id(host_sid)` — the
AD-domain SID of the SQL host — the same derivation as `Computer` / `User` / `Group` nodes
(see §9 "Group identity" and [graph.py](src/openhound_sccm/graph.py) for `domain_environment_id`).
This ensures MSSQL nodes merge correctly with a future `MSSQLHound` collection keyed on the same
domain SID.

**Output routing.** MSSQL nodes register in `SCCM_NODE_SPECS` (they are SCCM-owned,
`source_kind="SCCM"`). MSSQL edges insert into the single `graph_edges` table and are then
auto-routed by `_graph_edges_split` (§11f): edges whose Computer-SID or service-account-SID
endpoint is an AD node (`MSSQL_HostFor`, `MSSQL_ExecuteOnHost`, `MSSQL_HasLogin`,
`MSSQL_GetTGS`, `MSSQL_ServiceAccountFor`, `MSSQL_GetAdminTGS`) go to `graph_edges_ad` (untagged
AD payload); all-MSSQL/SCCM edges (`MSSQL_Contains`, `MSSQL_ControlServer`, `MSSQL_ControlDB`,
`MSSQL_MemberOf`, `MSSQL_IsMappedTo`, `SCCM_AssignAllPermissions`) go to `graph_edges_sccm`.
No change to `_graph_edges_split` is needed — MSSQL node ids are deliberately not in its AD id set.

### 11h. Stage 6: coerce-and-relay possible edges and the synthetic Authenticated Users node

Stage 6 adds three new edge kinds (`SCCM_CoerceAndRelayToAdminService`, `MSSQL_CoerceAndRelayToMSSQL`, `SCCM_CoerceAndRelayToSMB`) and one new synthetic node type. No new framework divergence categories are introduced; Stage 6 extends the existing preproc-only pattern from §11c and the output-split routing from §11f.

**Surgical `--disable-possible-edges` semantics.** The `disable_possible_edges` flag (persisted in `collection_settings`, read by `_read_disable_possible`) already gated Stage 3–4 possible-client nodes. Stage 6 extends it to the three relay builders with a *surgical* two-level gate:

- **Default (flag off):** a null or absent NTLM restriction is treated as *assumed vulnerable* — matching ConfigManBearPig's behavior at `ps1:6618`, `ps1:6712`, `ps1:6762`. A known EPA setting other than `Off` always disqualifies the server, but a null EPA is also treated as vulnerable.
- **Flag on:** only *explicitly confirmed* `Off` values qualify for each relay condition. A null NTLM restriction or null EPA causes the relay row to be dropped rather than assumed safe.

This gives operators a single flag to choose between a speculative-complete view (default) and a confirmed-only view without changing the collection. The three builders each implement this via a conditional SQL expression for the `ntlm_ok` (and `epa_ok` for MSSQL) predicate.

`_read_disable_possible` combines the collect-time `collection_settings` value with the `SOURCES__SCCM__DISABLE_POSSIBLE_EDGES` env var (tightening-only OR), so preproc can re-tighten existing raw without a re-collect.

**Lazy Authenticated Users node.** Rather than creating a fixed set of Authenticated Users nodes up front, `_node_authenticated_users` runs *after* all three relay edge builders have inserted into `graph_edges`. It reads the distinct `start_id` values from relay-kind rows and inserts one `Group` row into `node_group` per domain that actually produced at least one relay edge. The node id follows SharpHound's well-known-SID form (`UPPER(FQDN)-S-1-5-11`) so it merges with SharpHound data by id; the `environmentid` is resolved from a co-occurring domain computer's AD domain SID via a join on `_domain_to_sid`. This lazy approach matches CMBP's per-iteration `Upsert-Node` pattern and avoids creating orphan Authenticated Users nodes for domains with no exploitable relay path. The node must be inserted into `node_group` *before* `_node_backfill` and `_graph_edges_split` so it is included in the AD id set and routed to the AD payload correctly.

**`SCCM_CoerceAndRelayToSMB` traversable bug fix.** ConfigManBearPig's traversable allow-list at `ps1:2221` named the SMB relay kind `CoerceAndRelayNTLMtoSMB`, while the function that emits the edge at `ps1:6775` used `CoerceAndRelayToSMB` — the string mismatch meant the SMB relay edge was stored but never marked traversable. This port emits `SCCM_CoerceAndRelayToSMB` and includes that exact string in `TRAVERSABLE_EDGE_KINDS`, so all three relay kinds are traversable.

**Output routing.** All three relay edges touch an AD `Group` start node (Authenticated Users), so they are routed to `graph_edges_ad` (the untagged AD payload) by `_graph_edges_split`. For `SCCM_CoerceAndRelayToSMB` the end node is also an AD `Computer`, so both endpoints are AD nodes. For `SCCM_CoerceAndRelayToAdminService` the end is a `SCCM_Site`, and for `MSSQL_CoerceAndRelayToMSSQL` the end is an `MSSQL_Login` — both SCCM-payload nodes — but the AD-start-node rule routes them to the AD payload regardless.

### 11i. HTTP version fingerprint from ccmsetup.exe — a new HTTP-phase capability

*This is a new category of divergence from a stock OpenHound collector.*

#### The framework baseline

Every existing HTTP-phase probe (§2/§3 above) reads at most a small status code or a few KB of XML —
`MPKEYINFORMATION`, `MPLIST`, the site-signing certificate. A stock REST-API collector (and every
probe this extension had until now) treats "make an unauthenticated or authenticated request and
parse the response" as reading a small, structured payload. There is no precedent, here or in a stock
OpenHound extension, for downloading and parsing a multi-megabyte *binary* file as a source of truth.

#### Why it breaks for SCCM

[SCCMVersionGuesser](https://github.com/synacktiv/SCCMVersionGuesser)'s technique for learning a
site's exact SCCM build **without any credentials** is to read the version string Microsoft embeds in
`ccmsetup.exe`, the client-installer binary every Management Point serves unauthenticated. This is the
only way to fingerprint the site's patch level (and therefore its outstanding CVEs, and whether it's
new enough that the AdminService rejects NTLM) when the operator has no domain credentials, or when
privileged collection (AdminService/WMI) reached the site but returned no version. Getting that string
means fetching and regexing an actual binary — a fundamentally different operation from every other
probe in this file.

#### The add-on: a best-effort binary fetch inside the confirmed-MP handler

- [`_probe_ccmsetup_version`](src/openhound_sccm/collectors/http.py#L378-L404) runs only after
  `probe_management_point` confirms the MP role (`self.is_mp = True`) via the existing anonymous
  `HttpClient`; a failed, missing, or version-less fetch is logged (`logger.debug`) and skipped — it
  never gates or affects role detection.
- The version is pulled out of the raw response bytes with a UTF-16LE regex
  ([`_CCMSETUP_VERSION_RE`](src/openhound_sccm/collectors/http.py#L147-L151)) matching the
  `5.XX.XXXX.XXXX` pattern SCCMVersionGuesser uses; a hit is emitted as one row to a new raw table,
  `http_site_versions` (`site_code`, `sccm_version`, `source="HTTP-ccmsetup"`, `mp_host`).
- `preprocess`'s [`_coalesce_http_site_version`](src/openhound_sccm/transforms.py#L1224-L1241) LEFT
  JOINs this table onto `node_site` and coalesces **privileged-first**
  (`coalesce(ns.version, hv.http_version)`) — AdminService/WMI's `version` always wins when both are
  known; the HTTP fingerprint only fills sites that yielded no privileged version. This must run as
  part of `_node_site`, before anything downstream reads `node_site.version`.
- Two things now consume that coalesced version: `convert`'s `SCCMSite.as_node`
  ([models/sccm_site.py](src/openhound_sccm/models/sccm_site.py)) calls
  `cve_table.lookup_cves(version)` to populate the new `SCCM_Site.versionCVEs` property (the
  SCCMVersionGuesser build/CVE map, `cve_table.BUILD_MAP` / `CVE_MAP`), and
  [`_edge_coerce_relay_adminservice`](src/openhound_sccm/transforms.py#L2880-L2896) reads the same
  version to **suppress** the `SCCM_CoerceAndRelayToAdminService` edge on sites confirmed to be SCCM 2509+
  (build ≥ `cve_table.ADMINSERVICE_NTLM_MIN_BUILD` = 9141 — the build where the AdminService starts
  rejecting NTLM). An unknown/unparseable version fails **open**: the edge is kept as a possible edge
  that can't be confirmed mitigated.

#### Trade-offs

- **Bandwidth/OPSEC.** v1 downloads the entire `ccmsetup.exe` (multiple MB) through the existing
  `HttpClient.get()`, which has no partial/`Range` request support. On an unauthenticated probe this is
  a much larger and more noticeable footprint than every other HTTP-phase probe (a few KB of XML/JSON
  at most). A bounded/`Range` fetch is a known future optimization, gated on adding a `headers=`
  parameter to `HttpClient.get()`.
- **Two decoupled version sources feeding one field.** Because `node_site.version` can now come from
  either privileged collection or this HTTP fingerprint, `_coalesce_http_site_version` must run before
  every downstream reader of that column (the CVE lookup and the relay-edge gate). A future reordering
  of `transforms()` that read `node_site.version` before this coalesce runs would silently see only the
  privileged value.
- **Fail-open gate has a blind spot.** The 2509+ relay suppression only fires on a *confirmed* version.
  If privileged collection is unavailable and the HTTP fingerprint also fails (fetch error, no MP
  confirmed, unrecognized version string), a genuinely-patched 2509+ site still emits the (now
  inaccurate) `SCCM_CoerceAndRelayToAdminService` possible edge — correct by design (an unconfirmed
  mitigation can't be assumed), but a source of false positives operators should be aware of.

---

### 11j. AD-object attribute capture via the per-host resolution cache

`Computer`, `User`, and `Group` nodes now also carry the underlying AD object's own attributes —
`Domain`, `Enabled`, `IsDomainPrincipal`, `Type`, `objectClass`, `servicePrincipalName`, `CN` (see
[graph.py](src/openhound_sccm/graph.py) `ComputerProperties`/`UserProperties`/`GroupProperties`) —
alongside the SCCM-specific properties already emitted. No new AD collector was added; the
extension reuses AD-resolution work the collector was already doing for other reasons.

Every phase that needs to turn a name/SID/DN into an AD object calls
`SourceContext.resolve_principal` ([context.py:187](src/openhound_sccm/context.py#L187)) — LDAP
discovery resolving admins, RemoteRegistry resolving current users, AdminService/WMI resolving
device-referenced principals, and so on. `resolve_principal` already caches every lookup in
`ad_resolution_cache` (hits *and* misses, keyed by lookup string — see
[Where this code lives](#where-this-code-lives-the-shared-collector-common-library) for the
"AD-resolution cache" reference in §1) to avoid repeat LDAP round-trips. It now *also* calls
`_record_resolved_principal` ([context.py:300](src/openhound_sccm/context.py#L300)) on every fresh
(non-cache-hit) success, deduping by SID into a second, purely-successful accumulator,
`SourceContext.resolved_principals`.

At the end of the per-host stage, a new DLT resource, `ldap_resolved_principals`
([source.py:227](src/openhound_sccm/source.py#L227)), drains that accumulator into a raw table — one
row per uniquely-resolved AD object, regardless of which phase resolved it. `preprocess`'s
`_derive_ad_props` ([transforms.py:267](src/openhound_sccm/transforms.py#L267)) builds a
`sid -> AD-attribute` lookup table (`ad_props`) from it — deriving `Enabled` from the
`userAccountControl` `ACCOUNTDISABLE` bit, `Type` from the last `objectClass` element (title-cased),
and always setting `IsDomainPrincipal = True` (every row in this table was, by construction,
actually resolved against AD) — and `_join_ad_props`
([transforms.py:341](src/openhound_sccm/transforms.py#L341)) LEFT JOINs it onto `node_computer`,
`node_user`, and `node_group` by SID, before those tables reach `convert`.

> **CRITICAL: resolved-principals-only, not a domain-wide sweep.** This reaches only the principals
> the collector actually resolved during *this run* — site servers, admins, device-referenced
> users/groups, and anything else a phase happened to look up. It is deliberately **not** a new LDAP
> enumeration pass over the whole domain. A principal SCCM knows about (e.g. a device's
> `primaryUser`) that no phase ever needed to resolve stays bare — `Domain`, `Enabled`,
> `IsDomainPrincipal`, `Type`, `objectClass`, `servicePrincipalName`, and `CN` are all `null` on that
> node, exactly as before this feature existed. This is **partial parity by design**: these seven
> properties are best-effort enrichment of whatever the run already touched, not a guarantee that
> every AD-native node in the graph carries them.

**Trade-off.** `ldap_resolved_principals` is itself a best-effort finalization table whose own
`pipeline.run` is allowed to fail without aborting the collect ([transforms.py:276](src/openhound_sccm/transforms.py#L276)),
so it may be absent on some runs. `_derive_ad_props` treats it like any other optional source
(`_ensure_columns` backfills missing/all-NULL columns, `_safe` logs and skips outright absence),
leaving `ad_props` created-but-empty rather than raising, so `_join_ad_props`'s LEFT JOINs always
bind — a missing or partial `ldap_resolved_principals` degrades to "no AD-attribute enrichment this
run," never a preproc failure.

---

## 12. One-command end-to-end: a `--run-all` flag, not a new verb

### The framework baseline

OpenHound models the pipeline as three separate top-level CLI verbs — `collect`,
`preprocess`, `convert` — each a Typer group created as a module-level singleton
and mounted on the root app with `add_typer` (`openhound/main.py`). There is no
"run everything" verb, and no hook for an extension to add its own top-level verb.
The reason is import order: an extension's module is imported *inside* the root
app's constructor — `TyperOverride.__init__` calls
`CollectorManager.from_entrypoint("openhound.sources")` (`openhound/cli/override.py`),
which loads every extension *before* `main.py` binds the root `app` or mounts the
verb groups onto it. So when an extension runs it can import and hang commands off
the pre-existing verb *groups* (that is how it registers `collect sccm`), but it
never receives a reference to the root app instance and there is no registry to
attach a new verb to.

### Why it breaks for SCCM

Operators expect to point the tool at an environment and get a graph — one
command, not three, and without hand-deriving the intermediate `lookup.duckdb` /
dataset-dir / `graph` paths each time. But the natural shape (`openhound run
sccm`) is exactly the thing the framework can't express without a core edit.

### The add-on: a flag on `collect`, backed by a shared orchestrator

- **CLI surface:** a `--run-all` flag on the already-hand-registered `collect sccm`
  command ([`collect_sccm`](src/openhound_sccm/main.py)), so no new verb and no
  core edit. When set, `collect_sccm` runs collection as usual, then calls
  [`_run_e2e_after_collect`](src/openhound_sccm/main.py) once the collect log
  handlers are torn down, so the two follow-on stages log through the normal
  console handlers.
- **The chaining itself is shared.** The actual "preproc then convert" logic lives
  in `openhound_collector_common.orchestration.run_end_to_end` (see
  [Where this code lives](#where-this-code-lives-the-shared-collector-common-library)),
  which invokes the app's registered `preprocessor` / `converter` hooks
  **in-process** and derives every path from the single collect `OUTPUT_PATH`.
  It is framework-agnostic (duck-types the app; no `openhound`/`dlt` import), so
  the MSSQL collector can adopt the same flag by calling it.
- **Progress plumbing quirk:** the framework stages read progress inconsistently
  (`Converter` uses `progress.value`; `PreProcessor` forwards the object straight
  to `dlt.pipeline()`), so the orchestrator's contract is `Progress | None` and it
  applies a `.value=None` shim on the convert side for the silent case.
- **Consolidated output summary:** because the three phases each write their own
  artifacts (collect: raw JSONL + the ordered/diagnostics logs; preproc:
  `lookup.duckdb`; convert: the `graph/*.json` files) and interleave their logs,
  `_run_e2e_after_collect` returns the `StagePaths` and `collect_sccm` calls
  [`_log_all_output_locations`](src/openhound_sccm/main.py) as the very last step —
  re-surfacing every file location in one block. It runs *after* collect's
  finally-block tears down the ordered/diagnostics file handlers, so the summary
  points back at those files by path rather than duplicating their content.

### Trade-offs

- `--run-all` runs all three stages in **one process**, an execution mode the
  manual three-command workflow never exercises. Collect's process-global state
  (the planted `StreamBridge`, the bumped `EXTRACT__WORKERS`) is cleaned up in its
  `finally` before the chain starts, so the follow-on stages start clean.
- It is a *flag*, not the `openhound run sccm` verb an operator might expect —
  the price of not editing core.
- On failure the chain stops and re-raises, leaving raw data intact and logging
  the manual resume commands (stop-on-first-failure).

---

## 13. Tunneling all collection traffic through a SOCKS5 pivot

### The framework baseline

A stock OpenHound collector authenticates a single HTTPS endpoint from wherever
the process happens to run — a cloud REST API is reachable from anywhere with
an internet connection. The framework has no notion of routing traffic through
an intermediary; there is nothing to configure because there is nothing to
route around.

### Why it breaks for SCCM

This collector's whole reason for existing is on-prem, and on-prem engagements
are routinely run from **outside** the target network, through a single
foothold. Unlike a REST collector's one endpoint, SCCM collection is discovery
(LDAP/DNS/DC) plus **five** per-host wire protocols (RemoteRegistry, MSSQL,
AdminService, WMI, HTTP, SMB) across four different client libraries
(`ldap3`, `impacket`, `requests`, plus the collector's own raw-socket probes).
For a pivoted engagement to be usable at all, every one of those has to egress
through the same SOCKS5 hop — a single "proxy this one HTTP client" option
would leave four other protocols leaking traffic straight from the outside box.

### The add-on: a process-wide `socket` interception, installed for the run

- **Implementation** (`openhound_collector_common.proxy`, `proxy/patch.py` +
  `proxy/socks.py`): three stdlib entry points are swapped for the duration of
  the run — `socket.socket` (subclassed as `_ProxiedSocket`, whose `connect`
  performs the SOCKS5 handshake to the destination), `socket.create_connection`
  (dials the proxy and hands it the destination **hostname**, never resolving
  locally), and `socket.getaddrinfo` (a pass-through that hands back the
  hostname unresolved, so callers that pre-resolve before connecting — e.g.
  `urllib3`/`requests` — still route the real name through `connect` instead of
  failing on an internal-only name). Loopback targets and the proxy's own
  endpoint are always bypassed (a recursion / local-traffic guard).
- **Scoped to the collect run only**, via the `socks_proxy_installed(proxy_cfg)`
  context manager (`main.py`), wrapping the entire discovery + per-host-phase
  window; a no-op pass-through when no proxy is configured, so the direct-mode
  code path is unchanged.
- **Destination names resolve at the proxy** (`socks5h` behavior) — the
  collector never needs to resolve an internal-only hostname itself for TCP
  traffic.
- **Our own DNS lookups are forced onto TCP** so they ride the same tunnel
  (SOCKS5 `CONNECT` cannot carry UDP): four proxy-aware call sites check
  `active_proxy()` and pass `force_tcp=True` into the shared
  `discovery.dns.make_resolver` — `main.py::_resolve_dc_via_dns`, two sites in
  [`collectors/dns.py`](src/openhound_sccm/collectors/dns.py)
  (`dns_management_points`'s SRV lookups and the `_resolve_v4`/`_resolve_v4_via_dns`
  pair), and `context.py::resolve_ip`.
- **SCCM's own footprint is thin**: the CLI parse/validate
  (`_parse_proxy_or_exit`, `_require_dc_or_dns_for_proxy` — the latter exits(2)
  when `--proxy` is set without `--dc`/`--dns`, since internal names can't
  be resolved from the outside box), the install-around-run wrap, and the four
  DNS call sites above. The interception itself carries no SCCM-specific logic,
  so it was built directly in the shared library (see
  [Where this code lives](#where-this-code-lives-the-shared-collector-common-library))
  so the MSSQL collector can adopt it without re-deriving it.

### Trade-offs

- **Native OS authentication cannot be tunneled — a hard, documented limit, not
  a bug.** Live current-user SSPI Negotiate and OS-Kerberos make their
  KDC/DCOM calls inside the OS itself (LSASS for Kerberos; `win32com` for the
  WMI SSPI rung — see [§6](#6-windows-authentication-across-five-protocols)) —
  traffic this process never touches, so no userland socket hook can carry it.
  To use a logged-in identity through the pivot, export its Kerberos ticket and
  pass `--ticket` (pass-the-ticket runs in-process through impacket, so it
  tunnels completely), or set up OS-level transparent proxying (tun2socks /
  Proxifier) on the outside box. Everything else in-process — explicit
  credentials, pass-the-hash, pass-the-ticket, and impacket-minted Kerberos +
  NTLM including the KDC exchange — tunnels fully.
- **No UDP.** SOCKS5 `CONNECT` is TCP-only; DNS is the only UDP-shaped traffic
  this collector produces, and it is forced onto TCP for exactly this reason.
- **Install-once-per-process, not reentrant.** `install()` raises if a proxy is
  already active — consistent with the existing assumption that `collect` runs
  once per process, but it means the interception cannot be nested or shared
  across concurrent runs in the same interpreter.
- **The `getaddrinfo` pass-through is aggressive** — it returns an unresolved
  hostname for anything that isn't loopback/bypassed rather than attempting
  resolution and falling back. Validated offline against `ldap3`, `requests`,
  and `impacket` (see [`spike_socks_proxy.md`](spike_socks_proxy.md) — all three
  funnel through the patched stdlib entry points with no bypass found); a
  live-lab run against a real SOCKS5 pivot is the remaining confirmation.

---

## 14. A shared integration-test and payload-diff engine, invoked off `--run-all`

### The framework baseline

A stock OpenHound collector's correctness is checked with ordinary unit tests against mocked HTTP
responses — the framework has no notion of asserting the *shape and content of a collected OpenGraph
payload* against a set of expected nodes/edges, and no comparator for diffing one collected payload
against another. A small, stable cloud REST API doesn't usually need either.

### Why it breaks for SCCM

This collector's correctness has always been checked against ConfigManBearPig by hand: re-run the
PowerShell predecessor's own test kit (`powershell_deprecated/Invoke-ConfigManBearPigUnitTests.ps1`),
which asserted specific nodes/edges existed with position-based, `$expectedEdges_*`-hardcoded checks and a
dead coverage report (`Get-MissingTests`); or run the standalone `compare_results.py`, which aligns two
BloodHound zips by **list index**, not by identity. Neither is reachable from the collector's own CLI, so
"collect, then immediately assert the graph is right" or "collect, then diff it against yesterday's run"
took a separate, manual step outside `openhound collect sccm`.

### The add-on: a shared assert/diff engine, two `collect` flags

- **The engine is collector-agnostic** and lives in `openhound_collector_common/integration_testing/`
  (no third-party deps — stdlib `json`/`zipfile`/`fnmatch` only):
  - `graph.py` — `Graph`/`Node`/`Edge` + `load_graph`, accepting either a directory of `*.json` OpenGraph
    payloads or a `.zip` of them; a duplicate node id across payloads (e.g. `sccm_*` + `ad_*`) merges by
    unioning `kinds` and filling in missing properties rather than overwriting.
  - `cases.py` — typed `EdgeCase`/`NodeCase` fixtures, each with a stable `id`, an optional `CountSpec`
    (`exact` / `at_least` / `at_most`, combinable into a range) and a `negative` flag for "this must NOT
    exist".
  - `matcher.py` — `property_match` / `node_matches` / `edge_matches`, a direct port of the PowerShell
    kit's `Test-PropertyMatch` / `Test-NodePattern` / `Test-EdgePattern`: case-insensitive matching,
    `*`/`?` wildcards via `fnmatch`, list-subset semantics, tolerant `"True"/"1"`/`"False"/"0"` bool
    coercion.
  - `runner.py` — `run_suite` runs every edge/node case plus an optional list of whole-graph **invariant**
    callables (`Callable[[Graph], Result]`) — a hook for cross-node checks that don't reduce to a single
    case (the PS kit's one hardcoded `memberOf` root-site check generalizes to this hook). Prints the same
    `<kind>: <description> - PASS/FAIL/SKIP` line shape as the PS kit, plus totals and a coverage report.
  - `results.py` — `Result`/`Summary` + `write_results_json`.
  - `compare.py` — `compare_graphs` builds a `ComparisonReport`: nodes/edges only in A vs. only in B, a
    per-node/per-edge property diff (`only_in_a` / `only_in_b` / `changed`), and a **by-kind property
    rollup** (which property names appear on a given kind in A but not B, and vice versa) — fixing
    `compare_results.py`'s index-based fragility with identity-keyed comparison.
  - `coverage.py` — `load_schema_kinds` / `coverage` / `report` diff a schema JSON's `node_kinds` /
    `relationship_kinds` against the fixture-covered kinds, replacing the PS kit's dead `Get-MissingTests`.
- **SCCM's fixtures + wiring are extension-local**, in `openhound_sccm/integration/` — none of the
  mayyhem.com-specific knowledge is shared:
  - `fixtures/edges.py` — 61 `EdgeCase` fixtures ported from the PS kit, retargeted at the new `SCCM_`/
    `MSSQL_`-prefixed edge kind names (and the CMBP `CoerceAndRelaytoSMB` typo dropped).
  - `fixtures/nodes.py` — `NodeCase` count fixtures per node kind, plus two whole-graph invariants:
    AdminUser/SecurityRole/Collection node ids are canonicalized to the hierarchy root site code, and
    every `SCCM_ClientDevice` belongs to a primary site (guards the ope-e739 regression).
  - `__init__.py` — `run_integration_tests(graph_dir, ...)` (loads the graph, runs the fixtures against it
    plus a `schema_SCCM.json` coverage report, returns `1` if any case failed, else `0`) and
    `compare_to_zip(graph_dir, zip_path, ...)` (loads both graphs, runs `compare_graphs`, renders the
    report, always returns `0`).
- **Two `collect sccm` flags, in a new "Testing" help panel** (`main.py`). Both force `run_all = True`
  before the pipeline starts, since there is no graph to test or diff without a completed convert:
  - `--run-integration-tests` calls `run_integration_tests` once convert finishes, writing
    `integration_results-<ts>.json`, then `raise typer.Exit(code=rc)` — the process exits non-zero if any
    case failed.
  - `--compare-to-zip <path>` calls `compare_to_zip` against an arbitrary node/edge payload — a CMBP zip
    or another OpenHound run — writing `compare-<ts>.json`. Its return value is never turned into an exit
    code, so the run always exits `0`: informational only, safe to run without breaking automation on
    drift.
  - Both reuse `_ts`, the same run timestamp already used for the collect logs, so every artifact from one
    invocation shares a suffix.
- **No new framework extension point.** This reuses exactly the pattern [§12](#12-one-command-end-to-end-a---run-all-flag-not-a-new-verb)
  established: a flag on the hand-registered `collect` command, running shared-library logic in-process
  after the app's own `preprocessor`/`converter` hooks have already produced the graph.

### Trade-offs

- **The engine is shared; the correctness knowledge is not.** `integration_testing/` knows nothing about
  SCCM, sites, or client devices, so adopting it for **MSSQL** means writing MSSQL's own `fixtures/` (its
  own `EdgeCase`/`NodeCase` list and invariants), not importing SCCM's. `openhound_collector_common.integration_testing`
  is available today for the MSSQL collector to wire the same two flags onto `collect mssql` against its
  own graph.
- **Supersedes, doesn't extend, the old validation flow.** The PowerShell test kit and `compare_results.py`
  are no longer the sanctioned way to check a collection — these in-process flags cover the same
  assert/diff ground without leaving the `collect` command and without requiring PowerShell.
- **`--compare-to-zip` is diagnostic, not a gate.** Because it always exits `0`, a CI pipeline that wants
  to fail a build on drift has to parse `compare-<ts>.json` itself; the flag's job is to surface
  differences, not judge them.

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

## Changelog

| Date | Change |
|---|---|
| 2026-07-24 | **Added §15 — direct BloodHound CE upload + hand-registered `convert sccm`** (ope-8c44, implementing the pivoted [Ope-8wi2](.tickets/Ope-8wi2.md)). New shared `openhound_collector_common.bloodhound` subpackage (`auth.py` HMAC/Bearer signing, `client.py` retrying HTTP client over the BH CE schema/file-upload endpoints, `uploader.py` orchestration + credential resolution, `zip_bundle.py`, `schema.py::disable_possible_edges`) plus a new `openhound-collector-common` `requests` dependency; 25 offline tests. SCCM adds `bloodhound_schemas.py` (loads + mutates `schema_SCCM.json` **and** `schema_MSSQL.json` — this collector emits `MSSQL_*` kinds too) and `bloodhound_upload.py::run_upload` (single dispatch shared by both CLI commands). An identical **BloodHound Upload** panel (`-B`/`--bloodhound`, `--bloodhound-url`/`--token-id`/`--token-key` + env vars, `--upload-schema-only`/`--upload-results-only`, `--skip-collection`, `--upload-dir`) was added to both `collect sccm` (uploads after a `--run-all` chain, or schema-only via `--skip-collection`) and `convert sccm`. Landing the `convert sccm` flags required **hand-registering** `convert sccm` on the framework's `convert` Typer group — replacing the `@app.convert(lookup=SCCMLookup)` decorator with a manual `app.converter = _run_convert` assignment + `_convert_typer.command`, the same seam `collect sccm` already used — because the decorator exposes no flag-carrying seam. Updated the README Quick Start (direct-upload examples) and added a "BloodHound Upload" Command Line Options subsection. Full SCCM suite: 731 pass. Live validation against `bloodhound.mayyhem.com` is the remaining step (offline tests use fakes for the HTTP layer). |
| 2026-07-24 | **Added §11j — AD-object attribute capture via the per-host resolution cache** (ope-c141, Phase A of a broader CMBP-parity property effort; also documents Phase B, ope-fb99, and the ope-c0c0 bug fix). `Computer`/`User`/`Group` nodes gain `Domain`, `Enabled`, `IsDomainPrincipal`, `Type`, `objectClass`, `servicePrincipalName`, `CN` (`graph.py` `ComputerProperties`/`UserProperties`/`GroupProperties`), sourced from AD attributes captured whenever `SourceContext.resolve_principal` freshly resolves a principal during collection (`context.py::_record_resolved_principal`), persisted by a new `ldap_resolved_principals` DLT resource run at the end of the per-host stage (`source.py`), and joined onto the three AD node tables in preproc via new `transforms._derive_ad_props`/`_join_ad_props`. Deliberately **resolved-principals-only** — not a domain-wide LDAP sweep; a principal never resolved during a run stays bare. No new framework divergence category — extends the existing collect-side-table + preproc-join pattern (§11a/§11b). Also (Phase B, ope-fb99): `SCCM_Site.siteSystemRoles` (per-site aggregation of `Computer.SCCMSiteSystemRoles`, empty on Secondary Sites); six new `SCCM_ClientDevice` telemetry-extra properties (`currentManagementPoint`, `currentManagementPointSID`, `previousSMSID`, `previousSMSIDChangeDate`, `userName`, `userDomainName`); and `SCCM_IsMappedTo` now carries `SCCMInfra = true` (the only edge kind that does). And a bug fix (ope-c0c0): `SCCM_ClientDevice.lastOnlineTime`/`lastOfflineTime` were always empty due to a `c_n_*` vs `cn_*` raw-column-name typo in `_node_client_device`; both now populate. Updated the README Node Reference (Computer/User/Group/SCCM_Site/SCCM_ClientDevice tables + Limitations) and Edge Reference (`SCCM_IsMappedTo`). |
| 2026-07-22 | **Python integration-test kit + payload diff.** New shared `openhound_collector_common/integration_testing/` engine (graph loader for dir/zip, wildcard matcher, typed EdgeCase/NodeCase with exact/at_least/at_most counts, results+JSON, runner with a whole-graph invariant hook, deep comparator, schema-kind coverage). SCCM adds `openhound_sccm/integration/` fixtures (61 ported edge cases with new SCCM_/MSSQL_ names, node cases, memberOf invariant) and two `collect sccm` **Testing** flags: `--run-integration-tests` (assert vs mayyhem fixtures, non-zero exit on failure) and `--compare-to-zip` (property-level diff of this run vs an arbitrary payload, always exit 0). Both imply `--run-all`. Supersedes the PowerShell kit + `compare_results.py` for the assert/diff workflows. Shared-lib change is additive (new subpackage) so MSSQL can adopt the same engine + flags. |
| 2026-07-22 | **Renamed five graph edge kinds to match the hand-maintained OpenGraph schema (`schema.json`).** Added the `SCCM_` namespace prefix to `SameHostAs`→`SCCM_SameHostAs`, `LocalAdminRequired`→`SCCM_LocalAdminRequired`, `CoerceAndRelayToAdminService`→`SCCM_CoerceAndRelayToAdminService`, and `CoerceAndRelayToSMB`→`SCCM_CoerceAndRelayToSMB`; moved the SQL relay into the separately maintained MSSQL schema as `CoerceAndRelayToMSSQL`→`MSSQL_CoerceAndRelayToMSSQL` (its end node is an `MSSQL_Login`, so it belongs to the MSSQL schema the operator uploads alongside this one). Reconciled the other direction too: `schema.json` had listed the site-replication edge as `SCCM_SameAdminsAs`, corrected to the code-true `SCCM_AdminsReplicatedTo`. Emission and entity-panel help key off the `kinds/edges.py` constants, so the change centers on the constant *values* + the `TRAVERSABLE_EDGE_KINDS` allow-list, then propagates to the saved cypher queries, README (Edge Reference / TOC / Mermaid), and the offline edge tests. CMBP-history references (the `CoerceAndRelayNTLMtoSMB` allow-list vs `CoerceAndRelayToSMB` emitter mismatch) are left verbatim as historical record. The schema also lists `SCCM_HasNetworkAccessAccount`, which no collector code emits yet — left as a placeholder and tracked in ope-e10b (emit from Local collection, reading the NAA from client WMI). No graph-shape change: same edges, new kind strings. |
| 2026-07-22 | **Ordered-log per-host grouping fix + always-DEBUG full log + log rename** (ope-54be, §7). Three coupled logging-layer changes. (1) **Grouping bug:** the six Stage-2 per-host collectors were `@with_log_context`-decorated, which set a *resource* context (`func.__name__`) and fired resource-complete once per (host, phase) — so the ordered log filled with repeated `# collect_registry` fragments and the intended per-host `flush_host` was a no-op. Removed the decorator from `collect_registry` / `collect_mssql` / `collect_adminservice` / `collect_wmi` / `collect_http` / `collect_smb` (the engine's `phase_scope(target, phase)` already tags `[target][phase]`); with no resource context their records now bucket by host and flush once per host. Stage-1 discovery resources keep the decorator (DLT drives them interleaved). Regression guard: `tests/test_per_host_log_blocks.py::test_per_host_collectors_do_not_fire_resource_complete`. (2) **Always-DEBUG full log:** the ordered handler is now created at DEBUG and both collector namespaces (`openhound_sccm` + `openhound_collector_common`) are pinned to DEBUG for the run, so the full log always holds the complete collector trace regardless of console level; `dlt`/`ldap3` internals still require `--debug`. (3) **Rename:** `collect_log_* → collect_full_*`, `collect_diagnostics_* → collect_issues_*`; summary labels + README/§7 updated. Separately, truncated the ccmsetup.exe HTTP body-preview debug line in `clients/http.py` to 1024 chars (it dumped multi-MB binary, now always in the full log). The always-DEBUG change also surfaced a latent label bug: VERBOSE (level 15) was missing from `_ORDERED_LEVEL_LABEL`, so those newly-captured lines rendered as `L15` — the handler's fallback now uses `logging.getLevelName` so any named level (VERBOSE included) prints its name (guard: `test_verbose_records_render_with_level_name_not_l15`). |
| 2026-07-22 | **`-v` now enables VERBOSE (was a no-op) + new `--silent` console mute** (ope-76f1, §7). The `-v`/`--verbose` option changed from a repeatable count (`-v`→INFO no-op, `-vv`→VERBOSE) to a plain boolean that raises the console straight to VERBOSE; the ladder is now `(none)`=INFO → `-v`=VERBOSE → `--debug`=DEBUG, and `-vv` is no longer valid (no-backward-compat rule). Added `--silent`, a **console-only** mute: `_silence_console_handlers` raises just the console handlers above `CRITICAL` (identified by the new `_is_console_handler` helper — not a `FileHandler`, and either a `StreamHandler` or a duck-typed Rich handler with `.console`), leaving the root logger and the two on-disk logs at their detail level. Because the mute is at the *handler* level, `--silent` composes with the verbosity flags — `--silent --debug` = quiet terminal, DEBUG-level file logs — and it also forces `--progress off` (the tracker bypasses logging). `_apply_log_level` gained a `silent` parameter. Offline tests: `tests/test_verbose_silent_flags.py` (13). Follow-up ope-00df tracks per-file `--no-diagnostics-log` / `--no-collect-log` switches. Updated §7 (VERBOSE bullet + new `--silent` bullet), the README verbosity tip + CLI options table. |
| 2026-07-22 | **Renamed the SOCKS5 pivot flag `--socks-proxy` → `-x` / `--proxy`** (§13). CLI-facing rename only: the option now takes a short `-x` and a long `--proxy`, and the help text is the concise `SOCKS5 proxy address (host:port or socks5://[user:pass@]host:port). Requires --dc or --dns.`. The Python parameter stays named `socks_proxy`, so the `SOURCES__SCCM__SOCKS_PROXY` env var, the `_FLAG_TO_ENV` mapping, `_parse_proxy_or_exit` / `_require_dc_or_dns_for_proxy`, and all downstream plumbing are unchanged. Registered `-x`/`--proxy` in the `_SHORT_OPTIONS_WITH_VALUES` / `_LONG_OPTIONS_WITH_VALUES` typo-detection tables so the suspicious-argument warnings still fire on the new flag. Per the no-backward-compat rule, `--socks-proxy` no longer works. Updated the §13 prose, the README Network row / Limitations / Proxying-pivoting examples, and the two `_parse_proxy_or_exit` error strings. No behavioral change to the interception itself. |
| 2026-07-21 | **Wired `--nt-hash` / `--ticket` into the LDAP auth path + MSSQL EPA ticket-only warning** (ope-b7b2, subsumes ope-272e). LDAP was the last protocol ignoring pass-the-hash / pass-the-ticket: SCCM's `ADCredentials`/`ADClient` now forward `nt_hash` + `kerberos_ticket` onto the shared `LdapAuth`, so the shared lockout-safe waterfall selects `ntlm_hash` (ldap3 `LM:NT`) or ticket-backed GSSAPI by the same precedence used across SMB/WMI/HTTP (updated [§6](#6-windows-authentication-across-five-protocols) LDAP row). No shared-library change — SCCM's adapter simply stopped dead-ending the credentials. Separately, SCCM's MSSQL phase does only EPA detection, which distinguishes Allowed/Required by forging bogus/missing NTLM channel-binding AV pairs — impossible over impacket's opaque Kerberos login — so `test_epa` now logs a WARNING and skips when a ticket is the *sole* usable credential (explicit creds and current-user SSPI still take precedence and detect EPA normally, since EPA is a server-side/identity-agnostic setting). Pass-the-ticket-for-EPA was deliberately not implemented and no follow-up ticket was opened (owner decision). Offline tests: `tests/test_ad_pth_ptt.py` (3) + `tests/test_mssql_epa.py` (+2). Live-lab validated against `dc.mayyhem.com`: LDAP pass-the-hash bound `auth=ntlm_hash` and pass-the-ticket (runtime-minted `.kirbi`) bound `auth=kerberos`, both LDAPS:636+CBT, authenticated as `MAYYHEM\domainadmin`. |
| 2026-07-21 | **Recursive GenericAll group expansion on the System Management container** (ope-e191), reconciled against final-review findings the same day. `ldap_system_management_dacl` used to only log a group holding GenericAll on the container — its members, who effectively inherit Full Control, were never discovered as targets. New helper `_expand_group_targets` (updated [§3](#3-recursive-target-discovery-and-collection)) fetches the group's `member` attribute directly (BASE-scope search on the group DN), registers computer members as scan targets (source `LDAP-GenericAllSystemManagement`), logs user members without scanning them, and recurses into nested groups with a `visited` set keyed on **group DN** (not SID, so a SID-less group cycle still terminates) to stop circular nesting. Huge memberships are paged transparently by the shared client's `ldap3` `auto_range` (on by default) — the collector no longer reassembles `member;range=N-M` pages itself; it only warns when a **residual** `member;range=` key survives, meaning auto_range failed to complete. `_parse_sd_generic_all` gained warning/debug logging on its five degraded-SD/ACE branches (too-short SD, out-of-range DACL offset, truncated ACE header, invalid ACE size, short access-mask) so a malformed ACL is distinguishable from a genuinely empty GenericAll set. Target discovery only — no new edges, no schema change, the SD parser stays GenericAll-only. `tests/test_ldap_smc_recursion.py` (5 tests: recursive expansion, circular-nesting termination via DN, unchanged direct-computer regression, auto-range full-membership no-warning, residual-range-key warning). |
| 2026-07-20 | **Fixed inferred (CmRcService-only) client devices being attached to the CAS** (ope-e739). The `SCCM_HasClient` edge for a "possible" client started from `_root_code` (the CAS in a CAS-topped hierarchy), producing an impossible `CAS → SCCM_ClientDevice` edge — a port-parity bug against CMBP's explicit `siteType -eq "Primary Site"` filter (`ps1:3253-3254`). Two coordinated fixes (updated §11b): preproc `_node_client_device_possible` now stamps `site_code` from the new `_first_primary_code` helper (`MIN(site_code) WHERE site_type = 2`), falling back to the root only when a hierarchy has no Primary; and collect-side `ldap_cmrc_devices` picks a Primary via the new `_pick_client_device_site_code`, using `ctx.primary_site_codes` recorded from MP-capabilities `site_type` during `ldap_management_points_raw`. The node id keeps its `@root_site_code` suffix for namespacing. Targeted offline tests updated/added (`node_client_device_possible_test.py`, `ldap_cmrc_site_code_test.py`); no impact on confirmed clients. |
| 2026-07-17 | **Added §13: `--socks-proxy` tunnels ALL collection traffic through a SOCKS5 pivot** (discovery + every per-host protocol — RemoteRegistry, MSSQL, AdminService, WMI, HTTP, SMB). New divergence category: a process-wide interception of the stdlib `socket` module (`socket.socket`/`create_connection`/`getaddrinfo`), promoted straight into `openhound-collector-common` (`proxy/patch.py` + `proxy/socks.py`) so MSSQL can adopt it. Requires `--dc` or `--dns` (enforced by `_require_dc_or_dns_for_proxy`, exits 2 otherwise); destination names resolve at the proxy (socks5h); the collector's own DNS lookups are forced onto TCP across four proxy-aware call sites (`_resolve_dc_via_dns`, two sites in `collectors/dns.py`, `context.resolve_ip`). Documented boundary: live current-user SSPI and OS-Kerberos make their KDC/DCOM calls in the OS (LSASS/`win32com`), not this process, so they cannot be tunneled — use `--ticket` (tunnels completely) or OS-level transparent proxying instead. All in-process auth (explicit creds, pass-the-hash, pass-the-ticket, impacket Kerberos+NTLM including the KDC exchange) tunnels fully. Offline-validated against `ldap3`/`requests`/`impacket` (`spike_socks_proxy.md`); a live-lab run is the remaining confirmation. Added rows to the [Where this code lives](#where-this-code-lives-the-shared-collector-common-library) table and the quick-reference table, plus a TOC entry. Fixed the README `--socks-proxy` row and Limitations, which had gone stale claiming the flag was "intended for DHCP/TFTP collection — not yet ported." |
| 2026-07-17 | **Added §11i (new divergence category) — HTTP version fingerprint from `ccmsetup.exe`** (ope-b916). The unauthenticated HTTP phase now fetches `/CCM_Client/ccmsetup.exe` from a confirmed Management Point and regexes the embedded PE version string (the SCCMVersionGuesser technique) into a new raw table `http_site_versions` — the first HTTP-phase probe that reads binary content rather than a status code, with a bandwidth/OPSEC trade-off (full multi-MB download in v1; a bounded/`Range` fetch is a future optimization). `preprocess`'s new `_coalesce_http_site_version` fills `node_site.version` from this fingerprint, privileged-preferred (AdminService/WMI wins when both are known). `convert` uses the resolved version to populate a new `SCCM_Site.versionCVEs` property (via `cve_table.lookup_cves`, previously dead code) and `_edge_coerce_relay_adminservice` now suppresses `CoerceAndRelayToAdminService` on sites confirmed to be SCCM 2509+ (build ≥ 9141, `cve_table.ADMINSERVICE_NTLM_MIN_BUILD`) since that AdminService version rejects NTLM; unknown/unparseable versions fail open (edge kept). Updated README's Node Reference (`SCCM_Site.versionCVEs`, `version` fallback note) and Collection Overview (HTTP row + edge version-gate cross-reference). |
| 2026-07-16 | **Added §12: a `--run-all` flag on `collect sccm`** that chains preprocess + convert in-process via the new framework-agnostic `openhound_collector_common.orchestration.run_end_to_end`. New kind of divergence (end-to-end orchestration without a new top-level verb). Added a row to the [Where this code lives](#where-this-code-lives-the-shared-collector-common-library) table and the quick-reference table, plus a TOC entry. |
| 2026-07-14 | **Shared-library reconciliation (new divergence category).** Added the [Where this code lives](#where-this-code-lives-the-shared-collector-common-library) section: the Windows auth stacks, the per-target logging layer, the push→pull streaming bridge, and the DNS resolver were **promoted up** out of this extension into `openhound-collector-common`, a shared library both SCCM and MSSQL now consume (SCCM's own files reduced to thin adapters). Seven promote-up reconciliations landed on branch `integration` (`choose_auth`+`is_ip`; WMI impacket/pywin32 backends; `mssql_epa`→`detect_epa`; DNS `make_resolver`; HTTP negotiators over `KerberosToken`/`SspiClient`; `log_context` superset; `StreamBridge`+unified `DONE`). Updated §1 (streams re-export + `StreamBridge` + `extract_workers_for`; `set_bridge` handshake), §5 (shared `make_resolver`), §6 + §7 (relocation notes), the ground-rule box, and the quick-reference table. Relaxed the engine's zero-dependency test to permit exactly `openhound_collector_common`. Validated: 552 SCCM unit / 5 skipped, 172 MSSQL unit, ruff clean, and a full lab collection streaming 5 per-host sources (1005 rows through one bounded queue) with no lost rows or deadlock. |
| 2026-07-01 | Stage 7 (docs + validation) — final stage of the preproc/convert port. Whole-document reconciliation of README + ARCHITECTURE.md + in-code docstrings against code-truth (14 node kinds, 37 edge kinds). Fixed the stale Graph Model prose (README claimed 8 emitted). Added three Mermaid diagrams (pipeline data-flow, clustered AD/SCCM/MSSQL overview, complete edge reference). Non-behavioral docstring/`Attributes` completeness pass. Ran ruff/mypy/pytest in an isolated uv env + the validate-extension structural checklist. Verified + closed ope-7f61 (edge-count banner miscount, already corrected to 11 for Stages 1–2). No behavioral code changes; known limitations (e.g. ope-3dbc null-property BloodHound rejection) documented, not fixed. |
| 2026-06-30 | Stage 6 (coerce-and-relay) shipped. Added §11h: three `CoerceAndRelay*` possible-edge kinds with surgical `--disable-possible-edges` gate (default: null NTLM/EPA assumed vulnerable; flag: only explicit `Off` qualifies). Lazy `_node_authenticated_users` synthesises one `Group` node per domain with at least one relay edge (id = `UPPER(FQDN)-S-1-5-11`, merges with SharpHound). `graph_edges` gains two `VARCHAR[]` coercion columns (`coercion_victim_and_relay_target_pairs`, `coercion_victim_hostnames`); `SCCMRelayEdgeProperties` subclass carries them to the BloodHound entity panel. Fixed `CoerceAndRelayToSMB` traversable mismatch (CMBP allow-list used `CoerceAndRelayNTLMtoSMB`; the port emits and marks traversable `CoerceAndRelayToSMB`). Updated §11c `graph_edges` column list + `SCCMRelayEdgeProperties` note; added `node_computer.smb_signing_source` provenance note. Quick-reference table updated. |
| 2026-06-30 | Stage 5 (MSSQL) shipped. Added §11g: `MSSQL_Server` is a three-source coalesce (`mssql_server_instances` + `remoteregistry_mssql_servers` + `_mssql_sql_servers`), keyed on `upper(host_sid):port`, capturing multiple SQL hosts per site and non-SCCM servers. Six MSSQL node kinds inferred from SCCM topology (no live SQL enumeration). `environmentid` = AD-domain SID of the SQL host via `domain_environment_id`. MSSQL nodes in `SCCM_NODE_SPECS`; edges auto-routed by the existing `_graph_edges_split`. Quick-reference table updated. |
| 2026-06-29 | Split output shipped. Added §11f: `convert` now writes two payloads — the SCCM-tagged set (`sccm_*`, `source_kind="SCCM"`) and an untagged AD set (`ad_*`, no `metadata` block) for native AD-graph merge. New preproc step `transforms._graph_edges_split` partitions `graph_edges` into `graph_edges_ad` / `graph_edges_sccm`; new extension destination `opengraph_file_untagged`; `emit_graph_from_duckdb` gained `resource_prefix` + `source_kind=None` (untagged) handling; `NODE_SPECS`/`EDGE_SPECS` split into `SCCM_*`/`AD_*` spec lists. |
| 2026-06-29 | Stage 4 shipped. Added §11d documenting `_dedup_client_device` (merge real+inferred SCCM_ClientDevice twins by `ad_domain_sid`, runs before all edge builders — deliberate divergence from CMBP's post-edge merge order), `_edge_same_host` (bidirectional `Computer ↔ SCCM_ClientDevice` `SameHostAs`), and `_edge_local_admin_required` (site server → peer site systems `LocalAdminRequired`). Renamed §11d stub-node backfill to §11e. Updated §11b: inferred client rows now use `is_confirmed_active_client = False` (not "possible"); note the Stage 4 `SameHostAs` edge that links them back to AD computer objects. |
| 2026-06-25 | Stage 3 shipped. Updated §11c: `graph_edges` is now four columns (`start_id`, `end_id`, `kind`, `collection_source VARCHAR[]`); `GraphEdge` sets both `traversable` and `collection_source`; dedup pass groups by `(start_id, end_id, kind)` and array-unions `collection_source` via `list_distinct(flatten(list(...)))`. Updated quick-reference table row. |
| 2026-06-23 | Stage 2 preproc/convert shipped. Added §11 documenting the four Stage 2 add-ons: `host_object_sid` on RemoteRegistry current-user rows; `collection_settings` one-row flag persistence; `_read_disable_possible` persist-at-collect/gate-in-preproc mechanism; `TRAVERSABLE_EDGE_KINDS` + generic `GraphEdge`; and the new divergence category **edge-endpoint stub-node backfill** (`node_backfill` + `StubNode`). Updated §9 status from "design stage" to "Stages 1–2 shipped". Updated quick-reference table. |
