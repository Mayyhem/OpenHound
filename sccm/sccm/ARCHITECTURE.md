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

---

## Table of Contents

- [The big picture: one tenant vs. many hosts](#the-big-picture-one-tenant-vs-many-hosts)
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
| `build_streams` / `DONE` / `broadcast_done` | [`phased_pipeline/streams.py`](src/openhound_sccm/phased_pipeline/streams.py) | One **bounded** `queue.Queue` per output table. Bounded means a fast producer *blocks* until the consumer catches up — **backpressure** that keeps memory flat. `DONE` is the single end-of-stream sentinel. |

The hard part is making DLT — which insists on *pulling* — consume rows that are *pushed* by a separate
thread pool. The bridge is in [`source.py`](src/openhound_sccm/source.py):

- For every per-host output table, the extension registers a one-line DLT **"emit resource"** whose entire
  body is *block on this table's queue until `DONE`* — [`_drain_stream` / `_make_emit_resource`](src/openhound_sccm/source.py#L144-L178).
  A blocking `get()` means "an empty queue is a *wait*, not an end." This turns each DLT resource into a
  **consumer** of the engine's output instead of a producer.
- The two halves run concurrently in [`_run_per_host_stage`](src/openhound_sccm/main.py#L748-L832):
  the **engine runs on a background thread**
  (producing rows onto the bounded streams, then closing them with `DONE` at quiescence) while
  **`pipeline.run(...)` drains those streams on the main thread**.
- Each emit resource is declared `parallelized=True` ([source.py:174](src/openhound_sccm/source.py#L174))
  so DLT gives each its own extract thread. A single-threaded round-robin extractor would block on the
  first momentarily-empty stream while another stream filled to capacity — a deadlock. To guarantee a
  worker per table, `_run_per_host_stage` temporarily raises the framework's `EXTRACT__WORKERS` env var to
  `len(tables) + 2` and restores it afterward ([main.py:796-832](src/openhound_sccm/main.py#L796-L832)).

A second framework-shaped problem: DLT builds the source via **config injection** (every `source()`
parameter is a `dlt.config.value` / `dlt.secrets.value`, see [source.py:198-231](src/openhound_sccm/source.py#L198-L231)),
so there is **no constructor** through which to hand the source live Python objects (the shared work
queue, the AD-resolution cache, the stream registry). The extension threads them through **module-level
globals** planted just before each `pipeline.run` and cleared after —
[`set_shared_queue` / `set_table_queues` / `get_last_ctx`](src/openhound_sccm/source.py#L61-L141). It's a
handshake, not elegance, but it's the only channel the injection model leaves open.

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

- `_run_per_host_stage` installs **process-global** state (the stream registry, the bumped
  `EXTRACT__WORKERS`), so it assumes **one collect run per process** — true for the CLI, documented as
  "not reentrant" ([main.py:759-762](src/openhound_sccm/main.py#L759-L762)).
- The `finally` block must drain streams while joining the engine thread so a crashed `pipeline.run`
  can't leave a worker blocked forever on a full queue ([main.py:813-832](src/openhound_sccm/main.py#L813-L832)).
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
`-m/--collection-methods`, `-c/--computers`, `--sms`, `--threads`, and more. They also expect the tool to
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
- **Context auto-detection** mirrors CMBP's order: [`_detect_windows_domain`](src/openhound_sccm/main.py#L415-L436)
  reads `USERDNSDOMAIN` then the FQDN suffix (Windows only); [`_resolve_dc_via_dns`](src/openhound_sccm/main.py#L439-L466)
  finds a DC via the `_ldap._tcp.dc._msdcs.<domain>` SRV record (cross-platform). When neither yields a
  domain, [`_require_domain_or_explain`](src/openhound_sccm/main.py#L509-L532) fails fast with a
  platform-specific message *before* DLT's config resolver throws a noisy `ConfigFieldMissingException`.

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

There is no single universal selector — each protocol family has its own realizer — but they share the
same **credential precedence philosophy**: *explicit credentials win (Kerberos first, NTLM fallback),
then current-user SSO, then (where the protocol allows) anonymous.*

| Family | Where the ladder lives | Schemes (in precedence order) | Key libraries |
|---|---|---|---|
| **HTTP / AdminService** | shared `choose_auth` in [`clients/http_auth.py:134-168`](src/openhound_sccm/clients/http_auth.py#L134-L168), driven by [`clients/http.py`](src/openhound_sccm/clients/http.py) | pass-the-ticket → explicit (Kerberos→NTLM) → current-user SSPI → **anonymous** | `impacket` (krb5/ntlm/spnego), `pywin32` (SSPI), `requests` |
| **WMI (AdminService fallback)** | reuses the **same** `choose_auth` ([`clients/wmi.py:333-353`](src/openhound_sccm/clients/wmi.py#L333-L353)) | pass-the-ticket → explicit (Kerberos→NTLM) → current-user SSPI → ~~anonymous~~ (skipped — DCOM requires auth) | `impacket` (DCOM), `pywin32` (`win32com`) |
| **LDAP / AD** | attempt plan in [`clients/ad.py`](src/openhound_sccm/clients/ad.py) (`_build_attempt_plan`) | explicit NTLM (exclusive when username+password set); otherwise Kerberos (GSSAPI) → current-user SSPI-NTLM → anonymous — each over an auto-detected transport | `ldap3`, `pywin32` (SSPI), `winkerberos`/`gssapi` |
| **SMB (RemoteRegistry + SMB phases)** | inline ladder in `connect_smb` ([`clients/smb_sso.py:215-279`](src/openhound_sccm/clients/smb_sso.py#L215-L279)) | pass-the-ticket → pass-the-hash → explicit password → current-user SSPI Negotiate → null session | `impacket` (SMBConnection, krb5 CCache), `pywin32` (SSPI) |
| **MSSQL EPA probe** | `impacket_prober` / `sspi_prober` in [`clients/mssql_epa.py`](src/openhound_sccm/clients/mssql_epa.py) | explicit creds **or** current Windows user | `impacket` (tds/ntlm), `pywin32` (SSPI) |

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
  surfaced by `-vv`, gives CMBP's `[Verbose]` per-resolution/per-node traces without DLT/ldap3 internal
  noise (that's `--debug`).
- **A per-run diagnostics file** ([`_DiagnosticFileHandler`](src/openhound_sccm/main.py#L535-L585)) captures
  every WARNING+ **with full traceback** — even when the warning was logged without one, by injecting
  `sys.exc_info()` if a live exception is in flight, then restoring the record so the console isn't
  affected. The companion [`_DebugExcInfoFilter`](src/openhound_sccm/log_context.py#L226-L247) does the
  same on the console in `--debug`.
- **A human-ordered log** ([`_OrderedLogFileHandler`](src/openhound_sccm/main.py#L612-L715)) solves the
  interleaving problem: it **buffers** records keyed by the active resource (or host), and flushes each
  group as one labelled block the moment that resource/host *completes* — driven by completion callbacks
  fired from the DLT generator wrapper ([log_context.py:359-369](src/openhound_sccm/log_context.py#L359-L369))
  and from the engine's `on_target_complete` ([log_context.py:136-149](src/openhound_sccm/log_context.py#L136-L149)).
  The result is a log you can read host-by-host even though collection ran 10-wide.
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

1. **`_safe` — the safety net** ([transforms.py:16](src/openhound_sccm/transforms.py#L16)). Each "load
   source X into table Y" step runs as its own statement. If it fails, `_safe` **logs it and keeps going**
   instead of aborting the whole preproc. This is what lets a run that used only some collection methods
   still build a graph from whatever *was* collected. It mainly catches the missing-*table* case (a table
   that doesn't exist at all).

2. **`_ensure_columns` — fill the gaps** ([transforms.py:27](src/openhound_sccm/transforms.py#L27)). Right
   before each coalesce, it looks at the source table and **adds any missing columns the SQL needs as empty
   (NULL) columns**. So whether a column vanished because dlt dropped it (all-NULL) or because that source
   never had it, the column now exists and the SQL compiles. Adding a column the SQL doesn't actually read
   is harmless; a column that's already there keeps its real values. This is the piece that stops `_safe`
   from silently dropping a source just because one optional column went missing.

3. **`_arr` (and `CAST(... AS VARCHAR[])`) — fix the shapes**
   ([transforms.py:194](src/openhound_sccm/transforms.py#L194)). List-like columns arrive in several shapes:
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

The solution is the `collection_settings` table described above. `_read_disable_possible` in [transforms.py](src/openhound_sccm/transforms.py) reads `bool_or(disable_possible_edges)` from that table and passes the result to `_node_client_device_possible`, which appends inferred client rows (`is_confirmed_active_client = False`) to `node_client_device` only when the flag is `False`. The inferred-client node id is `upper(object_sid)@root_site_code` — a deterministic, namespaced id that avoids merging with the `Computer` node (raw SID) yet allows the Stage 4 `SameHostAs` edge to link it back to the AD computer object.

CMBP used a random GUID as the id for possible-client nodes; we use `object_sid@root_site_code` instead so id assignment is stable across repeated collections.

### 11c. Traversable allow-list and the generic GraphEdge model

CMBP maintains a hard-coded list of edge kinds whose `traversable` property is `True` — the set that BloodHound's attack-path engine follows when building attack paths (`ConfigManBearPig.ps1:2216-2249`). Kinds outside the list are stored but not traversed (e.g. `SCCM_HasMember`).

In OpenHound the list lives in `TRAVERSABLE_EDGE_KINDS` in [kinds/edges.py](src/openhound_sccm/kinds/edges.py). It is a `frozenset` covering current and future (Stage 3–6) kinds so later stages can add edges without updating the traversability logic.

All edges — regardless of kind — are emitted by the single generic [`GraphEdge`](src/openhound_sccm/models/graph_edge.py) model. It reads the `graph_edges` preproc table (four columns: `start_id`, `end_id`, `kind`, `collection_source VARCHAR[]`) and sets both `SCCMEdgeProperties.traversable = kind in TRAVERSABLE_EDGE_KINDS` and `SCCMEdgeProperties.collectionSource` from the row's `collection_source` array (defaulting to `[]`). The `collection_source` column is a typed `VARCHAR[]` array — **not** a JSON string. Storing it as JSON was a Stage-2 bug (DuckDB returns JSON columns as plain strings, which would have required manual parsing in convert); the typed array avoids that entirely. This keeps the edge model trivially thin and `graph_edges` a uniform table — new edge kinds only require rows in the table plus an entry in the allow-list if they should be traversable.

A final dedup pass (`_graph_edges_dedup`) in the `graph_edges` preproc query groups by `(start_id, end_id, kind)` and array-unions the `collection_source` values across the group via `list_distinct(flatten(list(collection_source)))`, replacing the old `SELECT DISTINCT` that could only deduplicate identical triples.

### 11d. Stage 4: client-device dedup and host-correlation edges

Stage 4 adds two new edge kinds and a pre-edge dedup pass, all of which interact closely with the `node_client_device` table built by Stages 2–3.

**`_dedup_client_device` — merge real+inferred twins before edges are built.** After `_enrich_client_device` resolves `ad_domain_sid` on real clients (from `SMS_R_System`) and inferred clients carry it from the CmRcService SPN's `object_sid`, the table can contain two rows for the same physical host: a real client (`is_confirmed_active_client = True`, id = SMSID) and its inferred twin (`is_confirmed_active_client = False`, id = `<SID>@root`). `_dedup_client_device` ([transforms.py:1531](src/openhound_sccm/transforms.py#L1531)) groups by `ad_domain_sid` (with a NULL-isolation guard so unresolved real clients are never grouped together), ranks the real client first, and keeps only the top-ranked row. Array columns (`collection_ids`, `collection_names`) are unioned across the group before the inferred row is discarded, so no data is lost. Critically, this runs **before** `_graph_edges_init` and all edge builders — so every edge is built from the deduped table and references only survivors, with no `graph_edges` rewrite needed afterward. This is a deliberate divergence from CMBP's order, where the merge happens after edges are built (`ps1:2269-2311`).

**`_edge_same_host` — bidirectional Computer ↔ SCCM_ClientDevice.** After dedup, each surviving `SCCM_ClientDevice` row whose `ad_domain_sid` matches a `Computer` node's `sid` gets two `SameHostAs` edges (one in each direction). This gives BloodHound paths in both directions (CMBP `ps1:2314-2320`). Because dedup runs first, the edge builder always sees the canonical survivor, never the discarded inferred twin.

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

---

## Quick reference: which framework extension point each add-on uses

| Divergence | Framework extension point used | Where it would edit core (but doesn't) |
|---|---|---|
| Per-host phased pipeline | DLT "emit" resources draining queues; `pipeline.run` | A native per-target scheduler |
| Recursive discovery | Custom `WorkQueue` + `register_target` funnel | A "collection discovers more work" primitive |
| Include-only targeting | Allow-list checked in `register_target` | A target-scoping config |
| AD CLI surface | Typer command registered on the framework's `collect` group + flag→env bridge | A richer `@app.collect()` signature |
| Windows auth (×5 protocols) | `clients/*` auth stacks carried by the extension | Framework Negotiate/Kerberos/SMB/DCOM support |
| Logging & diagnostics | Filters + extra handlers + runtime mutation of live handlers | A pluggable logging/formatting API |
| Windows log-rollover fix | Runtime monkey-patch of core's handler instances | A Windows-safe `doRollover` in core |
| Convert from DuckDB | `preproc` coalesced tables + a second `convert`-time `dlt.pipeline` (Convert2-Read-DB) | `read_from="duckdb"` on `@app.convert` (proposed) |
| Tolerant coalesce vs. pinned load schema | `_safe` + `_ensure_columns` + `_arr` in the preproc transforms | Pinning full per-table schemas/types at load (rejected — brittle; it caused the `ldap_sites` freeze crash) |
| Persist-at-collect / gate-in-preproc (`disable_possible_edges`) | `collection_settings` one-row table written at collect; `_read_disable_possible` reads it in preproc | A first-class CLI flag shared across pipeline phases |
| Traversable allow-list + collection source | `TRAVERSABLE_EDGE_KINDS` frozenset in `kinds/edges.py`; `GraphEdge` sets `traversable` from it and `collection_source` from the `graph_edges` typed `VARCHAR[]` column; dedup pass array-unions `collection_source` per `(start_id, end_id, kind)` group | A graph-model-level traversability attribute; a typed array column on edges |
| Edge-endpoint stub-node backfill | `_node_backfill` + `StubNode` synthesise bare nodes for unresolved edge endpoints | An `Upsert-Node`-equivalent that creates nodes on demand |
| Split output (untagged AD payload) | A second `convert`-time emit pass through an extension `opengraph_file_untagged` destination (no `metadata`); preproc `_graph_edges_split` partitions edges | A `source_kind=None` / multi-source option on `@app.convert` |
| MSSQL node merge + topology inference | `_mssql_sql_servers` temp table + three-source `UNION`/`GROUP BY` coalesce in `_node_mssql_server`; Login/DatabaseUser inferred from SCCM sysadmin-computer topology in `_node_mssql_login` / `_node_mssql_database_user`; MSSQL nodes in `SCCM_NODE_SPECS`; edges auto-routed by the existing `_graph_edges_split` | No new framework extension point — extends the existing Convert2-Read-DB pipeline and output-split (§11f) |

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
| 2026-06-30 | Stage 5 (MSSQL) shipped. Added §11g: `MSSQL_Server` is a three-source coalesce (`mssql_server_instances` + `remoteregistry_mssql_servers` + `_mssql_sql_servers`), keyed on `upper(host_sid):port`, capturing multiple SQL hosts per site and non-SCCM servers. Six MSSQL node kinds inferred from SCCM topology (no live SQL enumeration). `environmentid` = AD-domain SID of the SQL host via `domain_environment_id`. MSSQL nodes in `SCCM_NODE_SPECS`; edges auto-routed by the existing `_graph_edges_split`. Quick-reference table updated. |
| 2026-06-29 | Split output shipped. Added §11f: `convert` now writes two payloads — the SCCM-tagged set (`sccm_*`, `source_kind="SCCM"`) and an untagged AD set (`ad_*`, no `metadata` block) for native AD-graph merge. New preproc step `transforms._graph_edges_split` partitions `graph_edges` into `graph_edges_ad` / `graph_edges_sccm`; new extension destination `opengraph_file_untagged`; `emit_graph_from_duckdb` gained `resource_prefix` + `source_kind=None` (untagged) handling; `NODE_SPECS`/`EDGE_SPECS` split into `SCCM_*`/`AD_*` spec lists. |
| 2026-06-29 | Stage 4 shipped. Added §11d documenting `_dedup_client_device` (merge real+inferred SCCM_ClientDevice twins by `ad_domain_sid`, runs before all edge builders — deliberate divergence from CMBP's post-edge merge order), `_edge_same_host` (bidirectional `Computer ↔ SCCM_ClientDevice` `SameHostAs`), and `_edge_local_admin_required` (site server → peer site systems `LocalAdminRequired`). Renamed §11d stub-node backfill to §11e. Updated §11b: inferred client rows now use `is_confirmed_active_client = False` (not "possible"); note the Stage 4 `SameHostAs` edge that links them back to AD computer objects. |
| 2026-06-25 | Stage 3 shipped. Updated §11c: `graph_edges` is now four columns (`start_id`, `end_id`, `kind`, `collection_source VARCHAR[]`); `GraphEdge` sets both `traversable` and `collection_source`; dedup pass groups by `(start_id, end_id, kind)` and array-unions `collection_source` via `list_distinct(flatten(list(...)))`. Updated quick-reference table row. |
| 2026-06-23 | Stage 2 preproc/convert shipped. Added §11 documenting the four Stage 2 add-ons: `host_object_sid` on RemoteRegistry current-user rows; `collection_settings` one-row flag persistence; `_read_disable_possible` persist-at-collect/gate-in-preproc mechanism; `TRAVERSABLE_EDGE_KINDS` + generic `GraphEdge`; and the new divergence category **edge-endpoint stub-node backfill** (`node_backfill` + `StubNode`). Updated §9 status from "design stage" to "Stages 1–2 shipped". Updated quick-reference table. |
