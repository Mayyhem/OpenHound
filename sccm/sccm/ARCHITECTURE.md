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
- [Quick reference: which framework extension point each add-on uses](#quick-reference-which-framework-extension-point-each-add-on-uses)
- [Maintaining this document](#maintaining-this-document)

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

> **Status — design stage.** The previous preproc/convert layer (`graph.py`, `lookup.py`, `transforms.py`,
> `models/computer.py`, `models/sccm_site.py`) was **deleted** in commit `6af5cc0 "Delete preproc/convert
> data"` pending a rebuild. The chosen design is recorded in
> [`docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md`](docs/superpowers/specs/2026-06-16-sccm-preproc-convert-design.md)
> (authoritative) with rationale in the two proposals cited below. This section documents the
> **divergence and the design direction**, not yet-shipped code.

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

### Trade-offs

Convert2-Read-DB keeps each entity to a single emission — no duplicate-node disk cost and no dependence on BloodHound's
merge-by-id — at the price of `convert` carrying its **own** `dlt.pipeline` that reads DuckDB and re-shapes
nodes itself instead of using the stock JSONL reader. The exact DuckDB read-implementation (a custom
`@dlt.resource` over the open lookup connection vs. DLT's `sql_database` source) is **deferred to the
implementation plan**, where both are prototyped against the real `lookup.duckdb`. If Convert2-Read-DB proves
unworkable, the JSONL-writeback fallback above is the documented escape hatch.

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
