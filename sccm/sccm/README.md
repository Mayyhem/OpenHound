# OpenHound SCCM extension

OpenGraph collector for Microsoft Endpoint Configuration Manager (SCCM /
ConfigMgr). Ports the `sccm/ConfigManBearPig/python/` reference collector
(`configmanbearpig.py`, "CMBP") into the OpenHound DLT extension model with the
same per-edge-kind histogram on the three MAYYHEM lab users.

## Prerequisites

### Python 3.13 with working OpenSSL

This project pins to Python 3.13 (`.python-version`) and asks `uv` to prefer
**system / official Pythons** over uv-managed ones (`tool.uv.python-preference =
"only-system"` in `pyproject.toml`). Reason:

uv-managed Pythons on Windows ship with a `libcrypto-3-x64.dll` from the
`python-build-standalone` project that lacks the `OPENSSL_Applink` cross-CRT
shim. Any TLS handshake — `ssl.wrap_socket`, `requests`, `httpx`, even a stdlib
`urllib.request.urlopen` to an HTTPS URL — aborts the process with
`OPENSSL_Uplink: no OPENSSL_Applink`. Confirmed on uv-managed CPython 3.13.13
and 3.14.4.

The fix is to use a Python distribution whose OpenSSL has Applink baked in.
On Linux any system Python works (the bug doesn't exist). On Windows install
official python.org Python 3.13:

```pwsh
winget install --id Python.Python.3.13 --scope user
```

Then `uv sync` from this directory will pick that interpreter automatically
because of the `python-preference = "only-system"` setting.

### Optional: `just` task runner

The supplied `justfile` chains the four pipeline steps. Install with
`winget install Casey.Just` on Windows or your distro's package manager on
Linux. With a `.env` file present, `just sync && just all output/` is enough to
run a full collect → preprocess → convert → package cycle.

### Lab credentials

The three test users ship with these credentials in the MAYYHEM lab:
- `MAYYHEM\lowpriv` — password `password`
- `MAYYHEM\roanalyst` — password `password`
- `MAYYHEM\domainadmin` — password `password`

## Usage — three equivalent styles

The OpenHound `collect` / `preprocess` / `convert` subcommands for this
extension accept the **same CMBP-style `--flag` surface** that
`configmanbearpig.py` does. Every flag also has a matching `SOURCES__SCCM__*`
env var (autoloaded from `.env` when invoked via `just`).

### A. Cobra-style flags

```pwsh
uv run openhound collect    sccm output/ -d mayyhem.com -dc dc.mayyhem.com -u 'MAYYHEM\domainadmin' -p password -m LDAP,SMB,WMI
uv run openhound preprocess sccm output/ output/lookup.duckdb
uv run openhound convert    sccm output/sccm output/graph --lookup-file output/lookup.duckdb
uv run python -m openhound_sccm.main package --graph-dir output/graph --output-dir output
```

### B. Env vars (`.env` + `just`)

```pwsh
cp .env.example .env       # tweak the values
just all output/           # runs collect → preprocess → convert → package
```

### C. Mixed (flags override env)

```pwsh
SOURCES__SCCM__DOMAIN=mayyhem.com just collect output/ -u 'MAYYHEM\lowpriv' -p password
```

All three produce a `output/bloodhound-sccm-<ts>.zip` matching CMBP's 5-file
layout (`computers.json` / `groups.json` / `users.json` / `sccm.json` /
`seed_data.json`).

> ⚠️ **`preprocess` must run between `collect` and `convert`.** Every model in
> this collector uses `self._lookup` to resolve cross-table data (SIDs, hierarchy
> roots, role aggregations, etc.). Running `convert` against a missing or stale
> lookup DB silently produces partial / empty graphs. The `just all` recipe and
> the four-step usage examples above already chain them in the right order; only
> skip `preprocess` if you have a reason and know what you're losing.

## CLI reference

Every flag below works on `uv run openhound collect sccm <output>/ …` (it's the
phase that consumes them; downstream phases inherit via env vars). See
`.env.example` for the env-var form and `configmanbearpig.py:89-258` for the
CMBP flag reference.

### Connection

| Flag | Env var | CMBP equivalent | Default |
|---|---|---|---|
| `-d`, `--domain` | `SOURCES__SCCM__DOMAIN` | `-d / --domain` | *(required)* |
| `-dc`, `--domain-controller` | `SOURCES__SCCM__DOMAIN_CONTROLLER` | `-dc / --domain-controller` | *(required)* |
| `-u`, `--username` | `SOURCES__SCCM__USERNAME` | `-u / --username` | current Kerberos session |
| `-p`, `--password` | `SOURCES__SCCM__PASSWORD` | `-p / --password` | — |
| `--ldap-port` | `SOURCES__SCCM__LDAP_PORT` | `--ldap-port` | *(auto)* |

LDAP transport (LDAPS / StartTLS / plain) and hardening (NTLM signing,
channel binding) are **auto-detected at bind time** — there are no
`--ldaps` / `--ldap-start-tls` / `--ldap-signing` / `--ldap-channel-binding`
knobs. `ADClient.bind()` walks profiles in this order:

1. LDAPS:636 + CBT *(when NTLM credentials are supplied)*
2. StartTLS:389 + CBT *(when NTLM credentials are supplied)*
3. LDAP:389 + NTLM sign / seal *(when NTLM credentials are supplied)*
4. Plain LDAPS:636 or LDAP:389 *(anonymous / SASL fallback)*

The walk is **lockout-safe**: only AD's credential-class `invalidCredentials`
sub-codes (`data 52e/532/533/701/773/775` — bad password, expired, disabled,
locked) propagate immediately. Protocol-level rejections (`strongerAuthRequired`,
CBT mismatch `data 80090346`, TLS / connect errors) happen *before* the
password is validated, so falling through to the next profile never advances
`badPwdCount` of a real account. ldap3 >= 2.10.2rc4 is required for signing
and CBT support; the dependency floor in `pyproject.toml` enforces this.

Pin `--ldap-port` only when 636 / 389 isn't appropriate (Global Catalog
port 3269, custom firewall mapping, etc.). 636 / 3269 → LDAPS profile; any
other value → LDAP profile chain.

### Collection

| Flag | Env var | CMBP equivalent | Default |
|---|---|---|---|
| `-m`, `--collection-methods` | `SOURCES__SCCM__COLLECTION_METHODS` | `-m / --collection-methods` | `All` |
| `-c`, `--computers` | `SOURCES__SCCM__COMPUTERS` | `-c / --computers` | — |
| `-cf`, `--computer-file` | `SOURCES__SCCM__COMPUTER_FILE` | `-cf / --computer-file` | — |
| `-sms`, `--sms-provider` | `SOURCES__SCCM__SMS_PROVIDER` | `-sms / --sms-provider` | — |
| `-sc`, `--site-codes` | `SOURCES__SCCM__SITE_CODES` | `-sc / --site-codes` | — |

`-m` is a comma-separated include-list of method names: `All` (the default),
`LDAP`, `Local`, `DNS`, `DHCP`, `RemoteRegistry`, `MSSQL`, `AdminService`,
`WMI`, `HTTP`, `SMB`. **This replaces the older `OPENHOUND_SCCM_DISABLE_*` env
vars completely — they no longer have any effect.**

### Behaviour flags

| Flag | Env var | CMBP equivalent | Default | Notes |
|---|---|---|---|---|
| `--disable-possible-edges` | `SOURCES__SCCM__DISABLE_POSSIBLE_EDGES` | `--disable-possible-edges` | false | Suppresses edges tagged `is_possible=True` in the derived aggregator. |
| `--enable-bad-opsec` | `SOURCES__SCCM__ENABLE_BAD_OPSEC` | `--enable-bad-opsec` | false | Surface-only today: gates downstream NAA decryption / cleartext-secret paths once those resources are no longer stubs. |
| `-t`, `--threads` | `SOURCES__SCCM__THREADS` | `-t / --threads` | 1 | Accepted; per-host phase parallelism is sequential today. |
| `--show-cleartext-passwords` | `SOURCES__SCCM__SHOW_CLEARTEXT_PASSWORDS` | `--show-cleartext-passwords` | false | Surface-only today: pairs with `--enable-bad-opsec`. |

### Network

| Flag | Env var | CMBP equivalent | Default | Notes |
|---|---|---|---|---|
| `--socks-proxy` | `SOURCES__SCCM__SOCKS_PROXY` | `--socks-proxy` | — | Wired onto `ctx.socks_proxy`; consumed by DHCP / TFTP paths as the live CRED-1 PXE chain comes online. |

### Machine Account / CRED-2

All six CMBP CRED-2 flags are accepted today but **the CRED-2 chain is not yet
implemented in OpenHound** (no SCCM-client-registration → policy-request → NAA
decryption code path). Setting these values has no observable effect on the
emitted graph until that work lands.

| Flag | Env var | CMBP equivalent |
|---|---|---|
| `--machine-name` | `SOURCES__SCCM__MACHINE_NAME` | `--machine-name` |
| `--machine-pass` | `SOURCES__SCCM__MACHINE_PASS` | `--machine-pass` |
| `--client-name` | `SOURCES__SCCM__CLIENT_NAME` | `--client-name` |
| `--create-machine-account` | `SOURCES__SCCM__CREATE_MACHINE_ACCOUNT` | `--create-machine-account` |
| `--use-altauth` | `SOURCES__SCCM__USE_ALTAUTH` | `--use-altauth` |
| `--registration-sleep` | `SOURCES__SCCM__REGISTRATION_SLEEP` | `--registration-sleep` |

### General

| Flag | Env var | CMBP equivalent | Default |
|---|---|---|---|
| `-v`, `--verbose` | `RUNTIME__LOG_LEVEL=DEBUG` + `RUNTIME__LOG_CLI_LEVEL=DEBUG` | `-v / --verbose` | false |

### Framework arguments (inherited from `openhound`)

Each pipeline subcommand still accepts the framework's standard arguments:
positional `output_path` / `input_path`, `--progress {tqdm|log|alive_progress}`,
and (on `collect`) `--tables` / `--columns` / `--data-type` for DLT contract
mode selection.

## Architecture lessons learned

- **Cobra-style flags on framework subcommands are possible from inside an
  extension.** The `@app.collect()` / `@app.preproc()` / `@app.convert()`
  decorators are just convenience wrappers around `openhound.cli.{collect,
  preproc, convert}.command(name=…)`. Bypassing them and registering directly
  lets you add a richer Typer signature without touching framework code.
- **Don't use uv-managed Pythons on Windows for TLS-heavy code.** The
  `python-build-standalone` OpenSSL build is broken in a way that surfaces only
  at TLS handshake time, with no actionable Python-side traceback. Force
  `python-preference = "only-system"` so `uv` picks python.org Pythons.
- **AdminService curl shell-out is unnecessary** if the Python runtime is
  healthy. Use `requests` plus a `pyspnego`-backed `HttpNegotiateAuth`
  handler (`clients/adminservice.py`) for SPNEGO/Kerberos with explicit
  credentials. That gives true per-user differentiation without
  `runas /netonly`.
- **Per-user ZIP differentiation is real.** Lowpriv produces 14 files in
  `output/sccm/` (LDAP + DNS + SMB + LDAP-CmRcService ClientDevice synthesis);
  domainadmin produces 28 (full AdminService + WMI + registry + MSSQL).
- **CMBP's `SCCM_ClientDevice` synthesis from CmRcService SPN matches** is
  load-bearing. Without it, lowpriv's graph has no clients at all because
  AdminService 401s. `_synthesised_cmrc_client_devices()` mirrors CMBP's
  LDAP-CmRcService path.
- **Some `SCCM_HasClient` edges in CMBP are duplicates** (one per discovery
  path: AdminService cross-product + LDAP-CmRcService). OpenHound's edge
  packager dedupes by `(start, end, kind, collectionSource)`, which preserves
  the right count by treating distinct discovery paths as distinct edges.

## Deviations from `.agents/standards/openhound.md`

The agent standards under `.agents/standards/openhound.md` describe the
"skeleton" collector shape (one `source.py`, one `graph.py`, one `lookup.py`,
…). This collector is larger than the skeleton anticipates because it has to
match CMBP's enumeration surface end-to-end. The deviations below are
intentional; do not "fix" them back to the skeleton without reading the
rationale first.

- **`src/openhound_sccm/collectors/`** — per-protocol resource modules. CMBP
  enumerates via 11 protocols (LDAP, Local, DNS, DHCP, RemoteRegistry, MSSQL,
  AdminService, WMI, HTTP, SMB, derived). Inlining all of them into one
  `source.py` would create a ~3,000-line module. The `@app.resource` decorators
  still register on the single `app` instance from `main.py`; `source.py`
  re-imports them so DLT sees the same module-level registrations as the
  skeleton pattern.
- **`src/openhound_sccm/clients/`** — protocol clients (`ad.py` for LDAP with
  NTLM signing / channel binding, `adminservice.py` for SPNEGO-over-HTTPS,
  `sccm.py` for the SMS Provider DCOM surface, `sccm_crypto.py` for NAA secret
  decryption, etc.). These are load-bearing for CMBP parity and don't belong in
  `source.py`.
- **`src/openhound_sccm/context.py`** — `SourceContext` wraps the authenticated
  AD client plus the full CMBP-equivalent CLI knob surface. The skeleton's
  `SourceContext` only carries a `RESTClient`; SCCM needs much more.
- **`src/openhound_sccm/cve_table.py`** — static version → CVE lookup for SCCM
  site versions (used by `SCCMSite.as_node` to populate `versionCVEs`). A
  small Python dict is cleaner than threading another DuckDB table through
  preproc.
- **`src/openhound_sccm/log_context.py`** — phase / target log-prefix filter so
  the multi-threaded per-host collection output is readable.
- **`src/openhound_sccm/output.py`** — post-convert BloodHound ZIP packaging
  exposed as a `package` Typer subcommand. The framework has no post-convert
  hook for this.
- **Direct Typer-group registration in `main.py`** (`app.collector =
  collect_sccm`, etc.) instead of the `@app.collect()` / `@app.preproc()` /
  `@app.convert()` decorators. Needed so the CMBP-equivalent `-d` / `-dc` /
  `-u` / `-p` / `-m` / ... flag surface can sit on the framework's public Typer
  groups. The convenience decorators don't expose a way to add arbitrary Typer
  arguments. (See [`main.py:51-57`](src/openhound_sccm/main.py#L51-L57) for the
  inline rationale.)
- **Dual-root `environmentid`.** The skeleton expects every collected node to
  share one environment root, but this collector co-collects nodes whose
  *kinds* are owned by other extensions. AD-namespace kinds
  (`Computer` / `User` / `Group` / `Base`) carry `environmentid=self.domain`
  because they belong to the AD environment, not SCCM's. SCCM-namespace kinds
  set `environmentid=self.site_code` (currently still `self.domain` on several
  nodes pending follow-up — see below). MSSQL-namespace kinds belong under the
  MSSQL extension's root (server `host:port`) — also pending follow-up.

### Known follow-ups on the dual-root work

`environmentid` currently defaults to `self.domain or None` on most non-`SCCMSite`
nodes (e.g. [`sccm_admin_user.py`](src/openhound_sccm/models/sccm_admin_user.py),
[`sccm_collection.py`](src/openhound_sccm/models/sccm_collection.py), and the
`mssql_*` family). The semantically correct values are:

- `SCCMAdminUser` / `SCCMClientDevice` / `SCCMCollection` / `SCCMSecurityRole` →
  `self.site_code` (these are SCCM-namespace kinds; `SCCM_Site` is their
  environment per CMBP's `schema.json`).
- `MSSQLServer` / `MSSQLLogin` / `MSSQLDatabase` / `MSSQLDatabaseRole` /
  `MSSQLDatabaseUser` / `MSSQLServerRole` → the MSSQL server identifier (e.g.
  `host:1433`), or whatever the MSSQL extension defines as its environment root.

CMBP does not emit `environmentid`, so there is no parity baseline to match;
the change is unverifiable from `tests/test_parity.py` alone and needs an
end-to-end smoke against a BloodHound-with-OpenGraph deployment before
landing.

### Known follow-up: collect-time same-table writeback

[`collectors/adminservice.py::ldap_sites_admin_extra`](src/openhound_sccm/collectors/adminservice.py)
and [`collectors/smb.py::ldap_sites_smb_extra`](src/openhound_sccm/collectors/smb.py)
both use DLT's `table_name="ldap_sites"` override to write back into the
`ldap_sites` JSONL table at collect time, sharing a Python `seen_codes` set
across resources for dedup. The agent standards
(`.agents/skills/openhound/references/source-collection.md`) want collect to
write raw per-source JSONL only; cross-source merges belong in preproc SQL.

Unwinding this requires either (a) triple-binding the `SCCMSite` Pydantic
model to three separate tables (DLT semantics for this aren't documented), or
(b) building a `DerivedSite` aggregator that emits `SCCMSite` nodes from a
preproc-built `sccm.sites_union` view (parallel to the existing
`DerivedNode` pattern in
[`models/derived/derived_node.py`](src/openhound_sccm/models/derived/derived_node.py)).
The current pattern works correctly and is bit-identical to CMBP, but the
parity tests don't cover the AdminService-only or SMB-only site paths, so any
refactor here needs end-to-end smoke against a live SCCM lab. Deferred.

### Known follow-up: remaining per-site lookups

[`SCCMLookup.extra_collection_sources_for_site`](src/openhound_sccm/lookup.py),
[`admin_enrichment_for_site`](src/openhound_sccm/lookup.py),
[`stored_account_labels_for_site`](src/openhound_sccm/lookup.py), and
[`admin_user_logon_names_for_site`](src/openhound_sccm/lookup.py) still do
multi-table joins or 7-table probes per call. Each is `@lru_cache`-decorated
so the cost is paid once per unique `site_code`, making the per-call
amortised cost small. If a future profile shows convert-phase site-emission
spending real time in these methods, lift each into a precomputed
`sccm.site_*_by_site` view following the pattern set by
[`sccm.computer_sccm_infra` / `host_site_system_roles` / `ad_principals`](src/openhound_sccm/transforms.py)
(see `_build_computer_sccm_infra` et al. and the corresponding lookup
rewrites for the indexed `WHERE ... = ?` shape).

## Parity status (2026-05-06)

Per-user totals against CMBP (full AdminService, python.org Python 3.13):

| User | OH (v12) | CMBP | Nodes | Edges | Edge kinds |
|---|---|---|---|---|---|
| domainadmin | 143 / 478 / 36 | 143 / 478 / 36 | **100%** | **100%** | **36/36** ✓ |
| lowpriv     |  31 /  85 / 35 |  31 /  85 / 35 | **100%** | **100%** | **35/35** ✓ |
| roanalyst   | 143 / 469 / 36 | 143 / 469 / 36 | **100%** | **100%** | **36/36** ✓ |

All three users hit **bit-identical parity** with CMBP (totals AND per-edge-kind
histogram) when the same defaults are used.

See `sccm/HANDOFF.md` for the multi-session implementation history and the
diagnoses that led to true parity.

## Running parity tests

Two layers cover parity regressions:

### 1. In-CI unit tests (`tests/test_parity.py`)

Nineteen tests cover three plumbing layers — node-property surface, lookup
methods (in-memory DuckDB), and edge-aggregator emission. Run from this
directory:

```pwsh
uv run pytest tests/test_parity.py -v
```

The suite includes regression guards that fail CI if a future change drops a
``collection_source`` column, renames a CMBP-canonical field, or changes the
``traversable``/``SCCMInfra`` hints away from PS1's choices.

### 2. Three-way live diff (`utils/compare_nodes_and_edges.py`)

For full property-level parity validation against PowerShell `ConfigManBearPig.ps1`
and Python CMBP, run all three collectors against the same lab with
**possible/inferred edges disabled** on each side so only directly-observed data
is compared:

```pwsh
# OpenHound (this extension)
$env:SOURCES__SCCM__USERNAME='MAYYHEM\domainadmin'
$env:SOURCES__SCCM__PASSWORD='password'
$env:SOURCES__SCCM__DOMAIN='mayyhem.com'
$env:SOURCES__SCCM__DISABLE_POSSIBLE_EDGES='1'
uv run openhound collect sccm output/parity_da
uv run openhound preprocess sccm output/parity_da output/parity_da/lookup.duckdb
uv run openhound convert sccm output/parity_da/sccm output/parity_da/graph --lookup-file output/parity_da/lookup.duckdb
uv run python -m openhound_sccm.main --graph-dir output/parity_da/graph --output-dir output/parity_da

# PowerShell CMBP (source of truth) — run from a fresh dir so the zip lands
# in the cwd. The script's -ZipDir flag has a quirk that uses the value as
# the full file path; running from a fresh dir avoids it.
$work = 'C:\Users\domainadmin\Desktop\OpenHound\sccm\ConfigManBearPig\powershell_deprecated\parity_ps1_run'
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force -Path $work | Out-Null
Set-Location $work
..\ConfigManBearPig.ps1 -Domain mayyhem.com -DisablePossibleEdges -OutputFormat Zip -LogFile run.log -CollectionMethods All

# Python CMBP (cross-check)
cd C:\Users\domainadmin\Desktop\OpenHound\sccm\ConfigManBearPig\python
uv run configmanbearpig.py -d mayyhem.com -u 'MAYYHEM\domainadmin' -p password --disable-possible-edges -m All -o parity_py --log-file parity_py/run.log
```

Then compare. The compare script handles raw JSON and zip-bundled output, and
honours `--baseline PS1` to focus the diff on properties PS1 has that OH lacks
(suppresses OH-only extras):

```pwsh
cd C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm
uv run python utils/compare_nodes_and_edges.py `
    output/parity_da/bloodhound-sccm-*.zip `
    ../ConfigManBearPig/powershell_deprecated/parity_ps1_run/bloodhound-sccm-*.zip `
    --label1 OH --label2 PS1 --baseline PS1 `
    --normalize-ids `
    --kinds SCCM_Site,Computer,SCCM_AdminUser,SCCM_SecurityRole,SCCM_Collection,MSSQL_Database `
    -v
```

The script reports node counts per kind, "only in OH" / "only in PS1" / "in
both" partitions, per-property diffs on matching nodes, and a per-edge-kind
property-difference summary. Useful flags:

- `--baseline <label>` — only show properties the baseline has that the other
  side lacks, plus value differences. Suppresses non-baseline extras.
- `--kinds A,B,C` — restrict the comparison to specific node kinds.
- `--normalize-ids` — match nodes by `(kinds, name)` when SIDs differ between
  collectors (CMBP sometimes uses hostnames, OH always uses SIDs).
- `--dedup` — collapse multiple edges with the same `(start, end, kind)` to a
  single edge before comparing properties.

Parity is achieved when the per-kind / per-property diff for each in-scope kind
shows zero "only-in-baseline" entries.


### 3. Unit test harness (`tests/invoke_configmanbearpig_unit_tests.py`)

The integration harness runs any of the three collectors (PowerShell,
ConfigManBearPig Python, or this OpenHound extension), tests the resulting
OpenGraph output against
[`tests/unit_test_expectations.py`](tests/unit_test_expectations.py)'s 116
edge assertions, and produces a cross-collector comparison. Run from this
directory:

```pwsh
uv run python tests\invoke_configmanbearpig_unit_tests.py --help
```

Run a single collector and assert the expected-edge set:

```pwsh
uv run python tests\invoke_configmanbearpig_unit_tests.py `
  --collector openhound `
  --domain mayyhem.com --domain-controller 10.2.10.100 `
  --username 'MAYYHEM\domainadmin' --password password `
  --output-dir output\test-da
```

Run **all three** collectors in one pass and assert that node totals, edge
totals, per-edge-kind histograms, and canonical node/edge signatures match
across them. Use `--verbose` to also assert console-log parity across the three
verbose transcripts:

```pwsh
uv run python tests\invoke_configmanbearpig_unit_tests.py `
  --all-collectors `
  --domain mayyhem.com --domain-controller 10.2.10.100 `
  --username 'MAYYHEM\domainadmin' --password password `
  --output-dir output\sweep\domainadmin `
  --log-file output\sweep\domainadmin\sweep.log `
  --disable-possible-edges `
  --signature-compare `
  --console-diff `
  --verbose
```

Flags worth knowing:

- `--all-collectors` — run PowerShell, CMBP Python, and OpenHound, then
  cross-compare their outputs.
- `--signature-compare` — diff canonical node and edge signatures (not just
  totals + histograms). Mismatches are grouped per node/edge kind and
  deterministically sorted, with no truncation.
- `-v` / `--verbose` — propagate `-v` / `-Verbose` to every collector
  invocation and tee each collector's console output to
  `<output-dir>/<collector>/console_<collector>.log`.
- `--console-diff` — after the sweep completes, normalize timestamps /
  paths / progress bars and diff the three per-collector verbose transcripts
  to surface intent drift. Requires `--verbose`.
- `--disable-possible-edges` — passes the same flag through to each
  collector. Use this while triaging deterministic-edge drift, then re-run
  without it to confirm the possible-edge surface is also at parity.
- `--limit-edge-type <Kind>` — restrict the expected-edge assertions to
  one edge kind, for tight triage loops.
- `--skip-edge-tests` — skip the expected-edge assertions; only print
  node / edge totals and per-kind histograms.
- `--compare name=path` (repeatable) — load an extra OpenGraph ZIP / JSON /
  directory under *name* and include it in the cross-collector comparison.

Outputs land under `output/` (gitignored via the top-level `.gitignore`
`output*` glob).

Test an existing OpenGraph directory or ZIP without re-running collection:

```pwsh
uv run python tests\invoke_configmanbearpig_unit_tests.py --input-path output\sweep\domainadmin\openhound\domainadmin\graph
uv run python tests\invoke_configmanbearpig_unit_tests.py --input-path output\sweep\domainadmin\configmanbearpig-python\bloodhound-sccm-<timestamp>.zip
```
