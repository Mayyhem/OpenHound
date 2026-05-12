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
| `--ldap-port` | `SOURCES__SCCM__LDAP_PORT` | `--ldap-port` | 389 |
| `--ldaps` | `SOURCES__SCCM__USE_SSL` | `--ldaps` | false |
| `--ldap-start-tls` | `SOURCES__SCCM__LDAP_START_TLS` | `--ldap-start-tls` | false |
| `-ls`, `--ldap-signing` | `SOURCES__SCCM__LDAP_SIGNING` | `-ls / --ldap-signing` | `auto` |
| `-cb`, `--ldap-channel-binding` | `SOURCES__SCCM__LDAP_CHANNEL_BINDING` | `-cb / --ldap-channel-binding` | `auto` |

`--ldap-signing` and `--ldap-channel-binding` accept `auto` (default — retry
with NTLM sign-and-seal / CBT on `strongerAuthRequired`), `required` (always
on), or `disabled` (never use). With `auto`, plain-LDAP binds against DCs
that require signing succeed transparently after one re-bind. Channel
binding additionally requires LDAPS or `--ldap-start-tls`. ldap3 >= 2.10.2rc4
is required for these knobs to take effect.

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
| `-v`, `--verbose` | `OPENHOUND_LOG_LEVEL=DEBUG` | `-v / --verbose` | false |

### OpenHound-specific (no CMBP equivalent)

| Env var | Default | Notes |
|---|---|---|
| `SOURCES__SCCM__MSSQL_INTROSPECT` | false | Opt-in authenticated MSSQL TDS introspection. Off by default because impacket's TDS path can wedge against EPA-enforcing servers. |

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
