# OpenHound SCCM extension

OpenGraph collector for Microsoft Endpoint Configuration Manager (SCCM /
ConfigMgr). Ports the `sccm/ConfigManBearPig/python/` reference collector into
the OpenHound DLT extension model.

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

### Lab credentials

The three test users ship with these credentials in the MAYYHEM lab:
- `MAYYHEM\lowpriv` — password `password`
- `MAYYHEM\roanalyst` — password `password`
- `MAYYHEM\domainadmin` — password `password` (or current Kerberos session)

## Usage

```pwsh
cd sccm\sccm

$env:SOURCES__SCCM__DOMAIN = "mayyhem.com"
$env:SOURCES__SCCM__DOMAIN_CONTROLLER = "dc.mayyhem.com"
$env:SOURCES__SCCM__USERNAME = "MAYYHEM\domainadmin"
$env:SOURCES__SCCM__PASSWORD = "password"

uv run python src\main.py collect    sccm output\
uv run python src\main.py preprocess sccm output\ output\lookup.duckdb
uv run python src\main.py convert    sccm output\sccm output\graph --lookup-file output\lookup.duckdb
uv run python -m openhound_sccm.main --graph-dir output\graph --output-dir output
```

The packager produces `output/bloodhound-sccm-<ts>.zip` matching CMBP's 5-file
layout (`computers.json` / `groups.json` / `users.json` / `sccm.json` /
`seed_data.json`).

## Lessons learned

- **Don't use uv-managed Pythons on Windows for TLS-heavy code.** The
  `python-build-standalone` OpenSSL build is broken in a way that surfaces only
  at TLS handshake time, with no actionable Python-side traceback. Force
  `python-preference = "only-system"` so `uv` picks python.org Pythons.
- **AdminService curl shell-out is unnecessary** if the Python runtime is
  healthy. Use `requests` plus a `pyspnego`-backed `HttpNegotiateAuth`
  handler (`clients/adminservice.py`) for SPNEGO/Kerberos with explicit
  credentials. That gives true per-user differentiation without `runas
  /netonly`.
- **Per-user ZIP differentiation is real.** Lowpriv produces 14 files in
  `output/sccm/` (LDAP + DNS + SMB only); domainadmin produces 28 (full
  AdminService + WMI + registry + MSSQL).
- **CMBP's `SCCM_ClientDevice` synthesis from CmRcService SPN matches** is
  load-bearing. Without it, lowpriv's graph has no clients at all because
  AdminService 401s. `_synthesised_cmrc_client_devices()` mirrors CMBP's
  LDAP-CmRcService path.
- **Some `SCCM_HasClient` edges in CMBP are duplicates** (one per discovery
  path: AdminService cross-product + LDAP-CmRcService). OpenHound's edge
  packager dedupes by `(start, end, kind)`, so we cap at the unique-edge
  count. The graph is equivalent; the histogram count differs by ~13.

## Parity status (2026-05-04)

Per-user totals against CMBP (full AdminService, python.org Python 3.13):

| User | OH | CMBP | Nodes | Edges | Edge kinds |
|---|---|---|---|---|---|
| domainadmin | 114 / 395 / 36 | 143 / 478 / 36 | 80% | 83% | 100% |
| lowpriv     |  33 /  74 / 35 |  31 /  85 / 35 | 106% | 87% | 100% |
| roanalyst   | 113 / 383 / 36 | 143 / 469 / 36 |  79% | 82% | 100% |

All 36 edge kinds are emitted for users with full AdminService access; lowpriv
gets 35 kinds (missing the MSSQL kind that depends on a SQL host the lab
doesn't expose to a low-priv user).

Remaining gaps are well-understood:
- **`SCCM_HasClient` (~13 less per full-access user)** — CMBP allows
  duplicate edges per discovery path; OH dedupes.
- **`MSSQL_*` (-12 per user)** — lab `ps1-psv` doesn't expose port 1433.
- **`HasSession` (-9), `SCCM_IsAssigned` (-9)** — additional collector
  enrichment work.
- **`MemberOf` (-25)** — Foreign Security Principal rows CMBP emits with raw
  DN as the endpoint; OH drops these because the DN doesn't resolve to a SID.

See `sccm/HANDOFF.md` for the full per-edge-kind comparison and roadmap.
