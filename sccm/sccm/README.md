# OpenHound SCCM Collector

<img width="256" height="384" alt="ConfigManBearPig" src="https://github.com/user-attachments/assets/f40c4268-431d-4dbc-9134-ed6d0e7309a0" />

The **OpenHound SCCM collector** brings SCCM (Microsoft Configuration Manager) attack paths into [BloodHound](https://github.com/SpecterOps/BloodHound) using [OpenGraph](https://specterops.io/opengraph). It is the [OpenHound](https://github.com/SpecterOps/openhound) port of [ConfigManBearPig](https://specterops.io/blog/2026/01/13/introducing-configmanbearpig-a-bloodhound-opengraph-collector-for-sccm/), the PowerShell SCCM collector by Chris Thompson ([@_Mayyhem](https://x.com/_Mayyhem)) at [SpecterOps](https://x.com/SpecterOps).

Where the PowerShell tool is a single self-contained script, this version runs on the OpenHound framework's three-stage pipeline (`collect` → `preprocess` → `convert`), producing an OpenGraph dataset you upload to BloodHound's **File Ingest**.

> ## 🚧 Work in progress
>
> This port is **mid-migration**. The collection side is broad, but the graph-emission side is just getting started. As of today:
>
> - **`collect`** runs LDAP / Local / DNS **discovery** plus two real **per-host** phases (**RemoteRegistry** and **MSSQL** EPA detection). The remaining per-host phases (AdminService, WMI, HTTP, SMB, DHCP) are accepted on the command line but are still **stubs**.
> - **`convert`** emits exactly **one** node kind today — [`SCCM_Site`](#node-reference) — and **no edges**. The derived-edge tables are already computed during `preprocess`, but the convert-time consumers that would turn them into graph edges haven't been wired up yet.
>
> This README documents **what the code actually does today**, not the finished design. For the full intended model, see the PowerShell tool's reference doc, [README-CMBP.md](README-CMBP.md).

Questions? Reach out on the [BloodHound Slack](http://ghst.ly/BHSlack) (@Mayyhem), on Twitter ([@_Mayyhem](https://x.com/_Mayyhem)), or open an issue.

---

# Table of Contents

- [Quick Start](#quick-start)
- [Collection Overview](#collection-overview)
- [System Requirements](#system-requirements)
- [Limitations](#limitations)
- [Command Line Options](#command-line-options)
- [Graph Model](#graph-model)
- [Node Reference](#node-reference)
  - [SCCM_Site](#sccm_site)
- [Edge Reference](#edge-reference)
- [Understanding the Codebase](#understanding-the-codebase)
- [Contributing](#contributing)

---

# Quick Start

The collector is an OpenHound extension. All commands run from this directory (`sccm/sccm/`) through [`uv`](https://docs.astral.sh/uv/), which manages the virtual environment and pulls in the OpenHound framework.

### 1. Install dependencies

```powershell
uv sync
```

This installs the runtime dependencies (`ldap3`, `impacket`, `dnspython`, and — on Windows — `pywin32` and `winkerberos`) plus the OpenHound framework itself, which provides the `openhound` CLI.

### 2. Collect

Run from a domain-joined Windows host as the current user (the domain and a domain controller are auto-detected):

```powershell
uv run openhound collect sccm .\out -vv
```

Or supply everything explicitly (required on Linux/macOS, where the current-user domain context can't be auto-detected):

```powershell
uv run openhound collect sccm .\out -d mayyhem.com --dc dc01.mayyhem.com -u "MAYYHEM\lowpriv" -p "Passw0rd!" -vv
```

Limit which per-host phases run, and which hosts they target:

```powershell
# Only check the PS1 site database server for Extended Protection for Authentication
uv run openhound collect sccm .\out -d mayyhem.com -m RemoteRegistry,MSSQL -c ps1-db.mayyhem.com -vv
```

`collect` writes raw JSONL tables under `.\out\sccm\<table>\` and prints a per-resource row-count summary plus the next commands to run.

### 3. Preprocess (build the lookup database)

```powershell
uv run openhound preprocess sccm .\out .\lookup.duckdb
```

This loads the raw JSONL into DuckDB and builds the lookup/derived tables that `convert` reads (site hierarchies, SID resolution, role mappings, and so on).

### 4. Convert (produce the OpenGraph dataset)

```powershell
uv run openhound convert sccm .\out\sccm .\graph --lookup-file .\lookup.duckdb
```

### 5. Upload to BloodHound

Upload the resulting OpenGraph output via the BloodHound UI under **Administration → File Ingest**. To query the SCCM kinds, BloodHound must use the **PostgreSQL** graph backend (the prebuilt SCCM kinds will not resolve on Neo4j): https://bloodhound.specterops.io/get-started/custom-installation#postgresql

> **Verbosity tip:** `-v` is the default INFO level (step summaries); `-vv` is the chattier VERBOSE level (per-resolution / per-node traces, matching the PowerShell tool's `[Verbose]` tier); `--debug` adds the framework's `dlt` and `ldap3` internals. Each run also writes an ordered, human-readable log (`collect_log_<timestamp>.log`) and a warnings/errors-with-tracebacks diagnostics file (`collect_diagnostics_<timestamp>.log`) into the output directory.

---

# Collection Overview

`collect` runs in two stages, defined in [`collect_sccm`](src/openhound_sccm/main.py) and [`source.py`](src/openhound_sccm/source.py).

```text
                       openhound collect sccm
                                │
        ┌───────────────────────┴───────────────────────┐
        │  Stage 1 — Discovery (runs once)               │
        │  LDAP · Local · DNS                            │
        │  → seeds the work queue with candidate hosts   │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        │  Stage 2 — Per-host phases (worker pool)       │
        │  RemoteRegistry · MSSQL  [· AdminService ...]  │
        │  gated by --collection-methods                 │
        │  loops as new hosts are discovered             │
        └───────────────────────┬───────────────────────┘
                                │
                      raw JSONL on disk
                                │
              preprocess  →  DuckDB lookup database
                                │
               convert  →  OpenGraph nodes (+ edges, planned)
```

## Stage 1 — Discovery (once-phases)

These resources run a single time per collection and seed the per-host work queue. They are not gated by `--collection-methods` in the current build.

| Discovery resource | What it does | Status |
|---|---|---|
| **LDAP** ([collectors/ldap.py](src/openhound_sccm/collectors/ldap.py)) | Queries the AD **System Management** container for SCCM **sites** (`mSSMSSite`), **management points** (`mSSMSManagementPoint`), the container **DACL**, network-boot servers, devices with the `CmRcService` SPN, and computers whose names/descriptions match SCCM naming patterns (`sccm`, `mecm`, `sms`, …). Registers discovered site systems as per-host targets. | ✅ Implemented |
| **Local** ([collectors/local.py](src/openhound_sccm/collectors/local.py)) | When run on an SCCM client: reads the `root\CCM` WMI namespace (`SMS_Authority`, `SMS_LookupMP`, `CCM_Client`) and parses CCM client logs to find management points / distribution points and the local client's SMSID. **Windows-only.** | ✅ Implemented (Windows) |
| **DNS** ([collectors/dns.py](src/openhound_sccm/collectors/dns.py)) | For each discovered site code, resolves the `_mssms_mp_<sitecode>._tcp.<domain>` SRV record (with an ADIDNS/LDAP fallback) to find management points published to DNS. | ✅ Implemented |

## Stage 2 — Per-host phases

Each discovered (or `--computers`-supplied) host runs through the ordered per-host phases in [`per_host_phases.py`](src/openhound_sccm/per_host_phases.py), concurrently across a worker pool (`--threads`). A phase only runs for a host when its name is enabled by `--collection-methods` (`method_enabled` in [context.py](src/openhound_sccm/context.py)).

| Phase | What it does | Status |
|---|---|---|
| **RemoteRegistry** ([collectors/registry.py](src/openhound_sccm/collectors/registry.py)) | Binds the remote registry over SMB (impacket `rrp`) to read SCCM keys under `HKLM\SOFTWARE\Microsoft\SMS` — site codes, component servers/roles, current users, and SQL/MSSQL settings. Retries the initial bind to absorb the RemoteRegistry trigger-start race. | ✅ Implemented |
| **MSSQL** ([collectors/mssql.py](src/openhound_sccm/collectors/mssql.py)) | Connects to the host's SQL Server (TCP/1433) and probes its **Extended Protection for Authentication (EPA)** enforcement using [clients/mssql_epa.py](src/openhound_sccm/clients/mssql_epa.py). | ✅ Implemented |
| **AdminService / WMI / HTTP / SMB / DHCP** | Accepted as `--collection-methods` tokens, but the per-host collectors are still **stubs** ([collectors/stubs.py](src/openhound_sccm/collectors/stubs.py)) pending per-phase follow-up work. | 🚧 Stub / not yet ported |

---

# System Requirements

**Host running the collector:**

- **Python 3.13 or 3.14** (`requires-python = ">=3.13,<3.15"`) and [`uv`](https://docs.astral.sh/uv/).
- The **OpenHound framework** (installed automatically via `uv sync`; pulled from `git+https://github.com/SpecterOps/openhound.git`).
- Network line of sight to a **domain controller** and to the SCCM systems you target.
- **Active Directory context.** On **Windows**, the domain and a domain controller are auto-detected from the current user's context (`USERDNSDOMAIN`, then a DNS SRV lookup). On **Linux/macOS** you must pass `-d/--domain` (and `-u`/`-p` for any phase that authenticates); `--dc` is still resolved via DNS SRV if omitted.
- **Windows-only features:** local WMI/log collection, and current-user integrated authentication (Kerberos via `winkerberos`, NTLM via SSPI/`pywin32`). On Linux, integrated auth needs `gssapi[kerberos]` installed separately; explicit credentials work everywhere.

**Privileges needed per phase:**

| Phase | Minimum privilege |
|---|---|
| LDAP / DNS discovery | Any authenticated domain user |
| RemoteRegistry | **Local administrator** on the target |
| MSSQL (EPA detection) | Any domain user can probe a reachable SQL Server; reading the setting via RemoteRegistry instead needs local admin on the DB host |

**BloodHound side:**

- BloodHound with **OpenGraph** support.
- A **PostgreSQL** graph backend, required for the custom SCCM kinds to resolve: https://bloodhound.specterops.io/get-started/custom-installation#postgresql

**A note on `uv` and Python on Windows:** [pyproject.toml](pyproject.toml) sets `python-preference = "only-system"`. uv-managed (`python-build-standalone`) builds ship a `libcrypto` without the `OPENSSL_Applink` cross-CRT shim, which aborts TLS handshakes mid-flight — so on Windows the collector deliberately prefers an official/system Python.

---

# Limitations

- **Graph output is minimal today.** `convert` emits only the [`SCCM_Site`](#node-reference) node and **no edges**. See the [WIP banner](#-work-in-progress) and the [Edge Reference](#edge-reference).
- **Most per-host phases are stubs.** Only RemoteRegistry and MSSQL collect real data; AdminService/WMI/HTTP/SMB/DHCP are placeholders.
- **Site code is used as the site identity.** A `SCCM_Site` node's id (and `environmentid`) is the **site code** ([models/sccm_site.py](src/openhound_sccm/models/sccm_site.py)). SCCM hierarchies have no globally unique id, so two distinct hierarchies that happen to reuse the same site code will **merge** in the graph, producing false positives. Microsoft recommends against reusing site codes within a forest: https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/install/prepare-to-install-sites#bkmk_sitecodes
- **EPA "Allowed" vs "Required" is indistinguishable under integrated auth.** When EPA is detected using the current Windows user (SSPI), Windows always emits the channel-binding and target-name AV pairs, so the collector cannot tell `Allowed` from `Required` and reports the literal `Allowed/Required`. Explicit-credential and pass-the-hash paths (via impacket) *can* distinguish them. See [clients/mssql_epa.py](src/openhound_sccm/clients/mssql_epa.py) and the EPA matrix harness described under [Understanding the Codebase](#understanding-the-codebase).
- **`extension.yaml` is boilerplate.** The `credentials`/`parameters` blocks in [extension.yaml](extension.yaml) are framework placeholders and are not yet wired to the collector's actual options — pass configuration via CLI flags or `SOURCES__SCCM__*` env vars instead.
- **CRED-2 (machine-account) flags are inert.** `--machine-name`, `--machine-pass`, `--client-name`, `--create-machine-account`, `--use-altauth`, and `--registration-sleep` are defined but not yet implemented (their help text says so).

---

# Command Line Options

The collector adds CMBP-style flags to the framework's `collect` command. Every flag also has an environment-variable equivalent (`SOURCES__SCCM__<NAME>`), and CLI flag values take precedence. Run `uv run openhound collect sccm --help` for the authoritative list.

```text
uv run openhound collect sccm <output_path> [resources...] [options]
```

`<output_path>` (positional, required) is the directory raw JSONL is written to. `resources...` (optional) limits collection to a subset of resource names.

### Connection

| Option | Description |
|---|---|
| `-d`, `--domain` | AD domain (e.g. `mayyhem.com`). Auto-detected from the Windows current-user context; **required** on Linux/macOS. |
| `--dc`, `--domain-controller` | DC hostname or IP. If omitted, resolved from the domain via DNS SRV (`_ldap._tcp.dc._msdcs.<domain>`). |
| `-u`, `--username` | `DOMAIN\user` for explicit authentication. Omit to use the current Windows user (integrated auth). |
| `-p`, `--password` | Password for explicit authentication. |
| `--ldap-port` | Pin the LDAP port. Omit to auto-detect (LDAPS:636 → StartTLS:389 → LDAP:389 with sign-and-seal). |

### Collection

| Option | Description |
|---|---|
| `-m`, `--collection-methods` | Comma-separated methods (see the table below). Default `All`. |
| `-c`, `--computers` | Comma-separated computer targets. |
| `--cf`, `--computer-file` | Path to a file of computer targets, one per line. |
| `--sms`, `--sms-provider` | A specific SMS Provider host *(consumed by the not-yet-ported AdminService/WMI phases)*. |
| `--sc`, `--site-codes` | Site codes for DNS collection (CSV or file path). |

**`--collection-methods` tokens** (case-insensitive; matched in [context.py](src/openhound_sccm/context.py)):

| Token | Status |
|---|---|
| `All` | Default — enables every phase |
| `LDAP`, `Local`, `DNS` | ✅ Discovery phases (Stage 1) |
| `RemoteRegistry`, `MSSQL` | ✅ Per-host phases (Stage 2) |
| `AdminService`, `WMI`, `HTTP`, `SMB`, `DHCP` | 🚧 Accepted but stubbed / not yet ported |

### Behavior

| Option | Description |
|---|---|
| `--disable-possible-edges` | Suppress uncertain/"possible" edges *(no effect yet — no edges are emitted)*. |
| `--enable-bad-opsec` | Enable noisy operations (e.g. NAA decryption) likely to trip EDR *(consumed by not-yet-ported phases)*. |
| `-t`, `--threads` | Per-host worker-pool size. Default `10`. |
| `--show-cleartext-passwords` | Display cleartext passwords when discovered *(consumed by not-yet-ported phases)*. |

### Machine account / CRED-2 — 🚧 not yet implemented

| Option | Description |
|---|---|
| `--machine-name` | `DOMAIN\MACHINE$` for SCCM client registration. |
| `--machine-pass` | Machine-account password. |
| `--client-name` | Client FQDN to register. |
| `--create-machine-account` | Create a machine account (`auto` or a name). |
| `--use-altauth` | Use the `ccm_system_altauth` endpoint. |
| `--registration-sleep` | Seconds to wait post-registration before the policy request. Default `10`. |

### Network

| Option | Description |
|---|---|
| `--socks-proxy` | SOCKS5 proxy `HOST:PORT` *(intended for DHCP/TFTP collection — not yet ported)*. |
| `--dns`, `--dns-resolver` | DNS nameserver IP used for all lookups (DC discovery, SRV probes). Omit to use the system default. |

### Output & logging

| Option | Description |
|---|---|
| `--progress` | Progress tracker: `tqdm` (default), `log`, or `alive_progress`. |
| `--tables` / `--columns` / `--data-type` | DLT schema contracts for new tables / unknown columns / type mismatches. |
| `-v`, `--verbose` | Repeatable. `-v` → INFO (step summaries), `-vv` → VERBOSE (per-resolution / per-node traces). |
| `--debug` | DEBUG level (very chatty; includes `dlt` and `ldap3` internals). |

---

# Graph Model

The collector follows OpenHound's standard three-phase pipeline:

| Phase | Command | Role |
|---|---|---|
| **collect** | `openhound collect sccm` | Talk to LDAP/SCCM/SQL/SMB and write raw JSONL tables. |
| **preprocess** | `openhound preprocess sccm` | Load the JSONL into DuckDB and build lookup + derived tables ([transforms.py](src/openhound_sccm/transforms.py), [lookup.py](src/openhound_sccm/lookup.py)). |
| **convert** | `openhound convert sccm` | Read the JSONL + DuckDB lookup and emit OpenGraph nodes/edges. |

**Node identity.** Every node carries a stable string id (`node_id`) and an `environmentid` tying it to its collected environment. For `SCCM_Site`, both are the **site code** (e.g. `PS1`). The common property/ID base classes live in [graph.py](src/openhound_sccm/graph.py) (`SCCMNode`, `SCCMNodeProperties`, `SCCMEdgeProperties`); node and edge kind strings live in [kinds/nodes.py](src/openhound_sccm/kinds/nodes.py) and [kinds/edges.py](src/openhound_sccm/kinds/edges.py).

**Kinds declared** (in [kinds/nodes.py](src/openhound_sccm/kinds/nodes.py)) — note these are the kind *constants* the project intends to use; only `SCCM_Site` is actually emitted today:

- AD-native: `Computer`, `User`, `Group`, `Base`
- SCCM: `SCCM_Site`, `SCCM_ClientDevice`, `SCCM_Collection`, `SCCM_AdminUser`, `SCCM_SecurityRole`
- MSSQL: `MSSQL_Server`, `MSSQL_Login`, `MSSQL_Database`, `MSSQL_DatabaseUser`, `MSSQL_ServerRole`, `MSSQL_DatabaseRole`

**Convert-time enrichment.** `SCCM_Site` is discovered from LDAP (`ldap_sites`), but many of its properties (display name, site server, SQL host/database/service account, version, hierarchy root, site-system roles, admin users, stored accounts) are filled in at convert time by joining against the DuckDB lookup tables — so a node's richness grows as more collection phases come online, without changing the model.

---

# Node Reference

> **Currently emitted: 1 node kind.** A `Computer` model exists in the tree ([models/computer.py](src/openhound_sccm/models/computer.py)) but is not yet registered for emission, so it is intentionally omitted here.

## SCCM_Site

A Configuration Manager **site**, discovered from the `mSSMSSite` objects in the AD System Management container and enriched at convert time. Model: [models/sccm_site.py](src/openhound_sccm/models/sccm_site.py).

- **Node id / `environmentid`:** the site code (e.g. `PS1`).
- **`name` / `displayname`:** the site code, or the human-readable display name when available.

| Property | Type | Description |
|---|---|---|
| `siteCode` | string | The site code (e.g. `PS1`). |
| `parentSiteCode` | string | Parent site in the hierarchy; the literal `"None"` for a root (CAS) site. |
| `rootSiteCode` | string | Hierarchy root site code (resolved from the lookup tables). |
| `siteType` | string | `Primary Site`, `Central Administration Site`, or `Secondary Site`. |
| `displayName` | string | Human-readable site name. |
| `distinguishedName` | string | LDAP DN of the `mSSMSSite` object. |
| `siteGuid` / `siteGUID` | string | Site GUID parsed from `mSSMSHealthState` (lowercase + CMBP uppercase spellings). |
| `sourceForest` | string | Source forest from `mSSMSSourceForest`. |
| `siteServerName` / `siteServerFQDN` | string | FQDN of the primary site server. |
| `siteServerDomainSID` | string | AD SID of the site server's computer account. |
| `SQLServerName` / `SQLServerFQDN` | string | FQDN of the MSSQL server hosting the site database. |
| `SQLDatabaseName` | string | Site database name (e.g. `CM_PS1`). |
| `SQLServerDomainSID` | string | AD SID of the SQL server's computer account. |
| `SQLServicePort` | string | SQL service port (emitted as `"1433"`). |
| `SQLServiceAccountName` | string | Bare sAMAccountName of the SQL service account (Secondary-site `LocalSystem` is mapped to the site server's `<HOST>$`). |
| `SQLServiceAccountDomainSID` | string | AD SID of the SQL service account. |
| `version` | string | Site version (e.g. `5.00.9106.1000`). |
| `buildNumber` | int | Build number parsed from `version` (e.g. `9106`). |
| `versionCVEs` | list\<string\> | Known CVEs for the version, from [cve_table.py](src/openhound_sccm/cve_table.py). |
| `installDir` | string | Site server install directory. |
| `siteSystemRoles` | list\<string\> | `RoleName@hostname` entries for site systems serving this site. |
| `adminUsers` | list\<string\> | Admin-user logon names assigned to this site. |
| `storedAccounts` | list\<string\> | Stored-account labels (`SMS_SCI_Reserved`) for this site. |
| `collectionSource` | list\<string\> | Collection sources that contributed to this node (e.g. `LDAP-mSSMSSite`). |
| `SCCMInfra` | bool | Always `true` for a site. |

---

# Edge Reference

> **Currently emitted: 0 edges.**

No edges are produced by `convert` yet. The only edge-kind constant declared today is `EX_MemberOf` ([kinds/edges.py](src/openhound_sccm/kinds/edges.py)), and nothing emits it.

This is a deliberate, visible gap in the port. The `preprocess` stage **already computes** derived-edge tables in DuckDB ([transforms.py](src/openhound_sccm/transforms.py) — e.g. site-hierarchy replication, `contains`, role assignments, coerce-and-relay, same-host-as), but the `convert`-time `models/derived/*` asset classes that would read those tables and yield graph edges have not been written yet. Until they are, the derived rows are materialized and then left unconsumed.

When edge emission lands, this section will document each edge kind, its source/target node kinds, and its properties — grounded in the asset classes that emit it.

---

# Understanding the Codebase

```text
sccm/sccm/
├── extension.yaml                # Extension metadata (name, authors, tags)
├── pyproject.toml                # Deps, Python version, entry point, dev tools
├── README.md                     # This file
├── README-CMBP.md                # Reference doc for the PowerShell predecessor
└── src/openhound_sccm/
    ├── main.py                   # CLI: collect/preprocess registration, logging, two-stage orchestration
    ├── source.py                 # DLT source, discovery resources, per-host emit resources
    ├── context.py                # SourceContext: targets, allow-list, caches, --collection-methods gating
    ├── per_host_phases.py        # The ordered Stage-2 phases and the tables each writes
    ├── graph.py                  # SCCMNode / SCCMNodeProperties / SCCMEdgeProperties base classes
    ├── cve_table.py              # SCCM version → CVE lookup
    ├── log_context.py            # [target][phase] log tagging, VERBOSE level, node/edge trace helpers
    ├── transforms.py             # DuckDB SQL transforms run during preprocess
    ├── lookup.py                 # Cached LookupManager queries used during convert
    ├── kinds/                    # Node + edge kind string constants
    ├── models/                   # @app.asset graph models (today: SCCMSite; plus raw-table placeholders)
    ├── collectors/               # ldap.py · dns.py · local.py · registry.py · mssql.py · stubs.py
    ├── clients/                  # ad.py (LDAP auth) · mssql_epa.py (EPA probe) · smb_sso.py (SMB SSPI)
    └── phased_pipeline/          # Reusable engine: work_queue.py · streams.py · engine.py
```

### Key concepts

- **Two-stage orchestration.** [main.py](src/openhound_sccm/main.py)'s `collect_sccm` runs discovery resources once (Stage 1), seeds a work queue, then drains it through a worker pool of per-host phases (Stage 2), streaming each table to disk as it's produced.
- **The phased pipeline** ([phased_pipeline/](src/openhound_sccm/phased_pipeline/)) is service-agnostic: a bounded-stream model (`streams.py`), a recursive work queue (`work_queue.py`), and an engine that runs phases per target with a `should_run` gate (`engine.py`).
- **Authentication** lives in [clients/ad.py](src/openhound_sccm/clients/ad.py): it auto-detects LDAP transport/signing (LDAPS → StartTLS → LDAP with sign-and-seal), supports explicit creds, NTLM, and current-user Kerberos/SSPI, and is careful not to increment `badPwdCount` on non-credential failures.
- **EPA detection** ([clients/mssql_epa.py](src/openhound_sccm/clients/mssql_epa.py)) infers Extended Protection enforcement by sending deliberately malformed NTLM channel/service bindings and observing how SQL Server reacts.
- **Convert enrichment** is driven by [lookup.py](src/openhound_sccm/lookup.py) (DuckDB-backed, cached) reading tables built by [transforms.py](src/openhound_sccm/transforms.py).

### Debug harnesses (lab use only)

These standalone scripts validate pieces of the collector against real infrastructure. They are developer tools, not part of the CLI:

- **`debug_epa_matrix.py`** — flips the SQL Server EPA-related registry settings through all 12 combinations, restarts the service, and verifies the EPA detector reports the right enforcement for each. Modifies a live lab SQL Server — see the in-script warning.
- **`debug_per_host.py`** — exercises the per-host pipeline (ordering, concurrency, recursion, termination) with stub phases.
- **`spike_smb_sso.py`** — validates the SMB SSPI Negotiate session-setup path.

### Project standards

This extension follows the rules in [AGENTS.md](AGENTS.md) and the [`.agents/`](.agents/) directory — the `.agents/standards/openhound.md` standards and the `openhound` skill's task references (`plan-collector`, `graph-schema`, `register-extension`, `source-collection`, `add-asset`, `preproc-lookup`, `validate-extension`).

---

# Contributing

1. **Read the standards first.** [.agents/standards/openhound.md](.agents/standards/openhound.md) for collector rules, [.agents/standards/workflow.md](.agents/standards/workflow.md) for the order of work, and the `openhound` skill references under [.agents/skills/openhound/](.agents/skills/openhound/).

2. **Use an isolated environment for validation** so you don't disturb the repo-local `.venv`:

   ```powershell
   $env:UV_PROJECT_ENVIRONMENT = "$env:TEMP\openhound-venv"; uv run pytest
   ```

3. **Run the checks.** The test suite lives in [tests/](tests/) (CLI parsing, AD auth warnings, the phased-pipeline engine/streams/work-queue, per-host wiring and log blocks, LDAP MP parsing, lookup/transform queries, SMB SSO, …), with one inline test beside the code it covers ([per_host_phases_test.py](src/openhound_sccm/per_host_phases_test.py)).

   ```powershell
   uv run pytest                       # tests
   uv run ruff check src tests         # lint
   uv run mypy src/openhound_sccm      # type-check
   ```

4. **Pre-commit hooks** ([.pre-commit-config.yaml](.pre-commit-config.yaml)) run `black` formatting plus YAML/JSON/whitespace/large-file checks:

   ```powershell
   uv run pre-commit run --all-files
   ```

5. **Replace a stub with a real collector** by following its follow-up ticket: implement the collector in [collectors/](src/openhound_sccm/collectors/), add a typed model under [models/](src/openhound_sccm/models/) (import it from `models/__init__.py` so its `@app.asset` actually registers), wire any new tables into the `preprocess` table map in [main.py](src/openhound_sccm/main.py), and validate against `.agents/skills/openhound/references/validate-extension.md` before finishing.

This collector documents **what the code does**, not what it will do — please keep the README honest as features land, marking anything in flight as such.
