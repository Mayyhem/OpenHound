# OpenHound SCCM Collector

<img width="256" height="384" alt="ConfigManBearPig" src="https://github.com/user-attachments/assets/f40c4268-431d-4dbc-9134-ed6d0e7309a0" />

The **OpenHound SCCM collector** brings SCCM (Microsoft Configuration Manager) attack paths into [BloodHound](https://github.com/SpecterOps/BloodHound) using [OpenGraph](https://specterops.io/opengraph). It is the [OpenHound](https://github.com/SpecterOps/openhound) port of [ConfigManBearPig](https://specterops.io/blog/2026/01/13/introducing-configmanbearpig-a-bloodhound-opengraph-collector-for-sccm/), the PowerShell SCCM collector by Chris Thompson ([@_Mayyhem](https://x.com/_Mayyhem)) at [SpecterOps](https://x.com/SpecterOps).

Where the PowerShell tool is a single self-contained script, this version runs on the OpenHound framework's three-stage pipeline (`collect` → `preprocess` → `convert`), producing an OpenGraph dataset you upload to BloodHound's **File Ingest**.

> ## 🚧 Work in progress
>
> This port is **mid-migration**. The collection side is broad, but the graph-emission side is just getting started. As of today:
>
> - **`collect`** runs LDAP / Local / DNS **discovery** plus six real **per-host** phases — **RemoteRegistry**, **MSSQL** EPA detection, **AdminService**, **WMI** (the AdminService fallback), **HTTP** (unauthenticated site-system role probing), and **SMB** (signing check + SCCM share-role enumeration). AdminService, WMI, HTTP, and SMB are **collect-only** (raw `adminservice_*` / `wmi_*` / `http_*` / `smb_*` tables; graph conversion is a later phase). **DHCP** is accepted on the command line but not yet ported.
> - **`convert`** emits four node kinds — [`Computer`](#computer), [`User`](#user), [`Group`](#group), and [`SCCM_Site`](#sccm_site) — and one edge kind: [`SCCM_AdminsReplicatedTo`](#sccm_adminsreplicatedto).
>
> This README documents **what the code actually does today**, not the finished design. For the full intended model, see the PowerShell tool's reference doc, [README-CMBP.md](README-CMBP.md).

Questions? Reach out on the [BloodHound Slack](http://ghst.ly/BHSlack) (@Mayyhem), on Twitter ([@_Mayyhem](https://x.com/_Mayyhem)), or open an issue.

---

# Table of Contents

- [Quick Start](#quick-start)
- [Collection Overview](#collection-overview)
- [System Requirements](#system-requirements)
- [Assumptions](#assumptions)
- [Limitations](#limitations)
- [Command Line Options](#command-line-options)
- [Graph Model](#graph-model)
- [Node Reference](#node-reference)
  - [Computer](#computer)
  - [User](#user)
  - [Group](#group)
  - [SCCM_Site](#sccm_site)
- [Edge Reference](#edge-reference)
  - [SCCM_AdminsReplicatedTo](#sccm_adminsreplicatedto)
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
| **AdminService** ([collectors/privileged.py](src/openhound_sccm/collectors/privileged.py)) | Queries the SCCM AdminService REST API (`https://<provider>/AdminService/wmi/...`) over Negotiate and collects the site hierarchy, site definitions, reserved accounts, devices, users, **security groups** (`SMS_R_UserGroup` — each group's name *and* SID, used to resolve `SecurityGroupName` memberships to Group nodes offline), collections, security roles, admins, and site-system roles into raw `adminservice_*` tables. Collect-only (graph conversion is a later phase). | ✅ Implemented (collect-only) |
| **WMI** ([collectors/privileged.py](src/openhound_sccm/collectors/privileged.py)) | **Fallback for AdminService.** Shares the *same* collection helpers as the AdminService phase (one set, parameterized per transport in `privileged.py`); when AdminService is unreachable on a host, it reads the same SMS Provider classes directly in the `root\SMS\site_<code>` WMI namespace (over DCOM via impacket, or pywin32 for the current Windows user) and writes the matching `wmi_*` tables. Runs only on hosts AdminService did **not** already collect — gated by `should_run_phase` reading `TargetEntry.completed_phases`. | ✅ Implemented (collect-only) |
| **HTTP** ([collectors/http.py](src/openhound_sccm/collectors/http.py)) | **Unauthenticated** probing of the SCCM web endpoints over http then https — `SMS_MP/.sms_aut` (`MPKEYINFORMATION`/`MPLIST`/`SMSTRC`/`MPLIST1`), `SMS_DP_SMSPKG$`, `AdminService/wmi/SMS_Identification`, and the site-signing certificate — to identify **Management Point**, **Distribution Point**, **SMS Provider**, and **Site Server** roles from the 401/403/200 status codes. Enumerates and registers sibling MPs and the site server as new probe targets; writes raw `http_*` role tables. Skipped on hosts AdminService/WMI already collected. Collect-only (graph conversion is a later phase). | ✅ Implemented (collect-only) |
| **SMB** ([collectors/smb.py](src/openhound_sccm/collectors/smb.py)) | An **unauthenticated** SMB2-negotiate **signing-required** check (via [clients/smb.py](src/openhound_sccm/clients/smb.py)), then **authenticated** share enumeration (`NetShareEnum`) that classifies SCCM-specific shares — `SMS_SITE`/`SMS_<code>` (Site Server), `SMS_DP$` (Distribution Point), `REMINST` (PXE), `SCCMContentLib$`/`SMSPKG` (content library) — into site-system roles and a site code. Writes raw `smb_computers` / `smb_sites` tables. Skipped on hosts AdminService/WMI already collected. Collect-only (graph conversion is a later phase). | ✅ Implemented (collect-only) |
| **DHCP** | Accepted as a `--collection-methods` token, but the per-host collector is not yet ported. | 🚧 Not yet ported |

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
| SMB | The signing-required check is **unauthenticated** (anyone with TCP/445 line of sight); share enumeration needs an **authenticated** SMB session (any domain user — current Windows user via SSPI, or `-u`/`-p`, `--nt-hash`, `--ticket`) |

**BloodHound side:**

- BloodHound with **OpenGraph** support.
- A **PostgreSQL** graph backend, required for the custom SCCM kinds to resolve: https://bloodhound.specterops.io/get-started/custom-installation#postgresql

**A note on `uv` and Python on Windows:** [pyproject.toml](pyproject.toml) sets `python-preference = "only-system"`. uv-managed (`python-build-standalone`) builds ship a `libcrypto` without the `OPENSSL_Applink` cross-CRT shim, which aborts TLS handshakes mid-flight — so on Windows the collector deliberately prefers an official/system Python.

---

# Assumptions

The collector relies on these assumptions about the target environment and how its output is consumed. They hold for the overwhelming majority of real deployments, but violating one can corrupt the graph (see [Limitations](#limitations)).

- **Site codes are unique within an organization.** A site code is only three characters and SCCM provides no globally unique hierarchy identifier, so the collector uses the (hierarchy-root) **site code as the `environmentid`** for SCCM-native nodes — those with no AD-domain home (`SCCM_Site` today, and the other SCCM-specific kinds as the port adds them). If two distinct hierarchies in the same organization reuse a site code, their SCCM environments collide and merge. Microsoft likewise recommends against reusing site codes within a forest: https://learn.microsoft.com/en-us/intune/configmgr/core/servers/deploy/install/prepare-to-install-sites#bkmk_sitecodes
- **One organization per graph.** Do not load data collected from two different organizations into the same BloodHound graph. Because site codes are not globally unique across organizations, a shared site code would merge the two organizations' SCCM environments. Collect and ingest each organization into its own graph.

> AD-native nodes (`Computer`, `User`, `Group`) are unaffected by the above: they use their AD **domain SID** as `environmentid`, so they merge with existing SharpHound data by SID rather than by site code.

---

# Limitations

- **Graph output covers the base identity layer.** `convert` emits [`Computer`](#computer), [`User`](#user), [`Group`](#group), and [`SCCM_Site`](#sccm_site) nodes plus the [`SCCM_AdminsReplicatedTo`](#sccm_adminsreplicatedto) site-replication edge. Richer edges (role assignments, `contains`, coerce-and-relay paths) are planned for later stages. See the [WIP banner](#-work-in-progress) and the [Edge Reference](#edge-reference).
- **Some per-host phases are not yet ported.** RemoteRegistry, MSSQL, AdminService, WMI, HTTP, and SMB collect real data (AdminService/WMI/HTTP/SMB are collect-only — raw tables, no graph yet); DHCP is a placeholder.
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
| `--nt-hash` | NT hash for pass-the-hash (bare 32-hex; empty LM half assumed). Used by AdminService Kerberos (as the RC4 key) and NTLM, and by the SMB-based phases (RemoteRegistry, SMB) via impacket. |
| `--ticket` | Base64 Kerberos ticket (`.kirbi` / KRB-CRED) for pass-the-ticket. Kerberos only — no NTLM fallback. Honored by AdminService/WMI and the SMB-based phases (RemoteRegistry, SMB). |
| `--ldap-port` | Pin the LDAP port. Omit to auto-detect (LDAPS:636 → StartTLS:389 → LDAP:389 with sign-and-seal). |

#### Authentication methods (AdminService / WMI / HTTP)

The shared HTTP client ([clients/http.py](src/openhound_sccm/clients/http.py)) authenticates to the SCCM AdminService with **Negotiate**, in this precedence:

1. **Explicit credentials win** — `-u` plus one of `-p` / `--nt-hash` / `--ticket`. Kerberos is tried first (a service ticket for `HTTP/<fqdn>`, built from the password, the NT hash as the RC4 key, or the supplied ticket), with an automatic **NTLM fallback** on protocol failure. A bare-IP target skips Kerberos (no SPN can be formed) and uses NTLM directly.
2. **Current-user Windows SSO** — passwordless SSPI Negotiate, when no credentials are supplied (Windows only).
3. **Anonymous** — no `Authorization` header. This is what the HTTP role-probe uses, so it can read the unauthenticated `401`/`403` that reveal site-system roles.

PKI / HTTPS-only sites are **detected** (e.g. a `403` on a probe endpoint), not satisfied — OpenHound does not present a client certificate. The KDC reuses `--dc`; there is no separate `--kdc` flag.

The **WMI fallback** ([clients/wmi.py](src/openhound_sccm/clients/wmi.py)) reuses this *exact* credential precedence (`choose_auth`), but realizes each rung over a WMI transport: pass-the-ticket / Kerberos / NTLM (incl. pass-the-hash) over **DCOM** via impacket, current-user **SSPI** via pywin32, and it skips the anonymous rung (DCOM always requires authentication). So `-u`/`-p`/`--nt-hash`/`--ticket` and passwordless current-user collection all work identically whether a host answers over AdminService or only over WMI.

The **SMB-based phases** — RemoteRegistry ([collectors/registry.py](src/openhound_sccm/collectors/registry.py)) and SMB ([collectors/smb.py](src/openhound_sccm/collectors/smb.py)) — authenticate through the shared `connect_smb` ([clients/smb_sso.py](src/openhound_sccm/clients/smb_sso.py)), which honors the same credential set over SMB: **pass-the-ticket** (`kerberosLogin` with the supplied TGT), **pass-the-hash** (`--nt-hash`), explicit **password** NTLM, current-user **SSPI** Negotiate, then an anonymous **null session**. SMB's signing-required check is unauthenticated (negotiate-only) and so works regardless of the credential method.

```bash
# Passwordless, as the current domain user (domain-joined collector):
uv run openhound collect sccm ./out -d mayyhem.com --sms ps1-sms.mayyhem.com

# Pass-the-hash against a specific SMS provider:
uv run openhound collect sccm ./out -d mayyhem.com -u MAYYHEM\\sccmadmin \
    --nt-hash 8846f7eaee8fb117ad06bdd830b7586c --sms ps1-sms.mayyhem.com

# Pass-the-ticket (base64 .kirbi):
uv run openhound collect sccm ./out -d mayyhem.com -u MAYYHEM\\sccmadmin \
    --ticket "$(base64 -w0 ticket.kirbi)" --sms ps1-sms.mayyhem.com
```

> **Status:** the auth client is implemented and unit- and live-validated against the lab AdminService. The **AdminService**, **WMI**, and **HTTP** per-host phases are implemented (collect-only); see [`--collection-methods`](#collection). HTTP uses the client's **anonymous** mode — it reads the unauthenticated 401/403/200 that reveal site-system roles.

### Collection

| Option | Description |
|---|---|
| `-m`, `--collection-methods` | Comma-separated methods (see the table below). Default `All`. |
| `-c`, `--computers` | Comma-separated computer targets. |
| `--cf`, `--computer-file` | Path to a file of computer targets, one per line. |
| `--sms`, `--sms-provider` | A specific SMS Provider host *(consumed by the AdminService / WMI phases)*. |
| `--sc`, `--site-codes` | Site codes for DNS collection (CSV or file path). |

**`--collection-methods` tokens** (case-insensitive; matched in [context.py](src/openhound_sccm/context.py)):

| Token | Status |
|---|---|
| `All` | Default — enables every phase |
| `LDAP`, `Local`, `DNS` | ✅ Discovery phases (Stage 1) |
| `RemoteRegistry`, `MSSQL`, `AdminService`, `WMI` | ✅ Per-host phases (Stage 2). `WMI` is the AdminService fallback — it runs on a host only when AdminService could not reach it. |
| `HTTP` | ✅ Per-host phase (Stage 2). Unauthenticated role probing of the SCCM web endpoints; runs on a host only when AdminService/WMI did not already collect it. Collect-only. |
| `SMB` | ✅ Per-host phase (Stage 2). SMB-signing check + SCCM share-role enumeration; runs on a host only when AdminService/WMI did not already collect it. Collect-only. |
| `DHCP` | 🚧 Accepted but not yet ported |

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

**Node identity.** Every node carries a stable string id and an `environmentid` tying it to its collected environment. AD-native nodes (`Computer`, `User`, `Group`) use the **AD SID** as the id and the **AD domain SID** (the `S-1-5-21-X-Y-Z` prefix stripped of the trailing RID) as `environmentid`, so they merge with SharpHound data by SID. `SCCM_Site` uses the **site code** as both id and `environmentid` (scoped to the hierarchy root site code). The common node/property base classes live in [graph.py](src/openhound_sccm/graph.py) (`SCCMNode`, property dataclasses); node and edge kind strings live in [kinds/nodes.py](src/openhound_sccm/kinds/nodes.py) and [kinds/edges.py](src/openhound_sccm/kinds/edges.py).

**Kinds declared** (in [kinds/nodes.py](src/openhound_sccm/kinds/nodes.py)) — the following are the kind *constants* the project intends to use; `Computer`, `User`, `Group`, and `SCCM_Site` are emitted today:

- AD-native: `Computer`, `User`, `Group`, `Base`
- SCCM: `SCCM_Site`, `SCCM_ClientDevice`, `SCCM_Collection`, `SCCM_AdminUser`, `SCCM_SecurityRole`
- MSSQL: `MSSQL_Server`, `MSSQL_Login`, `MSSQL_Database`, `MSSQL_DatabaseUser`, `MSSQL_ServerRole`, `MSSQL_DatabaseRole`

**Convert-time enrichment.** Nodes are built from coalesced DuckDB tables (`node_computer`, `node_user`, `node_group`, `node_site`) computed by `preprocess`. Each table unions multiple raw collected sources (AdminService, WMI, LDAP, RemoteRegistry, SMB, HTTP) into one row per identity, so a node's richness grows as more collection phases come online, without changing the model.

---

# Node Reference

> **Currently emitted: 4 node kinds** — `Computer`, `User`, `Group`, and `SCCM_Site`.

All AD-native nodes (`Computer`, `User`, `Group`) use the **AD SID** as the node id and the **AD domain SID** (`S-1-5-21-X-Y-Z`) as `environmentid`. Builtin or well-known SIDs that have no domain part are qualified with a co-occurring domain SID where available; nodes that cannot be placed in a domain environment are dropped and logged. All property keys are lowercase with underscores.

## Computer

An AD computer account observed in SCCM — collected from AdminService/WMI resource tables, LDAP, RemoteRegistry, SMB, and HTTP sources and coalesced into one row per SID. Model: [models/computer.py](src/openhound_sccm/models/computer.py).

- **Node id:** the AD SID (uppercased, e.g. `S-1-5-21-11-22-33-1104`).
- **`environmentid`:** the AD domain SID (`S-1-5-21-11-22-33`).
- **Kinds:** `["Computer", "Base"]`.
- **`name` / `displayname`:** the SAM account name, DNS hostname, or SID (whichever is available first).

| Property | Type | Description |
|---|---|---|
| `collection_source` | list\<string\> | Collection sources that contributed to this node. |
| `sccm_site_system_roles` | list\<string\> | SCCM site-system roles observed on this host (e.g. `SMS Provider`, `SMS Distribution Point`). |
| `sccm_resource_ids` | list\<string\> | SCCM resource IDs in `"<id>@<site_code>"` format, one per site that enrolled this device. |
| `sccm_infra` | bool | `true` if this computer is an SCCM infrastructure host (site system, server). |
| `sccm_client_device_identifier` | string | The SCCM client GUID (`sms_unique_identifier` / `GUID:…`). |
| `smb_signing_required` | bool | `true` if SMB signing is required on this host (from RemoteRegistry or SMB signing-check). |
| `sccm_has_client_remote_control_spn` | bool | `true` if the host has a `CmRcService` SPN in AD (LDAP-discovered). |
| `network_boot_server` | bool | `true` if the host was discovered as a network boot server in AD. |
| `disable_loopback_check` | bool | `true` if the loopback check is disabled (RemoteRegistry). |
| `restrict_receiving_ntlm_traffic` | string | NTLM restriction policy value (e.g. `Off`, `Deny_All`) from RemoteRegistry. |
| `sccm_client_certificate_required` | bool | `true` if the host's SCCM site systems require a client certificate (from HTTP probing). |
| `sccm_hosts_content_library` | bool | `true` if an SCCM content library share was found on this host (SMB). |
| `sccm_is_pxe_support_enabled` | bool | `true` if PXE support was found on this host (SMB `REMINST` share). |

## User

An AD user account observed in SCCM — collected from AdminService/WMI user resource tables, admin tables, reserved-account tables, and RemoteRegistry. Model: [models/user.py](src/openhound_sccm/models/user.py).

- **Node id:** the AD SID (uppercased).
- **`environmentid`:** the AD domain SID.
- **Kinds:** `["User", "Base"]`.
- **`name` / `displayname`:** the account name or SID.

| Property | Type | Description |
|---|---|---|
| `collection_source` | list\<string\> | Collection sources that contributed to this node. |
| `sccm_resource_ids` | list\<string\> | SCCM resource IDs in `"<id>@<site_code>"` format. |
| `sccm_infra` | bool | `true` if this account appears in the SCCM admins tables (an SCCM admin user). |
| `stored_in_sccm_site` | string | Site code of the SCCM site that stores this account as a reserved/stored credential (`SMS_SCI_Reserved`). |

> **Not yet emitted:** `is_sccm_network_access_account` — this property is set only when NAA secrets are decrypted, which requires the `--enable-bad-opsec` flag and the NAA-secret collector, neither of which is implemented yet.

## Group

An AD group observed in SCCM — either named in a device's or user's `security_group_name` list or present directly in the SCCM admins tables. Model: [models/group.py](src/openhound_sccm/models/group.py).

`security_group_name` carries only group **names**; the SIDs come from the `SMS_R_UserGroup` resource (AD Security Group Discovery mirrors each group, with its SID, into `adminservice_user_group` / `wmi_user_group`). `preproc` folds those `(name, SID)` pairs into the `principal_by_name` lookup, so a name→SID join resolves each membership **offline** — replacing ConfigManBearPig's live per-name Active Directory lookup. (A name shared by two distinct groups can't be disambiguated from the name alone, so both resolve.)

- **Node id:** the AD SID (uppercased).
- **`environmentid`:** the AD domain SID; builtin SIDs use a co-occurring domain SID as a fallback.
- **Kinds:** `["Group", "Base"]`.
- **`name` / `displayname`:** the group name or SID.

| Property | Type | Description |
|---|---|---|
| `collection_source` | list\<string\> | Collection sources that contributed to this node. |
| `sccm_infra` | bool | `true` if this group appears in the SCCM admins tables. |
| `sccm_resource_ids` | list\<string\> | SCCM resource IDs in `"<id>@<site_code>"` format. |

## SCCM_Site

A Configuration Manager **site**, coalesced from AdminService/WMI site tables, site-definition tables, and LDAP `mSSMSSite` objects. Model: [models/sccm_site.py](src/openhound_sccm/models/sccm_site.py).

- **Node id:** the site code (e.g. `PS1`).
- **`environmentid`:** the hierarchy root site code (e.g. `CAS`); falls back to the site's own code for standalone deployments with no CAS.
- **Kinds:** `["SCCM_Site"]`.
- **`name` / `displayname`:** the human-readable site name, or the site code when no name is available.

| Property | Type | Description |
|---|---|---|
| `collection_source` | list\<string\> | Collection sources that contributed to this node. |
| `site_code` | string | The site code (e.g. `PS1`). |
| `parent_site_code` | string | Parent site in the hierarchy; `null` for the root (CAS) site. |
| `root_site_code` | string | Hierarchy root site code (CAS if present, else the parentless Primary). |
| `site_type` | string | `Primary Site`, `Central Administration Site`, or `Secondary Site`. |
| `site_guid` | string | Site GUID from the site definitions or LDAP `mSSMSHealthState`. |
| `site_server_name` | string | Hostname of the primary site server. |
| `sql_server_name` | string | Hostname of the SQL Server hosting the site database. |
| `sql_database_name` | string | Site database name (e.g. `CM_PS1`). |
| `version` | string | Site version string (e.g. `5.00.9106.1000`). |
| `build_number` | string | Build number (e.g. `9106`). |
| `install_dir` | string | Site server install directory. |
| `sccm_infra` | bool | Always `true` for a site. |

---

# Edge Reference

> **Currently emitted: 1 edge kind** — `SCCM_AdminsReplicatedTo`.

## SCCM_AdminsReplicatedTo

Represents the SCCM site replication topology — which sites replicate administrative data to which other sites. Built from the site hierarchy computed by `preprocess` (the `graph_edges` table). Edge model: [models/replication_edge.py](src/openhound_sccm/models/replication_edge.py).

- **Source:** `SCCM_Site`
- **Target:** `SCCM_Site`
- **Direction:**
  - CAS ↔ Primary Site: **bidirectional** (two edges, one in each direction)
  - Primary Site → Secondary Site: **one-way**

No edge properties beyond the start and end site-code ids are emitted in Stage 1.

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
    ├── collectors/               # ldap.py · dns.py · local.py · registry.py · mssql.py · privileged.py · http.py · smb.py · stubs.py
    ├── clients/                  # ad.py (LDAP auth) · mssql_epa.py (EPA probe) · http.py/http_auth.py (Negotiate) · wmi.py · smb_sso.py (SMB SSPI) · smb.py (signing + shares)
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
- **`debug_per_host.py`** — exercises the per-host pipeline (ordering, concurrency, recursion, termination) with stub phases. Set `COLLECTION_METHODS` to run only specific collectors (mirrors the `-m`/`--collection-methods` flag).
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
