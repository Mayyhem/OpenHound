# OpenHound MSSQL Collector

The **OpenHound MSSQL collector** brings Microsoft SQL Server attack paths into [BloodHound](https://github.com/SpecterOps/BloodHound) using [OpenGraph](https://specterops.io/opengraph). It is the [OpenHound](https://github.com/SpecterOps/openhound) port of [MSSQLHound](https://github.com/SpecterOps/MSSQLHound), the SQL Server BloodHound collector by Chris Thompson ([@_Mayyhem](https://x.com/_Mayyhem)) at [SpecterOps](https://x.com/SpecterOps).

MSSQLHound exists as a PowerShell script (`MSSQLHound.ps1`) and as a Go binary (`mssqlhound`). This version is a third implementation: a native OpenHound extension that runs on the framework's three-stage pipeline (`collect` → `preprocess` → `convert`) and produces an OpenGraph dataset you upload to BloodHound's **File Ingest**. It matches the intent and collection order of the PowerShell tool while adding the enhancements introduced in the Go version (linked-server recursion, AD node creation, the CVE-2025-49758 check, SOCKS5 proxying, and the full offensive edge catalog).

The collector talks to SQL Server entirely in **pure Python** (TDS + TLS + NTLM/Kerberos/EPA via [impacket](https://github.com/fortra/impacket)), so there are no native binaries, ODBC drivers, or child processes. The shared transport, auth, LDAP/AD, DNS, proxy, and DLT plumbing live in a sibling library, `openhound-collector-common`, which this extension imports.

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
  - [MSSQL_Server](#mssql_server)
  - [MSSQL_Login](#mssql_login)
  - [MSSQL_ServerRole](#mssql_serverrole)
  - [MSSQL_Database](#mssql_database)
  - [MSSQL_DatabaseUser](#mssql_databaseuser)
  - [MSSQL_DatabaseRole](#mssql_databaserole)
  - [MSSQL_ApplicationRole](#mssql_applicationrole)
  - [Computer](#computer)
  - [User](#user)
  - [Group](#group)
- [Edge Reference](#edge-reference)
  - [Membership & structure](#membership--structure)
  - [Server-level control & impersonation](#server-level-control--impersonation)
  - [Alter & ownership](#alter--ownership)
  - [Privilege grants](#privilege-grants)
  - [Execution context](#execution-context)
  - [Connection](#connection)
  - [Linked servers](#linked-servers)
  - [Credentials & proxies](#credentials--proxies)
  - [Host, coercion & Kerberos](#host-coercion--kerberos)
- [Understanding the Codebase](#understanding-the-codebase)
- [Testing Changes](#testing-changes)
- [Contributing](#contributing)

---

# Quick Start

The collector is an OpenHound extension. All commands run from this directory (`mssql/mssql/`) through [`uv`](https://docs.astral.sh/uv/), which manages the virtual environment and pulls in the OpenHound framework plus the shared `openhound-collector-common` library.

### 1. Install dependencies

```powershell
uv sync
```

This installs the runtime dependencies (`impacket`, `ldap3`, `dnspython`, `cryptography`, and — on Windows — `pywin32` and `winkerberos`, carried transitively through `openhound-collector-common`) plus the OpenHound framework itself, which provides the `openhound` CLI.

### 2. Collect

Collect from a single SQL Server in the `mayyhem.com` lab as an explicit domain user (works on Windows, Linux, and macOS):

```powershell
uv run openhound collect mssql .\out -t ps1-db.mayyhem.com -d mayyhem.com -u "MAYYHEM\domainadmin" -p "Passw0rd!" -v
```

On a domain-joined Windows host you can omit the credentials and the domain to authenticate as the current Windows user (current-user SSPI):

```powershell
uv run openhound collect mssql .\out -t ps1-db.mayyhem.com -v
```

Leave `-t/--targets` off to **discover** SQL Servers from Active Directory by their `MSSQLSvc` SPNs instead of naming a host:

```powershell
uv run openhound collect mssql .\out -d mayyhem.com --dc dc.mayyhem.com -u "MAYYHEM\domainadmin" -p "Passw0rd!" -v
```

`collect` writes raw JSONL tables under `.\out\mssql\<table>\` (one per collected SQL query).

### 3. Preprocess (build the lookup database)

```powershell
uv run openhound preprocess mssql .\out .\lookup.duckdb
```

This loads the raw JSONL into DuckDB and builds the derived/lookup tables that `convert` reads (principal maps, nested role-membership closures, effective high-privilege summaries, fixed-role permission expansion, linked-server flags, and the AD-node + graph-edge tables).

### 4. Convert (produce the OpenGraph dataset)

```powershell
uv run openhound convert mssql .\out\mssql .\graph --lookup-file .\lookup.duckdb
```

### 5. Upload to BloodHound

Upload the resulting OpenGraph output via the BloodHound UI under **Administration → File Ingest**. To query the MSSQL kinds, BloodHound must use the **PostgreSQL** graph backend (the prebuilt MSSQL kinds will not resolve on Neo4j): https://bloodhound.specterops.io/get-started/custom-installation#postgresql

> **Verbosity tip:** `-v` raises the console log to INFO (collection-step summaries); `--debug` adds the framework's `dlt`, `impacket`, and `ldap3` internals (very chatty — useful when diagnosing TLS/EPA/NTLM handshakes).

---

# Collection Overview

The collector follows OpenHound's standard three-phase pipeline.

```text
                       openhound collect mssql
                                │
        ┌───────────────────────┴───────────────────────┐
        │  Target resolution                             │
        │  explicit list / file / inline creds /         │
        │  MSSQLSvc SPN enumeration / scan-all-computers  │
        │  (LDAP + DNS), IP de-dupe, recursion seed       │
        └───────────────────────┬───────────────────────┘
                                │
        ┌───────────────────────┴───────────────────────┐
        │  Per-target SQL collection (worker pool)       │
        │  EPA probe → connect → ps1-ordered queries     │
        │  → raw JSONL rows; linked servers re-queued     │
        └───────────────────────┬───────────────────────┘
                                │
                      raw JSONL on disk
                                │
       preprocess → DuckDB lookup database (derived tables)
                                │
       convert → OpenGraph nodes + edges (full property bags)
```

## collect — per-target SQL collection

`collect` resolves a target list, then connects to each SQL Server and runs the collection queries **in the exact order of `MSSQLHound.ps1`** (decision D8 in the [design spec](docs/superpowers/specs/2026-06-25-mssql-collector-design.md)). For each server the steps are, in order: resolve the host to its computer SID and build the server's stable identifier; probe **Extended Protection for Authentication (EPA)** over an unauthenticated TDS prelogin *before* opening the database connection; open the SQL connection; read the FQDN, `@@VERSION`, instance name, and mixed-mode flag; enumerate server principals, server-role memberships, server permissions, and credential mappings; per online database, read the database principals, role memberships, permissions, owner, and database-scoped credentials; enumerate linked servers (recursively, up to ten levels, unless skipped); and read server credentials and SQL Agent proxies. Each step yields raw rows tagged by table and streamed to JSONL.

All node and edge *derivation* — principal processing, the nested-role and effective-permission graph walks, fixed-role permission expansion — is deliberately deferred to `preprocess`/`convert` for scalability; `collect` only runs SQL and emits raw rows.

## preprocess — build the lookup database

`preprocess` loads the raw JSONL into DuckDB and runs the SQL transforms in [transforms.py](src/openhound_mssql/transforms.py) to build the derived tables `convert` reads: per-server and per-database principal maps, the nested server-/database-role membership closures, the effective high-privilege summary (which domain principals end up with sysadmin / CONTROL SERVER / securityadmin / IMPERSONATE ANY LOGIN), fixed-role permission expansion, linked-server privilege flags, the AD-node table, and the flattened `graph_edges` table that carries every emitted edge with its `traversable` flag already decided.

## convert — produce the OpenGraph dataset

`convert` reads the DuckDB lookup database (using the SCCM-proven "convert-reads-DuckDB" pattern) and emits the OpenGraph nodes and edges. The node assets map one raw row to one node and enrich it from the derived tables; the edges are emitted from the preproc-built `graph_edges` table by a single generic [`GraphEdge`](src/openhound_mssql/models/graph_edge.py) model, so no edge derivation happens at convert time.

---

# System Requirements

**Host running the collector:**

- **Python 3.13 or 3.14** (`requires-python = ">=3.13,<3.15"`) and [`uv`](https://docs.astral.sh/uv/).
- The **OpenHound framework** and the **`openhound-collector-common`** library (installed automatically via `uv sync`; OpenHound is pulled from `git+https://github.com/SpecterOps/openhound.git`, the shared library from the sibling path `../../openhound-collector-common`).
- The pure-Python auth/transport stack: **`impacket`** (TDS, NTLMv2 with EPA channel binding, Kerberos, SPNEGO, pass-the-hash), **`ldap3`** (SPN discovery, SID → AD-object resolution), **`dnspython`** (DC / SRV / A discovery), **`cryptography`** (TLS certificate hashing for the `tls-server-end-point` channel-binding fallback).
- Network line of sight to a **domain controller** (for SPN discovery, SID resolution, and EPA testing) and to the **SQL Servers** you target (TCP/1433 by default).

**Authentication — Windows vs. Linux/macOS:**

- **Explicit credentials work everywhere.** A domain login (`DOMAIN\user` + password), pass-the-hash (`--nt-hash`), or pass-the-ticket (`--ticket`) authenticates over impacket on any platform. This is the path the comparison harness uses for all three test users.
- **Current-user SSPI / single sign-on is Windows-only.** Passing no SQL credentials on a domain-joined Windows host authenticates as the current Windows user via `pywin32` SSPI; `winkerberos` provides the current-user TGT for `ldap3`'s GSSAPI bind. These packages are installed only on Windows (`sys_platform == 'win32'`).
- **The AD domain** is auto-detected from the current Windows user context; on Linux/macOS pass `-d/--domain` for any AD operation. `--dc` is resolved from the domain via DNS SRV (`_ldap._tcp`) then an A record when omitted.

**A note on `uv` and Python on Windows:** [pyproject.toml](pyproject.toml) sets `python-preference = "only-system"`. uv-managed (`python-build-standalone`) builds ship a `libcrypto` without the `OPENSSL_Applink` cross-CRT shim, which aborts TLS handshakes mid-flight — so on Windows the collector deliberately prefers an official/system Python. (This mirrors the SCCM extension.)

**BloodHound side:**

- BloodHound with **OpenGraph** support.
- A **PostgreSQL** graph backend, required for the custom MSSQL kinds to resolve: https://bloodhound.specterops.io/get-started/custom-installation#postgresql

---

# Limitations

- **TLS is capped at 1.2 on every EPA / auth path.** TLS 1.3 removed the `tls-unique` channel binding (RFC 8446), and SChannel will not accept `tls-server-end-point` as a substitute, so the EPA channel-binding logic forces `maximum_version = TLSv1_2`. A server that refuses anything below TLS 1.3 cannot be EPA-probed by this collector.
- **EPA "Allowed" vs. "Required" is indistinguishable under current-user SSPI.** When EPA is detected as the current Windows user, Windows always emits the channel-binding and target-name AV pairs, so the collector cannot tell `Allowed` from `Required` and reports the literal `Allowed/Required`. Explicit-credential and pass-the-hash paths (via impacket) *can* distinguish them.
- **Some edge kinds only appear when their preconditions exist in the environment.** Linked-server edges (`MSSQL_LinkedTo` / `MSSQL_LinkedAsAdmin`) require configured linked servers; credential edges require mapped credentials, SQL Agent proxies, or database-scoped credentials; `MSSQL_CoerceAndRelayToMSSQL` requires a computer-account login on a server with EPA disabled; `MSSQL_GetAdminTGS` requires at least one domain principal who is effectively sysadmin. The [Edge Reference](#edge-reference) lists every kind the collector *can* produce — a clean lab will not exercise all of them.
- **`--disable-possible-edges` only changes traversability, not presence.** The six "possible" edges (`MSSQL_LinkedTo`, `MSSQL_IsTrustedBy`, `MSSQL_ServiceAccountFor`, `MSSQL_HasDBScopedCred`, `MSSQL_HasMappedCred`, `MSSQL_HasProxyCred`) are best-effort inferences. They are still emitted with the flag set; they are simply marked non-traversable so BloodHound's attack-path engine does not follow them.
- **Windows 8.3 short-path / dlt issue.** On Windows, dlt's pipeline working directory can land under an 8.3-style short path (e.g. `C:\Users\DOMAIN~2\...`), which dlt mishandles. This extension does **not** carry SCCM's Windows-on-Windows dlt/log workarounds (they proved unreliable — design decision D13); if you hit a pipeline-directory lock or a path error during a run, point the scratch directory somewhere with a normal path (e.g. `--temp-dir C:\mssqlhound`).
- **`--ticket` / `--ldap-ticket` are Kerberos-only.** Pass-the-ticket has **no NTLM fallback** — a target that cannot be reached over Kerberos (e.g. a bare-IP target with no formable SPN) will fail rather than fall back.

---

# Command Line Options

The collector adds MSSQLHound-style flags to the framework's `collect` command. Every flag also has an environment-variable equivalent (`SOURCES__MSSQL__<NAME>`), and **CLI flag values take precedence** over the env var or a `.env` entry. Run `uv run openhound collect mssql --help` for the authoritative list — everything documented below is implemented (✅).

```text
uv run openhound collect mssql <output_path> [options]
```

`<output_path>` (positional, required) is the directory raw JSONL is written to.

### Authentication — SQL

The SQL login may present **at most one** secret: `--password`, `--nt-hash`, and `--ticket` are mutually exclusive. With no SQL credentials at all, the collector authenticates as the current Windows user (SSPI, Windows only).

| Option | Description |
|---|---|
| `-u`, `--user` | SQL/Windows login (`DOMAIN\user` for domain auth, or a SQL login name). |
| `-p`, `--password` | Password for the SQL/Windows login. |
| `--nt-hash` | NT hash for pass-the-hash (bare 32-hex NT hash; empty LM half assumed). |
| `--ticket` | Base64-encoded Kerberos ticket (`.kirbi` / KRB-CRED) for pass-the-ticket. Kerberos only — no NTLM fallback. |

### Authentication — LDAP/AD

Separate credentials for SPN discovery, SID resolution, and EPA testing. When the LDAP login is unset but a domain-shaped SQL login was supplied, the LDAP path falls back to the SQL credentials. The same one-secret rule applies (`--ldap-password` ⊕ `--ldap-nt-hash` ⊕ `--ldap-ticket`).

| Option | Description |
|---|---|
| `--ldap-user` | LDAP/AD login. Falls back to the SQL login when domain-shaped and unset. |
| `--ldap-password` | Password for the LDAP/AD login. |
| `--ldap-nt-hash` | NT hash for LDAP/AD pass-the-hash. |
| `--ldap-ticket` | Base64-encoded Kerberos ticket (`.kirbi` / KRB-CRED) for LDAP/AD pass-the-ticket. |

### Connection / Collection

| Option | Description |
|---|---|
| `-t`, `--targets` | Target(s): `host` \| `host:port` \| `host\instance` \| `MSSQLSvc/host:port` \| comma-separated list \| path to a file (one target per line). Leave empty to enumerate SQL Servers via LDAP SPN discovery. |
| `-d`, `--domain` | AD domain (e.g. `mayyhem.com`). Auto-detected from the Windows current-user context; **required** on Linux/macOS for AD operations. |
| `--dc` | DC hostname or IP. If omitted, resolved from `--domain` via DNS SRV (`_ldap._tcp`) then an A record. |
| `--dns-resolver` | DNS nameserver IP used for all lookups (DC discovery, SPN/SRV probes). Omit to use the system default. |
| `-x`, `--proxy` | SOCKS5 proxy (`socks5://[user:pass@]host:port`) for all TCP connections. |

### Collection toggles

| Option | Description |
|---|---|
| `-A`, `--scan-all-computers` | Enumerate every AD computer object (`objectClass=computer`) and probe it for SQL Server. |
| `--scan-all-computer-ports` | Comma-separated TCP ports to probe under `--scan-all-computers`. Default `1433`. |
| `--skip-private-address` | Skip targets that resolve to RFC1918 / private addresses. |
| `--domain-enum-only` | Only enumerate SQL Servers via SPN discovery; do not connect or collect. |
| `--skip-linked-servers` | Do not enumerate linked servers. |
| `--collect-from-linked` | Enqueue discovered linked servers as new targets and collect from them. |
| `--skip-ad-nodes` | Do not create AD (`Computer` / `Group` / `User`) nodes. |
| `--disable-nontraversable-edges` | Omit the non-traversable informational edges (Alter / Control / Impersonate / Connect / …). |
| `--disable-possible-edges` | Mark the uncertain/"possible" edges (`MSSQL_LinkedTo`, `MSSQL_IsTrustedBy`, `MSSQL_ServiceAccountFor`, the `*Cred` edges) non-traversable. |
| `--skip-ip-dedupe` | Do not de-duplicate targets that resolve to the same IP. |

### Performance

| Option | Description |
|---|---|
| `--linked-timeout` | Per-target timeout (seconds) for linked-server enumeration. Default `300`. |
| `--port-check-timeout` | TCP port-reachability check timeout in seconds. Default `2`. |
| `--memory-threshold` | Pause spawning new workers above this memory-usage percentage. Default `90`. |
| `-w`, `--workers` | Number of targets collected concurrently. `0` = sequential (default). |

### Output

| Option | Description |
|---|---|
| `--temp-dir` | Directory for scratch/intermediate files. Defaults to the system temp dir. |
| `--log-per-target` | Write a separate log file per target. |

### General

| Option | Description |
|---|---|
| `-v`, `--verbose` | Repeatable. Raises the console log level to INFO (collection-step summaries). |
| `--debug` | DEBUG level (very chatty; includes `dlt`, `impacket`, and `ldap3` internals). |

### preprocess / convert arguments

The later two phases take positional paths plus a couple of options:

```text
uv run openhound preprocess mssql <input_path> [output_file]   # output_file default: lookup.duckdb
uv run openhound convert    mssql <input_path> <output_path> --lookup-file <file>
```

| Option | Phase | Description |
|---|---|---|
| `--lookup-file` | convert | DuckDB lookup file path produced by `preprocess`. Default `lookup.duckdb`. |
| `--progress` | preprocess / convert | Progress tracker: `tqdm` (default), `log`, or `alive_progress`. |

---

# Graph Model

The collector emits the graph shape MSSQLHound defines, so BloodHound ingest and the MSSQLHound validators agree on the result. The OpenGraph metadata block carries `source_kind = MSSQL_Base`.

| Phase | Command | Role |
|---|---|---|
| **collect** | `openhound collect mssql` | Connect to each SQL Server and write raw JSONL tables (one per collected query). |
| **preprocess** | `openhound preprocess mssql` | Load the JSONL into DuckDB and build derived/lookup tables ([transforms.py](src/openhound_mssql/transforms.py), [lookup.py](src/openhound_mssql/lookup.py)). |
| **convert** | `openhound convert mssql` | Read the DuckDB lookup and emit OpenGraph nodes/edges with full property bags. |

**Node identity (the SID-based ID scheme).** Every node carries a stable string `id` and an `environmentid`. The **SQL Server is the root / environment node**, and *its* id is the `environmentid` of every other MSSQL node in the graph. IDs are built in [ids.py](src/openhound_mssql/ids.py):

| Kind | `id` format |
|---|---|
| `MSSQL_Server` | `<computerSID>:<port>` — falls back to `<lowercased-host>:<port>` when no SID is resolved; a **named** instance keys by `<base>:<instanceName>` instead of `:<port>`. |
| `MSSQL_Login` / `MSSQL_ServerRole` | `<name>@<serverOID>` |
| `MSSQL_Database` | `<serverOID>\<dbName>` |
| `MSSQL_DatabaseUser` / `MSSQL_DatabaseRole` / `MSSQL_ApplicationRole` | `<name>@<serverOID>\<dbName>` |
| `Computer` / `User` | the AD object **SID** |
| `Group` | `S-1-5-11` / `<domain>-S-1-5-11` (Authenticated Users), or `<host>-<SID>` for a machine-local group |

When a server is first keyed by hostname and later resolved to its computer SID, every principal/database/permission id that embedded the old server OID is rewritten in place (`ids.rewrite_server_id`), so the final graph keys consistently on the SID.

**Property names.** MSSQL node and edge properties use **MSSQLHound's exact original casing** verbatim (`isMixedModeAuthEnabled`, `SQLServer`, `ownerPrincipalID`, `windowsAbuse`, `credentialId`, …) so they render correctly in BloodHound entity panels and the MSSQLHound validators accept them. The framework's mandatory base fields (`name`, `displayname`, `environmentid`) are kept alongside them. The four CVE-2025-49758 properties are emitted with hyphenated keys (`isVulnerableToCVE-2025-49758`, etc.), remapped from their underscore field names at emit time.

**Kinds.** The seven `MSSQL_*` kinds each carry a font-awesome icon; the three AD kinds (`Computer`, `User`, `Group`) carry a second `Base` kind and **no icon** (they are BloodHound-native objects that merge with SharpHound data by SID). Kind strings are defined in [kinds/nodes.py](src/openhound_mssql/kinds/nodes.py) and [kinds/edges.py](src/openhound_mssql/kinds/edges.py).

---

# Node Reference

> **10 node kinds** — 7 `MSSQL_*` kinds plus the 3 AD kinds. Property keys use MSSQLHound's exact casing; absent/optional properties are omitted from a node rather than emitted empty.

## MSSQL_Server

A Microsoft SQL Server instance — the **root / environment node**. One per collected target. Model: [models/server.py](src/openhound_mssql/models/server.py).

- **Node id:** `<computerSID>:<port>` (or `<lowercased-host>:<port>`; named instances key by `<base>:<instanceName>`).
- **`environmentid`:** the server id itself (every other MSSQL node points back to it).
- **Kinds:** `["MSSQL_Server"]` (icon: `server`).
- **`name` / `displayname`:** the resolved SQL Server display name (`<fqdn>:<port>`).

| Property | Type | Description |
|---|---|---|
| `hostname` | string | Host name of the SQL Server machine. |
| `fqdn` | string | Fully-qualified domain name of the host. |
| `sqlServerName` | string | Original SQL Server name (short name or instance form). |
| `version` | string | Full `@@VERSION` banner. |
| `versionNumber` | string | Numeric product version (e.g. `15.0.2000.5`). |
| `edition` | string | SQL Server edition. |
| `productLevel` | string | Product level (e.g. `RTM`, `SP1`). |
| `isClustered` | bool | Whether the instance is clustered. |
| `port` | int | TCP port the instance listens on. |
| `instanceName` | string | Instance name (omitted for the default instance). |
| `isMixedModeAuthEnabled` | bool | Whether mixed-mode authentication is enabled. |
| `forceEncryption` | string | ForceEncryption verdict (when collected). |
| `strictEncryption` | string | Strict (TDS 8.0) encryption verdict (when collected). |
| `extendedProtection` | string | Extended Protection / EPA verdict (when collected; may be the literal `Allowed/Required` under SSPI). |
| `isVulnerableToCVE-2025-49758` | bool | CVE-2025-49758 vulnerability verdict. |
| `CVE-2025-49758_updateName` | string | Name of the patch that fixes the CVE. |
| `CVE-2025-49758_patchKB` | string | KB number of the fixing patch. |
| `CVE-2025-49758_requiredVersion` | string | Minimum patched version. |
| `servicePrincipalNames` | list\<string\> | SPNs registered for the instance. |
| `serviceAccount` | string | First service account (NetBIOS prefix stripped). |
| `databases` | list\<string\> | Names of online databases on the instance. |
| `linkedToServers` | list\<string\> | Names of linked servers configured here. |
| `isLinkedServerTarget` | bool | `true` if a linked server resolves back to this server. |
| `hasLinksFromServers` | list\<string\> | Object identifiers of servers that link back to this one. |
| `domainPrincipalsWithSysadmin` | list\<string\> | Object identifiers of domain principals with effective sysadmin. |
| `domainPrincipalsWithControlServer` | list\<string\> | Object identifiers with effective CONTROL SERVER. |
| `domainPrincipalsWithSecurityadmin` | list\<string\> | Object identifiers with effective securityadmin. |
| `domainPrincipalsWithImpersonateAnyLogin` | list\<string\> | Object identifiers with effective IMPERSONATE ANY LOGIN. |
| `isAnyDomainPrincipalSysadmin` | bool | `true` if any domain principal is effectively sysadmin. |

## MSSQL_Login

A server-level login — a SQL login, a Windows login, or a Windows group. Emitted by the server-principal asset on every `type_desc` other than `SERVER_ROLE`. Model: [models/server_principal.py](src/openhound_mssql/models/server_principal.py).

- **Node id:** `<name>@<serverOID>`.
- **`environmentid`:** the server id.
- **Kinds:** `["MSSQL_Login"]` (icon: `user-gear`).
- **`name` / `displayname`:** the login name.

| Property | Type | Description |
|---|---|---|
| `principalId` | int | SQL `principal_id` of the login. |
| `createDate` | string | Login create date (RFC3339). |
| `modifyDate` | string | Login modify date (RFC3339). |
| `SQLServer` | string | Display name of the owning SQL Server. |
| `type` | string | `type_desc` (`SQL_LOGIN` / `WINDOWS_LOGIN` / `WINDOWS_GROUP` / …). |
| `disabled` | bool | Whether the login is disabled. |
| `defaultDatabase` | string | Default database name for the login. |
| `isActiveDirectoryPrincipal` | bool | Whether the login maps to an AD principal. |
| `activeDirectorySID` | string | SID when the login is an AD principal. |
| `activeDirectoryPrincipal` | string | Resolved AD principal name (AD principals only). |
| `databaseUsers` | list\<string\> | Database users mapped from this login (`user@db`). |
| `memberOfRoles` | list\<string\> | Names of server roles this login belongs to. |
| `explicitPermissions` | list\<string\> | Explicitly granted/denied server permissions. |

## MSSQL_ServerRole

A server-level role (fixed or user-defined). Emitted by the server-principal asset when `type_desc == SERVER_ROLE`. Model: [models/server_principal.py](src/openhound_mssql/models/server_principal.py).

- **Node id:** `<name>@<serverOID>`.
- **`environmentid`:** the server id.
- **Kinds:** `["MSSQL_ServerRole"]` (icon: `users-gear`).
- **`name` / `displayname`:** the role name.

| Property | Type | Description |
|---|---|---|
| `principalId` | int | SQL `principal_id` of the role. |
| `createDate` | string | Role create date (RFC3339). |
| `modifyDate` | string | Role modify date (RFC3339). |
| `SQLServer` | string | Display name of the owning SQL Server. |
| `isFixedRole` | bool | Whether this is a fixed server role. |
| `members` | list\<string\> | Member principal names. |
| `memberOfRoles` | list\<string\> | Names of server roles this role belongs to. |
| `explicitPermissions` | list\<string\> | Explicitly granted/denied server permissions. |

## MSSQL_Database

A SQL Server database — one node per online database. Model: [models/database.py](src/openhound_mssql/models/database.py).

- **Node id:** `<serverOID>\<dbName>`.
- **`environmentid`:** the server id.
- **Kinds:** `["MSSQL_Database"]` (icon: `database`).
- **`name` / `displayname`:** the database name.

| Property | Type | Description |
|---|---|---|
| `databaseId` | int | SQL `database_id`. |
| `createDate` | string | Database create date (RFC3339). |
| `compatibilityLevel` | int | Compatibility level integer. |
| `isReadOnly` | bool | Whether the database is read-only. |
| `isTrustworthy` | bool | Whether the TRUSTWORTHY flag is set. |
| `isEncrypted` | bool | Whether the database is encrypted. |
| `SQLServer` | string | Display name of the owning SQL Server. |
| `SQLServerID` | string | Object identifier of the owning server. |
| `ownerLoginName` | string | Owner login name (when present). |
| `ownerPrincipalID` | string | Owner `principal_id` as a string (when resolvable). |
| `OwnerObjectIdentifier` | string | Owner principal's object identifier (when resolvable). |
| `collationName` | string | Database collation (when present). |

## MSSQL_DatabaseUser

A database-level user (a mapped login or a contained user). Emitted by the database-principal asset on every `type_desc` other than `DATABASE_ROLE` / `APPLICATION_ROLE`. Model: [models/database_principal.py](src/openhound_mssql/models/database_principal.py).

- **Node id:** `<name>@<serverOID>\<dbName>`.
- **`environmentid`:** the server id.
- **Kinds:** `["MSSQL_DatabaseUser"]` (icon: `user`).
- **`name` / `displayname`:** `Name@DatabaseName`.

| Property | Type | Description |
|---|---|---|
| `principalId` | int | SQL `principal_id` of the database user. |
| `createDate` | string | User create date (RFC3339). |
| `modifyDate` | string | User modify date (RFC3339). |
| `database` | string | Database the user lives in. |
| `SQLServer` | string | Display name of the owning SQL Server. |
| `type` | string | `type_desc` (`SQL_USER` / `WINDOWS_USER` / …). |
| `defaultSchema` | string | Default schema (when present). |
| `serverLogin` | string | Mapped server login name (when the user maps to a login). |
| `memberOfRoles` | list\<string\> | Names of database roles the user belongs to. |
| `explicitPermissions` | list\<string\> | Explicitly granted/denied database permissions. |

## MSSQL_DatabaseRole

A database-level role (fixed or user-defined). Emitted by the database-principal asset when `type_desc == DATABASE_ROLE`. Model: [models/database_principal.py](src/openhound_mssql/models/database_principal.py).

- **Node id:** `<name>@<serverOID>\<dbName>`.
- **`environmentid`:** the server id.
- **Kinds:** `["MSSQL_DatabaseRole"]` (icon: `users`).
- **`name` / `displayname`:** `Name@DatabaseName`.

| Property | Type | Description |
|---|---|---|
| `principalId` | int | SQL `principal_id` of the role. |
| `createDate` | string | Role create date (RFC3339). |
| `modifyDate` | string | Role modify date (RFC3339). |
| `database` | string | Database the role lives in. |
| `SQLServer` | string | Display name of the owning SQL Server. |
| `isFixedRole` | bool | Whether this is a fixed database role. |
| `defaultSchema` | string | Default schema (when present). |
| `members` | list\<string\> | Member principal names. |
| `memberOfRoles` | list\<string\> | Names of database roles this role belongs to. |
| `explicitPermissions` | list\<string\> | Explicitly granted/denied database permissions. |

## MSSQL_ApplicationRole

A database application role. Emitted by the database-principal asset when `type_desc == APPLICATION_ROLE`. Model: [models/database_principal.py](src/openhound_mssql/models/database_principal.py).

- **Node id:** `<name>@<serverOID>\<dbName>`.
- **`environmentid`:** the server id.
- **Kinds:** `["MSSQL_ApplicationRole"]` (icon: `robot`).
- **`name` / `displayname`:** `Name@DatabaseName`.

| Property | Type | Description |
|---|---|---|
| `principalId` | int | SQL `principal_id` of the application role. |
| `createDate` | string | Create date (RFC3339). |
| `modifyDate` | string | Modify date (RFC3339). |
| `database` | string | Database the role lives in. |
| `SQLServer` | string | Display name of the owning SQL Server. |
| `defaultSchema` | string | Default schema (when present). |
| `memberOfRoles` | list\<string\> | Names of database roles this role belongs to. |
| `explicitPermissions` | list\<string\> | Explicitly granted/denied database permissions. |

## Computer

The AD computer account that hosts a SQL Server, plus any computer accounts that own SQL logins. Built in preprocess by the AD-node builder (a port of MSSQLHound's `createADNodes`) and emitted by the [ad_node.py](src/openhound_mssql/models/ad_node.py) asset. Suppressed entirely by `--skip-ad-nodes`.

- **Node id:** the AD object **SID**.
- **`environmentid`:** empty (AD principals are global BloodHound objects, not scoped to one SQL Server).
- **Kinds:** `["Computer", "Base"]` (no icon).
- **`name` / `displayname`:** the account name.

| Property | Type | Description |
|---|---|---|
| `SID` | string | Object SID. |
| `domain` | string | Domain name (when known). |
| `isDomainPrincipal` | bool | Whether this is a domain (vs. local) principal. |
| `SAMAccountName` | string | `sAMAccountName` (LDAP-enriched). |
| `isEnabled` | bool | Whether the AD account is enabled (LDAP-enriched). |
| `distinguishedName` | string | LDAP distinguished name (LDAP-enriched). |
| `userPrincipalName` | string | `userPrincipalName` (LDAP-enriched). |
| `DNSHostName` | string | DNS host name (computer accounts). |

> AD nodes set only the properties present on the row; absent properties are omitted.

## User

An AD user account that has a SQL Server login, a mapped credential, or a service-account / Kerberos relationship to a collected server. Same builder and asset as `Computer`. Suppressed by `--skip-ad-nodes`.

- **Node id:** the AD object **SID**.
- **`environmentid`:** empty.
- **Kinds:** `["User", "Base"]` (no icon).
- **`name` / `displayname`:** the account name (NetBIOS prefix stripped to the `user@DOMAIN` form).

| Property | Type | Description |
|---|---|---|
| `SID` | string | Object SID. |
| `domain` | string | Domain name (when known). |
| `isDomainPrincipal` | bool | Whether this is a domain (vs. local) principal. |
| `SAMAccountName` | string | `sAMAccountName` (LDAP-enriched). |
| `isEnabled` | bool | Whether the AD account is enabled (LDAP-enriched). |
| `distinguishedName` | string | LDAP distinguished name (LDAP-enriched). |
| `userPrincipalName` | string | `userPrincipalName` (LDAP-enriched). |
| `DNSHostName` | string | DNS host name (when present). |

## Group

An AD or local group that has a SQL Server login, or the Authenticated Users group used as the start of a coerce-and-relay edge. Same builder and asset as `Computer`. Suppressed by `--skip-ad-nodes`.

- **Node id:** the group **SID** (domain group), `S-1-5-11` / `<domain>-S-1-5-11` (Authenticated Users), or `<host>-<SID>` (a machine-local group).
- **`environmentid`:** empty.
- **Kinds:** `["Group", "Base"]` (no icon).
- **`name` / `displayname`:** the group name.

| Property | Type | Description |
|---|---|---|
| `SID` | string | Object SID (domain groups). |
| `domain` | string | Domain name (when known). |
| `isDomainPrincipal` | bool | Whether this is a domain (vs. local) group. |
| `SAMAccountName` | string | `sAMAccountName` (LDAP-enriched). |
| `isActiveDirectoryPrincipal` | bool | Set on local-group nodes that are not AD principals. |
| `isEnabled` | bool | Whether the group is enabled (LDAP-enriched). |
| `distinguishedName` | string | LDAP distinguished name (LDAP-enriched). |

---

# Edge Reference

> **49 edge kinds** — 28 always-traversable offensive edges, 6 "possible" (best-effort) edges that `--disable-possible-edges` flips to non-traversable, and 15 non-traversable informational permission edges that `--disable-nontraversable-edges` omits.

Every edge is emitted from the preproc-built `graph_edges` table by the generic [`GraphEdge`](src/openhound_mssql/models/graph_edge.py) model. Edges carry MSSQLHound's full documentation property bag — `general`, `windowsAbuse`, `linuxAbuse`, `opsec`, `references`, and (for composition edges) `composition` — plus `withGrant` (set when the underlying permission was `GRANT_WITH_GRANT_OPTION`) and the typed props described per edge below. The `traversable` flag is decided in preprocess from the kind partition (transcribed verbatim from MSSQLHound's `IsTraversableEdge`) and the `--disable-*` toggles, then read straight off the row.

**Traversability summary:**

- **Always traversable (28):** `MSSQL_MemberOf`, `MSSQL_IsMappedTo`, `MSSQL_Contains`, `MSSQL_Owns`, `MSSQL_HasLogin`, `MSSQL_ControlServer`, `MSSQL_ControlDB`, `MSSQL_ControlDBRole`, `MSSQL_ControlDBUser`, `MSSQL_ControlLogin`, `MSSQL_ControlServerRole`, `MSSQL_ImpersonateAnyLogin`, `MSSQL_AlterAnyRole`, `MSSQL_ChangeOwner`, `MSSQL_DBTakeOwnership`, `MSSQL_AddMember`, `MSSQL_ChangePassword`, `MSSQL_GrantAnyPermission`, `MSSQL_GrantAnyDBPermission`, `MSSQL_ExecuteAs`, `MSSQL_ExecuteAsOwner`, `MSSQL_ExecuteOnHost`, `MSSQL_LinkedAsAdmin`, `MSSQL_HostFor`, `MSSQL_GetTGS`, `MSSQL_GetAdminTGS`, `MSSQL_CoerceAndRelayToMSSQL`, and the BloodHound-native `HasSession`.
- **Possible / best-effort (6):** `MSSQL_LinkedTo`, `MSSQL_IsTrustedBy`, `MSSQL_ServiceAccountFor`, `MSSQL_HasDBScopedCred`, `MSSQL_HasMappedCred`, `MSSQL_HasProxyCred`. Traversable by default; `--disable-possible-edges` marks them non-traversable.
- **Non-traversable / informational (15):** `MSSQL_Alter`, `MSSQL_Control`, `MSSQL_Impersonate`, `MSSQL_ImpersonateDBUser`, `MSSQL_ImpersonateLogin`, `MSSQL_AlterAnyLogin`, `MSSQL_AlterAnyServerRole`, `MSSQL_AlterAnyDBRole`, `MSSQL_AlterAnyAppRole`, `MSSQL_AlterDB`, `MSSQL_AlterDBRole`, `MSSQL_AlterServerRole`, `MSSQL_Connect`, `MSSQL_ConnectAnyDatabase`, `MSSQL_TakeOwnership`. Default-included; `--disable-nontraversable-edges` omits them.

## Membership & structure

| Kind | Start → End | Traversable | Description |
|---|---|---|---|
| `MSSQL_MemberOf` | Login / ServerRole → ServerRole, or DatabaseUser / DatabaseRole / ApplicationRole → DatabaseRole | yes | The source principal is a direct member of the target role, granting it all of the role's permissions. (Explicit memberships only — no implicit `public`.) |
| `MSSQL_IsMappedTo` | Login → DatabaseUser | yes | The server login is mapped to the named database user. |
| `MSSQL_Contains` | Server → Database / Login / ServerRole; Database → DatabaseUser / DatabaseRole / ApplicationRole | yes | Structural containment: the target exists within the scope of the source. |
| `MSSQL_Owns` | Login / ServerRole → Database / ServerRole; database principal → DatabaseRole | yes | The source owns the target; ownership confers full control. Carries the typed `ownerPrincipalID` prop. |
| `MSSQL_HasLogin` | AD principal (`Base`) or local Group → Login | yes | An enabled domain principal (or local group) with CONNECT SQL has a login on the server, allowing authentication with its credentials. |

## Server-level control & impersonation

| Kind | Start → End | Traversable | Description |
|---|---|---|---|
| `MSSQL_ControlServer` | Login / ServerRole → Server | yes | CONTROL SERVER lets the source perform any action on the instance that is not explicitly denied (denies are ignored for sysadmin members). |
| `MSSQL_ControlDB` | database principal → Database | yes | CONTROL on a database grants all permissions on it and its descendant objects. |
| `MSSQL_ControlDBRole` | database principal → DatabaseRole | yes | CONTROL on a database role grants all defined permissions on the role, including adding members and changing ownership. |
| `MSSQL_ControlDBUser` | database principal → DatabaseUser | yes | CONTROL on a database user lets the source impersonate that user and act with its permissions. |
| `MSSQL_ControlLogin` | Login / ServerRole → Login | yes | CONTROL on a server login lets the source impersonate the target login. |
| `MSSQL_ControlServerRole` | Login / ServerRole → ServerRole | yes | CONTROL on a user-defined server role lets the source take ownership of, add members to, or change the owner of the role. |
| `MSSQL_Control` | Login / ServerRole / database principal → Server / Database / principal | no | The abstract CONTROL permission edge: CONTROL at a scope includes CONTROL on all securables under that scope. Emitted alongside the specific control sub-edge above. |
| `MSSQL_Impersonate` | Login / ServerRole → Login, or database principal → DatabaseUser | no | The abstract IMPERSONATE permission edge on a securable. |
| `MSSQL_ImpersonateAnyLogin` | Login / ServerRole → Server | yes | IMPERSONATE ANY LOGIN effectively lets the source impersonate any server login. |
| `MSSQL_ImpersonateDBUser` | database principal → DatabaseUser | no | IMPERSONATE or CONTROL on a database user lets the source impersonate that user. |
| `MSSQL_ImpersonateLogin` | Login / ServerRole → Login | no | IMPERSONATE or CONTROL on a login lets the source impersonate that login. |

## Alter & ownership

| Kind | Start → End | Traversable | Description |
|---|---|---|---|
| `MSSQL_Alter` | principal → Server / Database / principal | no | The abstract ALTER permission edge: change a securable's properties (except ownership). |
| `MSSQL_AlterDB` | database principal → Database | no | ALTER on a database grants effective ALTER ANY ROLE and ALTER ANY APPLICATION ROLE. |
| `MSSQL_AlterDBRole` | database principal → DatabaseRole | no | ALTER on a database role lets the source add members to it (fixed roles require db_owner). |
| `MSSQL_AlterServerRole` | Login / ServerRole → ServerRole | no | ALTER on a user-defined server role lets the source add members to it. |
| `MSSQL_AlterAnyLogin` | Login / ServerRole → Server | no | ALTER ANY LOGIN lets the source change the password of any SQL login other than `sa` (subject to the CVE-2025-49758 gate for privileged targets). |
| `MSSQL_AlterAnyServerRole` | Login / ServerRole → Server | no | ALTER ANY SERVER ROLE lets the source add members to any user-defined server role (and fixed roles it belongs to). |
| `MSSQL_AlterAnyRole` | database principal → Database | yes | ALTER ANY ROLE lets the source add members to any user-defined database role. |
| `MSSQL_AlterAnyDBRole` | database principal → Database | no | The db_securityadmin / ALTER-ANY-ROLE database-role-management edge. |
| `MSSQL_AlterAnyAppRole` | database principal → Database | no | ALTER ANY APPLICATION ROLE lets the source change an application role's password and act with its permissions. **Destructive — breaks the dependent application.** |
| `MSSQL_ChangeOwner` | principal → ServerRole / Database / DatabaseRole | yes | The source can change the owner of the target or its descendant objects. |
| `MSSQL_TakeOwnership` | principal → Server / Database / principal | no | TAKE OWNERSHIP on a securable. |
| `MSSQL_DBTakeOwnership` | database principal → Database / DatabaseRole | yes | The database-scoped take-ownership edge. |

## Privilege grants

| Kind | Start → End | Traversable | Description |
|---|---|---|---|
| `MSSQL_AddMember` | Login / ServerRole → ServerRole, or database principal → DatabaseRole | yes | The source can add members to the target role, granting them the role's permissions. |
| `MSSQL_ChangePassword` | Login / ServerRole / database principal → Login / ApplicationRole | yes | The source can change the target SQL login or application role password. Gated by CVE-2025-49758 for securityadmin / IMPERSONATE-ANY-LOGIN targets on patched servers. |
| `MSSQL_GrantAnyPermission` | ServerRole → Server | yes | The securityadmin fixed role can grant any server-level permission (including CONTROL SERVER) to any login. |
| `MSSQL_GrantAnyDBPermission` | DatabaseRole → Database | yes | The db_securityadmin fixed role can grant all database permissions, effectively granting full database control. |

## Execution context

| Kind | Start → End | Traversable | Description |
|---|---|---|---|
| `MSSQL_ExecuteAs` | Login / ServerRole → Login, or database principal → DatabaseUser | yes | CONTROL or IMPERSONATE on a login/user lets the source execute in that principal's context. |
| `MSSQL_ExecuteAsOwner` | Database → Server | yes | A TRUSTWORTHY database owned by a highly-privileged login lets EXECUTE AS OWNER code run with elevated server privileges. |
| `MSSQL_ExecuteOnHost` | Server → Computer | yes | Control of the instance allows OS command execution (e.g. `xp_cmdshell`) on the host as the service account. |

## Connection

| Kind | Start → End | Traversable | Description |
|---|---|---|---|
| `MSSQL_Connect` | Login / ServerRole → Server, or database principal → Database | no | CONNECT SQL (server) or CONNECT (database) permission on the securable. |
| `MSSQL_ConnectAnyDatabase` | Login / ServerRole → Server | no | The CONNECT ANY DATABASE permission (or the SQL 2022+ `##MS_DatabaseConnector##` fixed role). |

## Linked servers

| Kind | Start → End | Traversable | Description |
|---|---|---|---|
| `MSSQL_LinkedTo` | Server → Server | yes (possible) | The source SQL Server has a linked-server connection to the target; the real privileges depend on the remote login mapping. Carries the full linked-server property bag (`localLogin`, `remoteLogin`, `dataSource`, `provider`, the remote-privilege flags, …). |
| `MSSQL_LinkedAsAdmin` | Server → Server | yes | The linked-server connection resolves to an administrative remote login (sysadmin / securityadmin / CONTROL SERVER / IMPERSONATE ANY LOGIN), allowing full control of the remote server. |

## Credentials & proxies

| Kind | Start → End | Traversable | Description |
|---|---|---|---|
| `MSSQL_HasMappedCred` | Login → AD identity (`Base`) | yes (possible) | The login has a mapped credential that authenticates as the target domain account for external resources. Carries the typed `credentialId`. |
| `MSSQL_HasProxyCred` | Login → AD identity (`Base`) | yes (possible) | The login is authorized to use a SQL Agent proxy that runs job steps as the target domain account. Carries the typed `credentialId` and `proxyId`. |
| `MSSQL_HasDBScopedCred` | Database → AD identity (`Base`) | yes (possible) | The database holds a database-scoped credential that authenticates as the target domain account for external resources. Carries the typed `credentialId`. |

## Host, coercion & Kerberos

| Kind | Start → End | Traversable | Description |
|---|---|---|---|
| `MSSQL_HostFor` | Computer → Server | yes | The computer hosts the SQL Server instance. |
| `MSSQL_ServiceAccountFor` | AD identity (`Base`) → Server | yes (possible) | The domain account runs the SQL Server service. |
| `HasSession` | Computer → service-account (`Base`) | yes | The computer has a session for the (non-built-in) domain service account running SQL Server. BloodHound-native edge. |
| `MSSQL_GetTGS` | service-account (`Base`) → Login | yes | The service account can request Kerberos service tickets for domain accounts that have a login on this server (kerberoasting). |
| `MSSQL_GetAdminTGS` | service-account (`Base`) → Server | yes | The service account can request Kerberos service tickets for domain accounts with administrative privileges on this server. |
| `MSSQL_CoerceAndRelayToMSSQL` | Authenticated Users (Group) → Login | yes | A computer-account login exists on a server with EPA disabled, allowing the computer's authentication to be coerced and relayed to SQL Server for access. |

---

# Understanding the Codebase

```text
mssql/mssql/
├── extension.yaml               # Extension metadata (name, authors, credential/parameter descriptions)
├── pyproject.toml               # Deps (openhound-collector-common), Python version, entry point, dev tools
├── README.md                    # This file
├── docs/superpowers/specs/      # The authoritative design spec + staged plan
└── src/openhound_mssql/
    ├── main.py                  # CLI: collect/preproc/convert registration, flag→env map, per-target orchestration
    ├── source.py                # DLT source + emit resources (push→pull bridge from the worker pool)
    ├── auth.py                  # CollectionConfig + SQL/LDAP credential assembly
    ├── ids.py                   # Stable ObjectIdentifier construction + server-OID rewrite
    ├── graph.py                 # MSSQLNode + per-kind NodeProperties + MSSQLEdgeProperties dataclasses
    ├── cve.py                   # CVE-2025-49758 version → verdict lookup
    ├── transforms.py            # DuckDB SQL transforms run during preprocess
    ├── lookup.py                # Cached MSSQLLookup queries used during convert
    ├── ad_nodes.py              # preproc AD-node builder (port of createADNodes)
    ├── edge_rules.py            # preproc: flattens derived edges into the graph_edges table (applies --disable-* toggles)
    ├── convert_pipeline.py      # convert-reads-DuckDB pipeline (self-run dlt + opengraph_file + no-op source)
    ├── output_adapter.py        # OpenGraph → MSSQLHound zip envelope adapter (for the existing validators)
    ├── kinds/                   # nodes.py (kind strings + icons) · edges.py (kind strings + traversability partitions)
    ├── models/                  # @app.asset graph models: server, server_principal, database, database_principal, ad_node, graph_edge (+ _common, members)
    ├── collection/              # run.py (worker pool) · targets.py (resolution) · server.py (per-server query driver) · queries.py · ad_resolve.py
    └── edges/                   # derive.py (server/db edges) · derive_ad.py (AD/linked/cred/Kerberos edges) · properties.py (edge property generators)
```

### Key concepts

- **Per-target collection, ps1-ordered.** [main.py](src/openhound_mssql/main.py)'s `collect_mssql` resolves targets, then runs a worker pool ([collection/run.py](src/openhound_mssql/collection/run.py)) that connects to each server and drives the SQL queries in the exact order of `MSSQLHound.ps1` ([collection/server.py](src/openhound_mssql/collection/server.py)). A push→pull `StreamBridge` (from `openhound-collector-common`) hands the rows to the DLT extract pass, which writes one JSONL table per query.
- **The shared library.** The generic, service-agnostic infrastructure lives in the sibling package **`openhound-collector-common`** (`../../openhound-collector-common`): the impacket TDS/TLS/NTLM/Kerberos/EPA client, the LDAP/AD client, WMI, DNS discovery, the SOCKS5 dialer, the work-queue/streams engine, the DLT source-bridge and convert pipeline, the DuckDB-safety helpers, the logging context, and the generic `GraphEdge`/stub-node graph base classes. The `openhound_mssql` package imports these and adds only MSSQL-specific logic.
- **EPA detection** is performed before database authentication by sending an unauthenticated TDS prelogin and manipulating the NTLM channel-binding / target-name AV pairs, capping TLS at 1.2 so the `tls-unique` channel binding is available.
- **Edge derivation is a faithful port of MSSQLHound's Go `createEdges`.** [edges/derive.py](src/openhound_mssql/edges/derive.py) covers the server- and database-level permission, membership, ownership, fixed-role, and trustworthy edges; [edges/derive_ad.py](src/openhound_mssql/edges/derive_ad.py) covers the AD / linked-server / credential / service-account / Kerberos / coercion edges. Both run in preprocess and flatten into the `graph_edges` table via [edge_rules.py](src/openhound_mssql/edge_rules.py); convert just emits that table.
- **Convert enrichment** is driven by [lookup.py](src/openhound_mssql/lookup.py) (DuckDB-backed, cached) reading the derived tables built by [transforms.py](src/openhound_mssql/transforms.py).

### Project standards

This extension follows the rules in [AGENTS.md](AGENTS.md) and the [`.agents/`](.agents/) directory — the `.agents/standards/openhound.md` standards and the `openhound` skill's task references (`plan-collector`, `graph-schema`, `register-extension`, `source-collection`, `add-asset`, `preproc-lookup`, `validate-extension`). The authoritative design reference is [docs/superpowers/specs/2026-06-25-mssql-collector-design.md](docs/superpowers/specs/2026-06-25-mssql-collector-design.md).

---

# Testing Changes

Use an isolated environment for validation so you don't disturb the repo-local `.venv`:

```powershell
$env:UV_PROJECT_ENVIRONMENT = "$env:TEMP\oh-mssql-venv"
uv run pytest
```

The unit tests live under [tests/unit/](tests/unit/) and cover ID construction, the CVE table, the kind constants, the node/edge property models, target parsing, the DuckDB transforms, the AD-node builder, the server/database and AD edge derivation, and the output adapter:

```powershell
uv run pytest tests/unit              # fast unit tests
uv run ruff check src tests           # lint
uv run mypy src/openhound_mssql       # type-check
```

The **integration comparison harness** under [tests/integration/](tests/integration/) runs the live three-stage Python collector against the `mayyhem.com` lab as three users (`lowpriv`, `roanalyst`, `domainadmin`), reshapes its OpenGraph output into the MSSQLHound zip envelope via [output_adapter.py](src/openhound_mssql/output_adapter.py), and checks it with the **existing** MSSQLHound validators (the Go `go test -tags integration -run TestIntegrationValidateZip` and/or the PowerShell `Invoke-MSSQLHoundUnitTests.ps1 -Action Test`). It also runs the Go binary as an oracle and diffs total node count, total edge count, and the edge-type set between the Python and Go output. The harness requires the prepared lab fixtures (manufactured once by the MSSQLHound setup phase as `MAYYHEM\domainadmin`) and network reachability to `ps1-db.mayyhem.com` (TCP/1433) and the domain controller `dc.mayyhem.com`.

---

# Contributing

1. **Read the standards first.** [AGENTS.md](AGENTS.md), the `.agents/standards/` documents (`openhound.md` for collector rules, `workflow.md` for the order of work), and the `openhound` skill references under [`.agents/skills/openhound/`](.agents/skills/openhound/). The design spec under [docs/superpowers/specs/](docs/superpowers/specs/) is the source of truth for graph shape and the locked design decisions; MSSQLHound's Go source is the source of truth for per-edge logic.

2. **Keep changes separable from SCCM.** This extension only touches `mssql/mssql/` and the shared `openhound-collector-common/` library so it can be committed on its own branch without disturbing the SCCM extension.

3. **Run the checks** (lint, type-check, unit tests) before finishing, and validate against `.agents/skills/openhound/references/validate-extension.md`.

4. **Keep the README honest.** This file documents **what the code does**, not what it might do — the Node Reference and Edge Reference list only the kinds the collector actually emits, and the CLI table covers the full flag surface. When you add or change user-facing behavior, update the matching section here in the same change.
