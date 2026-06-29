# MSSQL OpenHound Collector — Design Spec

> Authoritative design reference for porting **MSSQLHound** (PowerShell `MSSQLHound.ps1` v1.0 + Go `mssqlhound` v2.0.3) to a native **OpenHound/DLT** extension in `mssql/mssql`. Companion to the staged plan in `../plans/2026-06-25-mssql-collector-plan.md`. Source of truth for graph shape and per-edge logic is the Go implementation under `MSSQLHound/internal/`; the original `.ps1` is the source of truth for collection *order* and *intent*.

## Locked decisions (from grilling, 2026-06-25)

| # | Decision | Choice |
|---|---|---|
| D1 | Language / runtime | **Pure Python, in-process only.** No child processes, no native binaries, no FreeTDS/ODBC. TDS+TLS+NTLM+Kerberos+EPA via `impacket` + (Windows) `pywin32`, exactly as `sccm/sccm/src/openhound_sccm/clients/mssql_epa.py` already proves. The no-subprocess rule binds the **shipped collector**, not the test workflow. |
| D2 | Feature scope | **Full parity now** — explicit + SPN/LDAP target discovery, `scan-all-computers`, AD node creation, linked-server enumeration + recursion, credentials/proxies, CVE-2025-49758 check, SOCKS5 proxy, per-target logging, concurrency. |
| D3 | `test-epa-matrix` subcommand | **Out of scope as a collector feature.** EPA *detection during collection* is in scope. The registry-cycling verifier already exists in pure Python at `sccm/sccm/debug_epa_matrix.py` — reuse it for EPA validation; do not re-port. |
| D4 | Test oracle | Collector is pure-Python; **the test harness MAY** run the Go binary, `go test -tags integration`, and `MSSQLHound.ps1` via the shell as the comparison oracle. |
| D5 | Acceptance bar | **Do not port the unit-test suite.** Build a harness that runs the **Python** collector live as the 3 users, then run the **existing** validators (`go test -tags integration -run TestIntegrationValidateZip` with `MSSQL_ZIP=…`, and/or PS1 `Invoke-MSSQLHoundUnitTests.ps1 -Action Test -InputFile`) against its output `.json`. Cross-check by running the Go binary as oracle and diffing counts per user. |
| D6 | Output → validator bridge | Keep OpenHound's native OpenGraph convert output as the real BloodHound-ingest deliverable. Add a **pure-Python adapter** that reshapes it into MSSQLHound's zip-of-per-server-JSON envelope for the existing validators. Do not fork the validators. |
| D7 | Lab fixture environment | Run the **existing** setup phase once as `MAYYHEM\domainadmin` (`go test -tags integration -run TestIntegrationSetup`, or PS1 `-Action Setup`) to manufacture all edge-type fixtures + AD objects on `ps1-db`. Both collectors then run against that prepared state. |
| D8 | Phase split vs "exact order" | **Order preserved within `collect`**: per-target SQL queries run in the exact `.ps1` order. `preproc` builds DuckDB derived/lookup tables; `convert` runs edge derivation + emits the graph. Edge-*emission* order is irrelevant (validators pattern-match), so derivation moves to convert for scalability. |
| D9 | Comparison targets + auth | Primary target `ps1-db.mayyhem.com` (Go default; where setup manufactures edges + 10 loopback linked servers). The 3 users authenticate with explicit domain creds (`MAYYHEM\user` + password) over **impacket NTLM with EPA channel binding** — the path the Go binary uses for domain creds. Linked-server recursion exercises `cas-db`/`ps1-sec` as discovered. |
| D12 | Kerberos CLI | **Collapse the five Go Kerberos flags (`-k/--kerberos`, `--krb5-configfile`, `--krb5-credcachefile`, `--krb5-keytabfile`, `--krb5-realm`) into a single `--ticket`** — a base64-encoded Kerberos ticket (`.kirbi` / KRB-CRED) for pass-the-ticket; **Kerberos only, no NTLM fallback**. Mirrors SCCM's `--ticket` (env `SOURCES__MSSQL__KERBEROS_TICKET`; Typer param `ticket`). impacket loads the KRB-CRED into an in-memory ccache. The **LDAP/AD auth path gets matching options** `--ldap-ticket` (base64 KRB-CRED) and `--ldap-nt-hash`, alongside `--ldap-user`/`--ldap-password`. |
| D11 | Property naming | **Use MSSQLHound's EXACT original property names** (verbatim from the `.ps1` / Go output) — `isMixedModeAuthEnabled`, `windowsAbuse`, `linuxAbuse`, `ownerPrincipalID`, `SQLServer`, `credentialId`, `proxyId`, `isTrustworthy`, etc. — so they render correctly in BloodHound **entity panels**. NO snake_case conversion. (Superseded an earlier snake_case decision — reverted 2026-06-25.) Consequence: the MSSQL domain property fields in `graph.py` keep their original names; our OpenGraph **schema** declares those names; the **validation adapter (D6) does NOT remap property keys** — it only reshapes the envelope. OpenHound's framework-mandated base `NodeProperties` fields (`name`, `displayname`, `environmentid`, `last_seen`) remain as the framework requires (additive; harmless to validators and panels). Source of truth for names = Go `internal/types/types.go` JSON tags + the property keys set in `collector.go`/`edges.go`. |
| D10 | Code reuse strategy | **Build a shared library now.** New repo-root sibling package **`openhound-collector-common/`** (own `pyproject.toml`) holding the generalized generic collector infra (see §2.1). `mssql/mssql` depends on it via a **local path / uv-workspace** dependency. **SCCM is left untouched** (no regression, MSSQL branch stays separable = `openhound-collector-common/` + `mssql/mssql/` only). File a `gtk` **SCCM-agent ticket** to migrate SCCM onto the shared library later. The shared lib is *sourced/generalized from* SCCM's working implementations but SCCM keeps its own copies until that ticket is done. **(Update 2026-06-25:** the pre-existing `collector-utils`/`openhound-collector-utils` package was found to be **dead** — SCCM dropped `TargetQueue` for its own `phased_pipeline` engine and nothing imports it. Per user decision it was **deleted**, and SCCM's now-vestigial dep was removed from `sccm/sccm/pyproject.toml` + `uv.lock` regenerated (only that one entry removed; no other SCCM change). The new `openhound-collector-common` is created fresh.**)** |
| D13 | Windows dlt/log fixes | **Do NOT copy SCCM's Windows-on-Windows fixes** (dlt pipeline-dir lock, midnight log-rollover `WinError 32`) — per the user, they don't reliably work. Don't port them or build the diagnostic/ordered file handlers around them. Handle pragmatically only if a concrete failure appears during testing (e.g., a unique per-run pipeline working dir), and surface it; otherwise accept/log and move on. |

## Project rules that shape this work (from CLAUDE.md / AGENTS.md)

- Only modify code under `mssql/mssql/`. Never modify OpenHound core. May reference `sccm/sccm`, git history, tickets, plans.
- Port **all** node/edge properties (entity panel parity), even when an edge already conveys the relationship.
- Prefer readability over efficiency; simplify; no backward-compat baggage.
- Move work to `preproc`/`convert` when it improves scalability.
- Logs at appropriate level for every if/else and try/except, or a comment explaining the absence.
- Tests live under `mssql/mssql/tests/`, organized.
- Don't `git commit` — the user commits after testing.
- Track work with the `gtk` CLI ticket system.
- Update the README for any user-facing change (sections enumerated in CLAUDE.md).
- Surface decisions made on the basis of SCCM prior art before executing.

## 1. Service identity

| Field | Value |
|---|---|
| Source name (`OpenHound("mssql", …)`) | `mssql` |
| `source_kind` | `MSSQL_Base` (matches MSSQLHound metadata so BloodHound ingest + validators agree) |
| Python package | `openhound_mssql` |
| Graph prefix | `MSSQL_` (verbatim, to match existing kind strings) |
| Entry point | `mssql = "openhound_mssql.main:app"` (already wired) |

## 2. Architecture overview

```
collect (per-target, ps1-ordered SQL → raw JSONL)
  │   clients/: pure-Python TDS+auth (impacket), LDAP/AD (ldap3), SID resolution
  ▼
preproc (load JSONL → DuckDB; build derived + lookup tables)
  │   transforms.py: nested role membership, effective permissions, principal maps,
  │                  linked-server hierarchy, fixed-role permission expansion
  ▼
convert (DuckDB → OpenGraph nodes/edges with full properties)
  │   models/: one asset per node kind; edge generators ported from edges.go
  │   uses the SCCM "convert reads DuckDB via a self-run dlt pipeline + no-op source" pattern
  ▼
OpenGraph output  ──(pure-Python adapter, D6)──▶  MSSQLHound zip  ──▶  existing validators
```

Mirrors the SCCM extension's divergences (it is OpenHound's worked example of a non-REST, Windows-auth, multi-host collector). The generic infrastructure is **factored into the shared library** `openhound-collector-common` (D10); the `mssql` extension imports it and adds only MSSQL-specific logic.

### 2.1 Shared library `openhound-collector-common` (D10)

New repo-root sibling package, generalized from `sccm/sccm/src/openhound_sccm/`. Contents (SCCM-specific names/phases stripped):

| Module (proposed `openhound_collector_common/…`) | Sourced from SCCM | Purpose |
|---|---|---|
| `clients/mssql.py` | `clients/mssql_epa.py` | impacket TDS + TLS-over-TDS + NTLMv2(+EPA CBT/SPN) + Kerberos + SSPI; EPA detection. TLS-1.2 cap. |
| `clients/auth.py` | `clients/http_auth.py` | Kerberos AP-REQ/SPNEGO + NTLM + current-user SSPI token minting (controllable GSS flags). |
| `clients/ad.py` | `clients/ad.py` | LDAP transport×bind waterfall (lockout-safe), SPN search, SID→AD-object resolution. |
| `clients/wmi.py` | `clients/wmi.py` | impacket DCOM + pywin32 WMI (`Win32_GroupUser`, `Win32_Service`). |
| `discovery/dns.py` | `collectors/dns.py` | DC/SRV/A discovery, DNS resolver override (proxy-aware). |
| `phased_pipeline/` | `phased_pipeline/` | stdlib work-queue + streams + engine (multi-host, recursion-capable). |
| `dlt/source_bridge.py` | `source.py` helpers | push→pull `_drain_stream` + `parallelized` emit-resource pattern + shared-state globals. |
| `dlt/convert_pipeline.py` | `convert_pipeline.py` | convert-reads-DuckDB (self-run pipeline + `opengraph_file` + no-op source). |
| `dlt/duckdb_safe.py` | `transforms.py` helpers | `_safe`/`_ensure_columns`/`_arr` against dlt column-dropping. |
| `logging/log_context.py` | `log_context.py` | VERBOSE tier, `[target]`/`[phase]` contextvar tagging, ordered/diagnostic handlers. (No Windows log-rollover fix — D13.) |
| `graph/stub_node.py`, `graph/graph_edge.py` | `models/stub_node.py`, `models/graph_edge.py` | edge-endpoint stub backfill + generic `GraphEdge` + traversable allow-list. |
| `proxy/socks.py` | *new* (port Go `internal/proxydialer`) | pure-Python SOCKS5 dialer for `--proxy` (no SCCM equivalent found). |

**SCCM stays untouched.** A `gtk` SCCM-agent ticket tracks migrating SCCM onto this library later. The MSSQL-specific layer (Typer command + `SOURCES__MSSQL__*` flag→env map, MSSQL kinds/IDs/models, collection SQL, edge derivation, CVE table, output adapter) lives in `mssql/mssql/src/openhound_mssql/` and *uses* the shared modules above.

## 3. Dependencies

**`openhound-collector-common/pyproject.toml`** owns the third-party auth/transport deps (the shared clients live there):

```toml
dependencies = [
  "impacket>=0.13.1",            # TDS, NTLMv2 (+CBT/SPN AV pairs), Kerberos, SPNEGO, PtH — pure Python
  "ldap3>=2.10.2rc4",            # LDAP SPN discovery, AD object/SID resolution (ENCRYPT/TLS_CHANNEL_BINDING)
  "dnspython>=2.4.0",            # DC/SPN DNS SRV + A resolution
  "pyasn1", "pyasn1-modules",    # impacket Kerberos ASN.1 (transitive; pin)
  "cryptography>=42.0.0",        # TLS cert hash for tls-server-end-point fallback
  "pywin32>=306; sys_platform == 'win32'",         # current-user SSPI / SSO; Windows SID lookup
  "winkerberos>=0.10.0; sys_platform == 'win32'",  # ldap3 SASL GSSAPI (current-user TGT) on Windows
]
```

**`mssql/mssql/pyproject.toml`** depends on the shared library via a local path/uv-workspace dependency (alongside the existing `openhound` git dep):

```toml
dependencies = [
  "openhound-collector-common",  # local path dep (uv workspace / tool.uv.sources path)
]
# under [tool.uv.sources] (or equivalent): openhound-collector-common = { path = "../../openhound-collector-common", editable = true }
```

### 3.1 Dependency licenses (extension + shared lib are MIT)

| Package | License | Class |
|---|---|---|
| impacket | "Apache modified" (Impacket license) | Permissive |
| ldap3 | **LGPL-3.0-or-later** | Weak copyleft |
| dnspython | ISC | Permissive |
| pyasn1 / pyasn1-modules | BSD-2-Clause / BSD | Permissive |
| cryptography | Apache-2.0 OR BSD-3-Clause | Permissive |
| pywin32 | PSF | Permissive |
| winkerberos | Apache-2.0 | Permissive |
| (transitive) pycryptodomex / pyOpenSSL / six | BSD-2+public-domain / Apache-2.0 / MIT | Permissive |

All permissive except **`ldap3` (LGPL-3.0-or-later)**. Consumed as an unbundled pip dependency (not vendored), so LGPL copyleft does not reach our MIT code — the only obligation is user-replaceability, satisfied by it being a normal dependency. SCCM already ships `ldap3`, so no new posture. `openhound-collector-common` and `mssql` are both **MIT** (LICENSE file in each). Do not vendor `ldap3`/`impacket` source into our packages — depend on them.

**Critical EPA constraint:** every EPA/auth TLS path MUST force `context.maximum_version = ssl.TLSVersion.TLSv1_2`. TLS 1.3 removed `tls-unique` (RFC 8446); SChannel won't accept `tls-server-end-point` as a substitute. Both the Go code and impacket's TDS-8 path cap at 1.2; impacket's 7.x `set_tls_context` does **not**, so cap it explicitly.

## 4. CLI surface (Typer command `collect mssql`, mirroring Go `mssqlhound`)

All flags below map to `SOURCES__MSSQL__<NAME>` env vars (CLI wins). Grouped for `--help` like the Go binary. `output_path` is the OpenHound-supplied positional.

**Authentication — SQL:** `-u/--user`, `-p/--password`, `--nt-hash`, `--ticket` (base64 `.kirbi`/KRB-CRED, pass-the-ticket, Kerberos-only — D12).
**Authentication — LDAP/AD** (SPN discovery, SID resolution, EPA testing; separate from SQL creds): `--ldap-user`, `--ldap-password`, `--ldap-nt-hash`, `--ldap-ticket` (base64 `.kirbi`/KRB-CRED).
Mutual exclusions: SQL — `--nt-hash`⊕`--password`, `--ticket`⊕`--password`, `--ticket`⊕`--nt-hash`. LDAP — `--ldap-nt-hash`⊕`--ldap-password`, `--ldap-ticket`⊕`--ldap-password`, `--ldap-ticket`⊕`--ldap-nt-hash`. (LDAP creds still fall back to SQL creds when domain-shaped and LDAP creds unset, per Go.)

**Connection/Collection:** `-t/--targets` (`[user:pass@]host` | `host:port` | `host\instance` | `MSSQLSvc/host:port` | comma list | file path; empty ⇒ SPN enum), `-d/--domain`, `--dc`, `--dns-resolver`, `-x/--proxy` (SOCKS5), `-v/--verbose`, `--debug`.

**Collection toggles:** `-A/--scan-all-computers`, `--scan-all-computer-ports` (default `1433`), `--skip-private-address`, `--domain-enum-only`, `--skip-linked-servers`, `--collect-from-linked`, `--skip-ad-nodes`, `--disable-nontraversable-edges`, `--disable-possible-edges`, `--skip-ip-dedupe`.

**Performance:** `--linked-timeout` (300), `--port-check-timeout` (2), `--memory-threshold` (90), `-w/--workers` (0 = sequential).

**Output:** `--temp-dir`, `--log-per-target`. (OpenHound owns the final output path / format; `--zip-dir` and `-B/--bloodhound*` upload are **superseded by OpenHound's native pipeline & upload** — see §10.)

Target/credential parsing must reproduce Go's `extractAndApplyCredentials`/`classifyTarget` semantics (verified by `cmd/mssqlhound/main_test.go`): split inline creds on last `@`/first `:`, file-vs-list-vs-single detection, `--dc` auto-resolve via SRV `_ldap._tcp` then A record, LDAP-cred fallback to SQL creds when domain-shaped.

## 5. Node catalog (10 kinds) — `kinds/nodes.py`

source_kind `MSSQL_Base`. MSSQL_* nodes carry an `icon`; AD nodes carry a second kind `"Base"` and **no** icon.

> **Property names below are MSSQLHound's exact originals and are used VERBATIM in our output (D11)** — no renaming. The graph property dataclasses (`graph.py`) declare these exact field names (in addition to OpenHound's mandated base fields `name`/`displayname`/`environmentid`/`last_seen`). The adapter does not rename keys.

| Kind | Stable ID | Icon (font-awesome / color) | Key properties (port ALL; see go-edges-schema brief / collector.go) |
|---|---|---|---|
| `MSSQL_Server` | `<computerSID-or-lowerhost>:<instanceName≠MSSQLSERVER else port>` | `server` `#42b9f5` | name, hostname, fqdn, sqlServerName, version, versionNumber, edition, productLevel, isClustered, port, isMixedModeAuthEnabled, instanceName, forceEncryption, strictEncryption, extendedProtection, servicePrincipalNames[], serviceAccount, databases[], linkedToServers[], isLinkedServerTarget, hasLinksFromServers[], CVE-2025-49758 fields, domainPrincipalsWith{Sysadmin,ControlServer,Securityadmin,ImpersonateAnyLogin}[], isAnyDomainPrincipalSysadmin |
| `MSSQL_Login` | `<name>@<serverOID>` | `user-gear` `#dd42f5` | name, principalId, createDate, modifyDate, SQLServer, type, disabled, defaultDatabase, isActiveDirectoryPrincipal, activeDirectorySID, activeDirectoryPrincipal, databaseUsers[], memberOfRoles[], explicitPermissions[] |
| `MSSQL_ServerRole` | `<name>@<serverOID>` | `users-gear` `#6942f5` | name, principalId, createDate, modifyDate, SQLServer, isFixedRole, members[], memberOfRoles[], explicitPermissions[] |
| `MSSQL_Database` | `<serverOID>\<dbName>` | `database` `#f54242` | name, databaseId, createDate, compatibilityLevel, isReadOnly, isTrustworthy, isEncrypted, SQLServer, SQLServerID, ownerLoginName, ownerPrincipalID, OwnerObjectIdentifier, collationName |
| `MSSQL_DatabaseUser` | `<name>@<serverOID>\<dbName>` | `user` `#f5ef42` | name (`Name@DatabaseName`), principalId, createDate, modifyDate, database, SQLServer, type, defaultSchema, serverLogin, memberOfRoles[], explicitPermissions[] |
| `MSSQL_DatabaseRole` | `<name>@<serverOID>\<dbName>` | `users` `#f5a142` | name, principalId, createDate, modifyDate, database, SQLServer, isFixedRole, defaultSchema, members[], memberOfRoles[], explicitPermissions[] |
| `MSSQL_ApplicationRole` | `<name>@<serverOID>\<dbName>` | `robot` `#6ff542` | name, principalId, createDate, modifyDate, database, SQLServer, defaultSchema, memberOfRoles[], explicitPermissions[] |
| `Computer` (+`Base`) | computer SID | none | name, DNSHostName, domain, isDomainPrincipal, SID, SAMAccountName, (+LDAP: isEnabled, distinguishedName, userPrincipalName) |
| `Group` (+`Base`) | `S-1-5-11`/`<domain>-S-1-5-11`/`<host>-<SID>` | none | name, isActiveDirectoryPrincipal |
| `User` (+`Base`) | SID | none | name, SID, domain, isDomainPrincipal, SAMAccountName, isEnabled, distinguishedName, DNSHostName, userPrincipalName |

`type_desc → kind` mapping (collector_test.go `TestNodeKinds`): SERVER_ROLE→ServerRole; SQL_LOGIN/WINDOWS_LOGIN/WINDOWS_GROUP→Login; DATABASE_ROLE→DatabaseRole; SQL_USER/WINDOWS_USER→DatabaseUser; APPLICATION_ROLE→ApplicationRole. AD user node name strips NetBIOS prefix (`CONTOSO\jdoe`→`jdoe@CONTOSO.COM`).

ID rewriting: when a server is re-keyed (hostname ID → resolved SID ID), string-replace `@{old}` and `{old}\` across all principal/db/permission IDs (collector.go:2066-2115).

## 6. Edge catalog — `kinds/edges.py`

Master list = the Go `knownEdgeTypes` (38) plus the additional registered kinds. Emit with full property bags (`general`/`windowsAbuse`/`linuxAbuse`/`opsec`/`references`, empties filtered; `composition` Cypher for the composition set; `withGrant` when `GRANT_WITH_GRANT_OPTION`). Start/end kinds, producing logic, and traversability per the ps1 brief §4 and go-edges-schema brief §2. Authoritative per-edge logic: `MSSQLHound/internal/collector/collector.go` (`createEdges`, `createFixedRoleEdges`) + `internal/bloodhound/edges.go` generators.

**Traversable offensive:** `MSSQL_AddMember`, `MSSQL_ChangeOwner`, `MSSQL_ChangePassword`, `MSSQL_ExecuteAs`, `MSSQL_ControlServer`, `MSSQL_ControlDB`, `MSSQL_ImpersonateAnyLogin`, `MSSQL_Owns`, `MSSQL_MemberOf`, `MSSQL_Contains`, `MSSQL_IsMappedTo`, `MSSQL_HasLogin`, `MSSQL_GrantAnyPermission`, `MSSQL_GrantAnyDBPermission`, `MSSQL_ExecuteAsOwner`, `MSSQL_ExecuteOnHost`, `MSSQL_HostFor`, `MSSQL_GetTGS`, `MSSQL_GetAdminTGS`, `MSSQL_LinkedAsAdmin`, `MSSQL_CoerceAndRelayToMSSQL`, plus control/alter sub-kinds (`MSSQL_ControlDBRole/DBUser/Login/ServerRole`, `MSSQL_AlterDB/DBRole/ServerRole`, `MSSQL_DBTakeOwnership`).

**Non-traversable** (emitted only with `--disable-nontraversable-edges` off→ default includes them; flag disables; see edges.go `IsTraversableEdge`): `MSSQL_Alter`, `MSSQL_Control`, `MSSQL_Impersonate`, `MSSQL_ImpersonateDBUser`, `MSSQL_ImpersonateLogin`, `MSSQL_AlterAnyLogin`, `MSSQL_AlterAnyServerRole`, `MSSQL_AlterAnyDBRole`, `MSSQL_AlterAnyAppRole`, `MSSQL_Connect`, `MSSQL_ConnectAnyDatabase`, `MSSQL_TakeOwnership`. (Correction: `MSSQL_AlterAnyRole` is **traversable** — Go `edges.go IsTraversableEdge` does not list it; `kinds/edges.py` follows the Go source of truth. `MSSQL_CanExecuteOnServer`/`MSSQL_CanExecuteOnDB` are dead in Go — declared but never emitted, absent from `knownEdgeTypes` — so they're omitted from the producible-edge set.)

**"Possible" edges** (traversable by default; `--disable-possible-edges` makes non-traversable + rewrites schema): `MSSQL_LinkedTo`, `MSSQL_IsTrustedBy`, `MSSQL_ServiceAccountFor`, `MSSQL_HasDBScopedCred`, `MSSQL_HasMappedCred`, `MSSQL_HasProxyCred`.

**Non-`MSSQL_` kinds also emitted:** `HasSession` (Computer→service-account Base), `MemberOf` (BloodHound-native, local-group member SID→local group).

**Edges with extra typed props** injected at construction (not from generator): `ownerPrincipalID` on `MSSQL_Owns`; `credentialId` on `MSSQL_HasMappedCred`/`MSSQL_HasDBScopedCred`; `credentialId`+`proxyId` on `MSSQL_HasProxyCred`.

**The 3 load-bearing exact counts** (validators assert these): `MSSQL_LinkedTo`=10, `MSSQL_LinkedAsAdmin`=8, `MSSQL_ServiceAccountFor`=1 (glob `S-1-5-21-*`→`S-1-5-21-*` on the manufactured fixtures).

CVE gate: `MSSQL_ChangePassword` suppressed for targets with securityadmin/IMPERSONATE ANY LOGIN when the server is **patched** against CVE-2025-49758 (version table in `internal/collector/cve.go`); emitted regardless when unpatched.

## 7. Output JSON envelope (must match for the adapter, D6)

```json
{ "$schema": "https://raw.githubusercontent.com/MichaelGrafnetter/EntraAuthPolicyHound/refs/heads/main/bloodhound-opengraph.schema.json",
  "metadata": { "source_kind": "MSSQL_Base" },
  "graph": { "nodes": [ {"id","kinds","properties","icon?"} ], "edges": [ {"start":{"value"},"end":{"value"},"kind","properties?"} ] } }
```
AD-object content uses `"metadata": {}` (no source_kind). Edges deduped by full JSON serialization. The adapter (§ D6) consumes OpenHound's native convert output and re-emits this envelope so `TestIntegrationValidateZip` (`bloodhound.ReadFromFile`) and the PS1 `-InputFile` validator read it unchanged.

**CVE hyphen-key remap (D11 caveat):** MSSQLHound emits CVE keys with hyphens (`isVulnerableToCVE-2025-49758`, `CVE-2025-49758_patchKB`, `CVE-2025-49758_requiredVersion`, `CVE-2025-49758_updateName`), which aren't valid Python identifiers. `graph.py` declares them with underscores (`isVulnerableToCVE_2025_49758`, …); **node emission (Stage 5) or the adapter must remap these specific keys to the hyphenated form at emit time**. This is the one place exact-name parity needs an explicit per-key fix.

**Property names (D11):** native output uses MSSQLHound's exact property names verbatim, so the adapter does **no key renaming** (except the CVE hyphen remap above) — it only reshapes the envelope (OpenHound entries → `{$schema, metadata, graph:{nodes,edges}}`, `start/end`→`{"value"}`). OpenHound's mandated base fields (`displayname`, `environmentid`, `last_seen`) are additive and may be left in place (harmless to the validators, and they enrich the entity panel).

## 8. Collection order inside `collect` (per-target; EXACT ps1 order — D8)

Per server (ps1 brief §5; go-arch brief §3 `CollectServerInfo`):
1. Resolve hostname→SID; build `serverObjectIdentifier`. 2. Build serverString. 3. **EPA detection** (unauth TDS PRELOGIN + NTLM AV-pair manipulation) *before* DB auth. 4. Open SQL connection (auth priority §9); short-name retry; partial-output-from-SPN path on failure. 5. FQDN via `DEFAULT_DOMAIN()`. 6. `@@VERSION`. 7. `SERVERPROPERTY('InstanceName')`. 8. `IsIntegratedSecurityOnly`→mixed-mode. 9. merge SPN/service-account data. 10. EPA via registry (only if still unset). 11. service accounts (`dm_server_services`→regread→`SYSTEM_USER`→WMI). 12. server principals (`sys.server_principals`, version-aware, ORDER BY principal_id). 13. credential mappings (`server_principal_credentials`, 2012+). 14. server role memberships. 15. server permissions. 16. process server principals. 17. effective high-priv (nested role BFS). 18. local Windows group members (Windows/WMI). 19. databases (`state=0` ORDER BY name) → per db: ChangeDatabase, trustworthy, db principals, owner, db role members, db permissions (class 0,4), process, db-scoped creds. 20. linked servers (recursive T-SQL, level≤10) unless skipped. 21. credentials (`sys.credentials`). 22. SQL Agent proxies (`msdb..sysproxies`). 23. enabled domain principals w/ CONNECT SQL. 24. close.

Each step yields raw rows tagged by table → JSONL. Steps 16/17/19g (principal processing, effective-permission BFS, role expansion) and **all node/edge derivation** move to `preproc`/`convert` (D8); `collect` only runs SQL + emits raw rows.

## 9. Auth matrix (clients/mssql_client.py, reuse `mssql_epa.py`)

| Mode | How | Difficulty |
|---|---|---|
| SQL auth (`-u`/`-p`, SQL login) | impacket `tds.MSSQL.login` over TLS | Easy |
| Domain creds (`MAYYHEM\u`+`-p`) — **the 3-user path** | impacket NTLMv2 + EPA channel binding (`generate_cbt_from_tls_unique`, `getNTLMSSPType3(channel_binding_value=…, service=SPN)`) | Easy |
| Pass-the-hash (`--nt-hash`) | impacket `LMHASH:NTHASH` | Easy |
| Pass-the-ticket (`--ticket`, base64 `.kirbi`/KRB-CRED) | impacket loads KRB-CRED → in-memory ccache → AP-REQ/SPNEGO (pattern: `auth.py::KerberosNegotiator`). Kerberos only, no NTLM fallback (D12). LDAP path uses `--ldap-ticket` the same way. | Medium |
| Current-user SSPI (Windows SSO) | `pywin32` `sspi.ClientAuth` + `SECBUFFER_CHANNEL_BINDINGS` (pattern: `mssql_epa.py::login_sspi`); gate behind `sys.platform=="win32"` | Medium |
| TLS-over-TDS / TDS 8.0 strict | impacket `set_tls_context` / `_setup_tds8` (cap TLS 1.2) | Easy |

Connection strategy waterfall (encrypt vs strict vs no-encrypt; FQDN + short-host; reverse-DNS cert name), **stop on auth error** (lockout safety), as Go `connectNative`/`IsAuthError`. EPA "Allowed/Required" ambiguity under SSPI: report literal `"Allowed/Required"` (see memory `feedback_epa_uncertainty_label`).

## 10. Preproc / lookup needs

DuckDB derived tables (transforms.py) and `MSSQLLookup` methods (lookup.py) for cross-table resolution that `convert` can't do from JSONL alone:
- principal maps (principal_id → OID/name/type) per server and per database (edge target resolution).
- nested server-role & database-role membership closure (`Get-NestedRoleMembership`).
- effective permissions BFS (`Get-EffectivePermissions`) → domainPrincipalsWith* + fixed-role implicit permissions (`$fixedServerRolePermissions`/`$fixedDatabaseRolePermissions`).
- linked-server hierarchy + remote-privilege flags.
- login↔credential, proxy↔principal, db-scoped-cred resolution; SID→AD-object resolution cache.

convert uses the SCCM `convert_pipeline` pattern (self-run dlt pipeline reading DuckDB via the open lookup connection + `opengraph_file`, framework gets a no-op source).

## 11. Validation & 3-user comparison harness (D5–D7, D9)

`tests/integration/` (pure Python; MAY shell out to the oracle per D4):
1. **Setup once** as `MAYYHEM\domainadmin`: invoke existing `go test -tags integration -run TestIntegrationSetup` (or PS1 `-Action Setup`) against `ps1-db.mayyhem.com` to manufacture fixtures + AD objects.
2. For user ∈ {`lowpriv`, `roanalyst`, `domainadmin`} (passwords per task brief; creds in `sccm/sccm/debug_epa_matrix.py`):
   a. Run Python collector (`collect mssql` → preproc → convert) as that user.
   b. Adapter → MSSQLHound zip.
   c. Run existing validator on the zip: `MSSQL_ZIP=<zip> go test -tags integration -run TestIntegrationValidateZip ./internal/collector/...` and/or PS1 `-Action Test -InputFile`.
   d. Run Go binary as oracle for the same user; validate its zip; **diff** total nodes, total edges, and edge-type set (Python vs Go).
3. **Teardown** after.

**Acceptance:** for all 3 users — existing validators PASS on Python output; and total nodes / total edges / edge-type set match the Go binary's output. If a discrepancy is a bug in the *original* preventing a passing test, fix it in all collectors (per task brief) and surface it.

Lab: DC `dc.mayyhem.com` (10.2.10.100); SQL `ps1-db` (10.2.11.51, primary), `cas-db` (10.2.10.51), `ps1-sec` (10.2.11.200); router 10.2.10.254. Run from `admin-ps1-dev2` (Windows, logged in as domainadmin). Check 443/AdminService + port 1433 reachability first (memory `sccm-http-lab-validation`).

## 12. Logging (mirror SCCM)

stdlib `logging.getLogger(__name__)`; register a `VERBOSE` tier (INFO>VERBOSE>DEBUG); `[target]` contextvar tagging via a filter; `-v`→INFO, `-vv`→VERBOSE, `--debug`→DEBUG (incl. EPA/TLS/NTLM diagnostics). Set `RUNTIME__LOG_LEVEL`/`RUNTIME__LOG_CLI_LEVEL` before pipeline run. `--log-per-target` → per-target file capture. Color/level conventions follow the Go slog handler (info/cyan, success/green, warn/yellow, error/red). A log line per if/else and try/except (project rule).

## 13. README (per CLAUDE.md required sections)

Logo/Intro · TOC · Quick Start (Install deps / Collect / Preprocess / Convert / Upload, with copy-paste `mayyhem.com` examples) · Collection Overview · System Requirements (Windows vs Linux auth split) · Limitations · Command Line Options (grouped tables, short+long aliases, `SOURCES__MSSQL__*` env note, status markers) · Graph Model · Node Reference (one `##` per kind, identity bullets + property table) · Edge Reference (one `##` per kind) · Understanding the Codebase · Testing Changes · Contributing. README is code-truth: omit unimplemented nodes/edges; mark unimplemented CLI with 🚧 (memory `readme-code-truth-scope`).

## 14. Known risks

1. TLS 1.3 vs `tls-unique` (cap at 1.2 everywhere) — #1 EPA risk.
2. impacket 7.x `set_tls_context` doesn't cap TLS max — verify/patch on every EPA path.
3. dlt snake_cases camelCase keys + drops absent/all-NULL columns → coalesce `SELECT` BinderException; use the SCCM `_safe`/`_ensure_columns`/`_arr` defenses (memory `sccm-dlt-coalesce-gotchas`).
4. SSPI is Windows-only and can't distinguish EPA Allowed vs Required (report `"Allowed/Required"`).
5. Edge dedup is by full JSON — LinkedTo fixtures rely on unique `LocalLogin` per link to avoid collapsing the count of 10.
6. Windows-on-Windows dlt/log issues (pipeline-dir lock, midnight log rollover `WinError 32`) exist, but **SCCM's fixes don't reliably work — do NOT copy them (D13)**. If a concrete failure appears in testing, handle minimally (e.g. unique per-run pipeline working dir) and surface it; otherwise accept/log.
7. `impacket`/`pywin32` not yet declared in `mssql` pyproject (present only transitively via SCCM) — declare explicitly.
