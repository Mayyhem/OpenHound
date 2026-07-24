# Low-privilege live comparison — CMBP vs OpenHound (2026-07-23)

Live run against the **mayyhem.com** lab (site **PS1**, DC `dc.mayyhem.com`) as a
**non-privileged domain user, `MAYYHEM\lowpriv`**. Both tools were run with and
without the "possible edges" option, then compared.

## How each tool was run as `lowpriv`

- **OpenHound** takes explicit credentials, so it was run directly:
  `openhound collect sccm <out> -m All -d mayyhem.com --dc dc.mayyhem.com -u lowpriv -p password [--disable-possible-edges] --run-integration-tests --compare-to-zip <cmbp.zip>`
- **ConfigManBearPig.ps1 has no credential parameter** — it authenticates as
  whatever Windows logon context it runs in (here, `domainadmin`). It was launched
  under `lowpriv`'s **network** identity via a `CreateProcessWithLogonW` +
  `LOGON_NETCREDENTIALS_ONLY` shim (`Run-AsNetOnly.ps1`), the scriptable equivalent
  of `runas /netonly:MAYYHEM\lowpriv`. Verified: local token stayed `domainadmin`,
  but the LDAP *whoami* over the wire returned `u:mayyhem\lowpriv`.

### Environment caveats (worked around, not affecting validity)
- This host (`ps1-dev2`, 12 GB) sits ~98% physical memory (hypervisor ballooning).
  CMBP's default `-MemoryThresholdPercent 95` aborted its first run before the
  AdminService/HTTP/SMB phases; re-run with `-MemoryThresholdPercent 100` (a real
  OOM never occurred — commit had headroom).
- CMBP `-ZipDir` bug (uses the dir as the `Compress-Archive -DestinationPath`, so
  the zip lands as `<dir>.zip`). Worked around by dropping `-ZipDir` and setting the
  launcher's working directory instead.

## Headline results

| Run | Nodes | Edges | Integration (P/F/S) |
|---|---:|---:|---|
| CMBP — possible ON  | 52 | 146 | — |
| CMBP — possible OFF | 39 | 106 | — |
| **OpenHound — possible ON**  | **21** | **9** | **8 / 64 / 1** |
| **OpenHound — possible OFF** | **21** | **9** | **8 / 64 / 1** |

*(Baseline for reference: a full `domainadmin` collect is ~239 nodes / 419 edges and
passes ~68 integration cases.)*

## Finding 1 — OpenHound collects far less than CMBP as `lowpriv`, by design

Every **privileged** source is denied to `lowpriv`, identically for both tools:
- **RemoteRegistry**: binds, then `rpc_s_access_denied (0x5)` on every key (SMB
  signing, NTLM policy, MSSQL config, SMS site/component/current-user).
- **AdminService**: HTTP **404 / "not a reachable provider"** on every SMS Provider
  candidate — `lowpriv` cannot query the AdminService.
- **MSSQL**: TCP 1433 closed on reachable hosts; no EPA probe possible.

What **differs** is how each tool handles that denial:
- **CMBP fabricates the privileged attack graph by *assumption*.** It infers site
  database servers from LDAP and then emits the entire MSSQL internal structure
  (databases, logins, users, `db_owner`, `sysadmin`) and the standard SCCM
  permission / coerce-and-relay edges **whether or not it could confirm them**. Its
  own log says *"Assuming that ps1-db… is a site database server… may produce false
  positives."* Result: 106–146 edges, most unconfirmed.
- **OpenHound only emits what it actually confirmed.** With every privileged source
  denied, it emits just the 21 nodes / 9 edges it could derive from LDAP + SPNs:
  2 `SCCM_Site`, 15 `Computer`, 1 `User`, 3 `MSSQL_Server` (from `MSSQLSvc` SPNs),
  and those servers' baseline `MSSQL_HostFor` / `MSSQL_ExecuteOnHost` / `HasSession`
  edges. It does **not** invent the privileged scaffolding.

This is the core takeaway: **CMBP is assumption-heavy (more edges, more false
positives at low privilege); OpenHound is evidence-based (only confirmed edges).**

## Finding 2 — the possible-edges flag behaves differently for the two tools

- **CMBP**: possible ON → OFF drops **13 nodes / 40 edges**, almost entirely the
  CmRcService-SPN "client device" fan-out (`SCCM_ClientDevice` 14→1, `SameHostAs`
  29→3, `SCCM_HasClient` 15→1). Its MSSQL/coerce assumption edges persist either way.
- **OpenHound**: possible ON and OFF are **identical (21/9)**. It found the same 14
  CmRcService-SPN hosts CMBP did, but created **0** possible client devices — its
  builder needs the **root-site anchor** that only privileged (AdminService)
  collection provides, which `lowpriv` never obtained. So the flag has nothing to
  act on at low privilege. (Under `domainadmin` the flag does matter — prior runs
  showed the client-device fan-out.)

## Finding 3 — `--compare-to-zip` (OpenHound A vs CMBP zip B)

| | possible ON | possible OFF |
|---|---:|---:|
| nodes only in OpenHound (A) | 1 | 1 |
| nodes only in CMBP (B)      | 32 | 19 |
| edges only in OpenHound (A) | 3 | 3 |
| edges only in CMBP (B)      | 140 | 100 |

The "only in CMBP" bulk is exactly the assumption scaffolding from Finding 1
(MSSQL internals, SCCM permission/coerce edges, client-device fan-out) plus CMBP's
**old edge names** (`SameHostAs`, `LocalAdminRequired`, `CoerceAndRelaytoSMB` typo,
`CoerceAndRelayToMSSQL`) vs OpenHound's `SCCM_`/`MSSQL_` names. The 3 "only in
OpenHound" edges are the same *kinds* as CMBP has (`HasSession`,
`MSSQL_ExecuteOnHost`, `MSSQL_HostFor`) but with different node-id formats, so they
don't align on the `(start, kind, end)` key.

## Finding 4 — integration tests: 8 PASS / 64 FAIL / 1 SKIP (both modes)

The fixtures are anchored to the full `domainadmin` graph, so **FAIL here means
"`lowpriv` can't reach it," not "collector broke."** All 64 failures are `not found`
(privileged edges/nodes) or two count checks (`SCCM_Site` found 2, expected 3 — the
secondary site isn't emitted as an `SCCM_Site` by either tool at low privilege).

Of the 8 passes, only **3 are substantive** — the SPN-derived MSSQL facts
(`MSSQL_Server` ×3, `MSSQL_HostFor` ×3, `MSSQL_ExecuteOnHost` ×3). The other 5 pass
**vacuously**: three are *negative* assertions ("X should NOT exist") satisfied
because nothing was collected, and two are structural invariants that hold trivially
over an empty set. In other words, low-priv OpenHound can confirm essentially one
real thing on this lab: the MSSQL server instances (via `MSSQLSvc` SPNs) and their
host relationships.

## Bottom line

- Both tools authenticated correctly as `MAYYHEM\lowpriv`; neither silently used
  `domainadmin`.
- At low privilege the two tools **diverge sharply**: CMBP emits a large,
  largely-**unconfirmed/assumed** attack graph (106–146 edges); OpenHound emits a
  small, **fully-confirmed** graph (9 edges) and refuses to guess.
- The possible-edges flag reshapes CMBP's output but is a **no-op for low-priv
  OpenHound** (no privileged anchor to build possible edges from).
- OpenHound's integration suite correctly reports that a non-privileged principal
  can prove almost none of the privileged SCCM/MSSQL attack graph on this lab.

## Artifacts (gitignored except this file + harness scripts)
- CMBP zips: `cmbp/pe-on/bloodhound-sccm-20260723-163652.zip`,
  `cmbp/pe-off/bloodhound-sccm-20260723-164206.zip`
- OpenHound graphs + `integration_results-*.json` + `compare-*.json` under
  `openhound/pe-on/` and `openhound/pe-off/`
- CMBP logs: `cmbp/cmbp_pe-on.log`, `cmbp/cmbp_pe-off.log` (+ `_console.txt`)
- OpenHound logs: `openhound/pe-*/collect_full_*.log`, `collect_issues_*.log`
- Harness: `Run-AsNetOnly.ps1`, `netonly-probe.ps1`, `run-cmbp-both.ps1`,
  `run-openhound-both.ps1`
