# MSSQL collector — integration acceptance harness

`run_comparison.py` is the **Stage 8.2 three-user acceptance gate**. It proves that
our pure-Python OpenHound MSSQL collector produces the same BloodHound OpenGraph
output as the original MSSQLHound Go binary (the "oracle"), for three principals
with different SQL Server visibility.

This is a **test harness**, not part of the shipped collector, so it is allowed to
shell out to Go, PowerShell, and our own `openhound` CLI. The pure-Python rule
binds the collector, not this script.

## What it does

```
setup (once, as domainadmin)                       # Go TestIntegrationSetup
  └─ for each user in {domainadmin, roanalyst, lowpriv}:
        a. OUR pipeline:  collect → preprocess → convert → to_mssqlhound_zip → ours.zip
        b. ORACLE:        mssqlhound.exe ... --zip-dir → mssql-bloodhound-*.zip
        c. VALIDATE:      Go TestIntegrationValidateZip + PS1 -Action Test
                          on BOTH ours.zip and the Go zip (Go zip = control)
        d. DIFF:          nodes, edges, set of edge kinds + per-kind counts
teardown (always, in finally)                       # Go TestIntegrationTeardown
report: per-user table + domainadmin 38-type coverage + 3 load-bearing counts
```

The three principals (all password `password`):

| User                 | SQL privilege          | Expected output                       |
|----------------------|------------------------|---------------------------------------|
| `MAYYHEM\domainadmin`| sysadmin + local admin | full visibility, all 38 edge types    |
| `MAYYHEM\roanalyst`  | MSSQL `public` only    | limited set                           |
| `MAYYHEM\lowpriv`    | none (connect fails)   | partial / SPN-only (no abort on fail) |

## Acceptance target

- **domainadmin**: our zip passes the Go ValidateZip, all 38 known edge types are
  present, with the load-bearing exact counts `LinkedTo=10`, `LinkedAsAdmin=8`,
  `ServiceAccountFor=1`; ours total nodes/edges/edge-kinds equal the Go binary's.
- **roanalyst / lowpriv**: ours equals the Go binary's output for that user.

The script exits `0` only when domainadmin matches Go **and** its Go-ValidateZip
passes **and** roanalyst + lowpriv match Go; otherwise it exits `1`.

## Running

```bash
# Go must be on PATH; the prebuilt oracle binary must exist at MSSQLHound/mssqlhound.exe.
export PATH="$PATH:/c/Program Files/Go/bin"
export UV_PROJECT_ENVIRONMENT="C:/Users/domainadmin/AppData/Local/Temp/oh-mssql-venv"

python mssql/mssql/tests/integration/run_comparison.py
```

The harness creates a fresh full-path temp dir (`oh-mssql-accept-*` under the system
temp — **not** the 8.3 scratchpad), one subdir per user, and removes it at the end
(unless `OH_KEEP_WORKDIRS=1`).

### Environment knobs (all have lab defaults)

| Variable             | Default                          | Purpose                                          |
|----------------------|----------------------------------|--------------------------------------------------|
| `OH_REPO_ROOT`       | auto-detected from this file     | repo root                                        |
| `MSSQL_SERVER`       | `ps1-db.mayyhem.com`             | SQL Server target                                |
| `MSSQL_DOMAIN`       | `mayyhem.com`                    | AD domain                                        |
| `MSSQL_DC`           | `dc.mayyhem.com`                 | domain controller                                |
| `MSSQL_PASSWORD`     | `password`                       | shared lab password for all three users          |
| `UV_PROJECT_ENVIRONMENT` | `…/oh-mssql-venv`            | uv env for our collector                         |
| `OH_SKIP_SETUP`      | unset                            | `1` skips the Go setup step (fixtures present)   |
| `OH_SKIP_TEARDOWN`   | unset                            | `1` skips teardown (debugging only)              |
| `OH_KEEP_WORKDIRS`   | unset                            | `1` leaves the per-user temp dirs for inspection |

## How results are parsed

- **Go ValidateZip** logs `Results: <P> passed, <F> failed`; we parse that line and
  also honor the test's exit code (`go test` fails on the first failing subtest).
- **PS1 `-Action Test -InputFile <zip>`** loads the zip (no SQL connection) and
  prints an `OFFENSIVE Perspective Summary:` block; we sum the `Passed`/`Failed`
  lines **inside that block only** (anchored on the summary header to avoid
  double-counting the earlier per-perspective summary). The PS1 process exit code is
  not a reliable pass/fail signal, so PS1 "ok" = `failed == 0 and passed > 0`.
- **Diff** reads `graph.nodes` / `graph.edges` from every `*.json` inside both zips,
  counts nodes and edges, and groups edges by `kind`.
