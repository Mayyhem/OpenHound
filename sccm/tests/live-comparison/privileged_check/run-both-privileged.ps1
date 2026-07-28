<#
Runs CMBP.ps1 and the OpenHound SCCM extension as the CURRENT logon context
(MAYYHEM\domainadmin), both flag states each, into fresh directories.

Why this exists: every change in the low-priv-assumed-edges plan landed in code the
PRIVILEGED path also runs through -- _site_hierarchy now consumes every site-code source
and infers missing site types, _node_computer gained four arms, _edge_mssql_structural
gained a resolve-or-drop guard, and the assumed families gained provenance columns. So a
privileged run is the regression gate for the whole plan, and the low-priv harness next
door cannot provide it.

Differences from ..\lowpriv_check\run-openhound-both.ps1:
  * No Run-AsNetOnly shim. CMBP authenticates as whatever context it runs in, and that is
    already domainadmin here.
  * No -u/-p for OpenHound: omitting them selects integrated auth as the current user.
  * Integration tests are asserted with the FULL fixture set (privileged=True), including
    the Tier-D RBAC cases a low-priv run legitimately cannot satisfy.

--clean is MANDATORY on every OpenHound run and each CMBP run gets its own empty dir:
re-running into a used directory does not overwrite raw data, it APPENDS a dlt load
package, and preprocess reads every .jsonl.gz per table -- so the previous run's rows are
UNIONed into this run's graph. Measured 2026-07-28: 11 of 24 raw tables held rows from two
different dates, with exit code 0 and fresh graph/ timestamps hiding it completely.

NOTE: as of 2026-07-28 `uv run` cannot resolve this project -- the in-flight packaging
migration points openhound-collector-common at an unpublished PyPI package and its
documented `just dev` path does not exist yet. Until that lands, temporarily restore a
[tool.uv.sources] editable path entry in sccm/sccm/pyproject.toml, and RESTORE IT
AFTERWARDS (byte-exactly; that file belongs to the packaging workstream).
#>
$ErrorActionPreference = "Continue"
$base = $PSScriptRoot
$sccm = "C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm"
$cmbp = Join-Path $sccm "powershell_deprecated\ConfigManBearPig.ps1"

"Running as: {0}\{1}" -f $env:USERDOMAIN, $env:USERNAME | Write-Host
if ($env:USERNAME -ne 'domainadmin') {
    Write-Host "  !! expected to run as domainadmin; results will not be the privileged baseline"
}

$results = @()

foreach ($m in @(@{tag = 'pe-on'; dp = $false }, @{tag = 'pe-off'; dp = $true })) {

    # ---------- CMBP ----------
    $cmbpDir = Join-Path $base "cmbp\$($m.tag)"
    if (Test-Path $cmbpDir) { Remove-Item -Recurse -Force $cmbpDir }
    New-Item -ItemType Directory -Force -Path $cmbpDir | Out-Null
    $cmbpLog = Join-Path $base "cmbp\cmbp_$($m.tag).log"
    $cmbpCon = Join-Path $base "cmbp\cmbp_$($m.tag)_console.txt"
    # -MemoryThresholdPercent 100 disables CMBP's self-imposed memory guard; this host sits
    # near its ceiling from hypervisor ballooning and CMBP otherwise aborts before the
    # AdminService/HTTP phases. A real OOM has never occurred.
    # HASHTABLE splat, not an array. Array splatting binds elements positionally, which on
    # 2026-07-28 bound '-DisablePossibleEdges' as the VALUE of -MemoryThresholdPercent
    # ("Cannot convert value ... to type System.Int32") and killed both CMBP runs at 0s.
    # A hashtable names every parameter explicitly, and a switch is passed as $true.
    $cmbpArgs = @{
        CollectionMethods      = 'All'
        Domain                 = 'mayyhem.com'
        DomainController       = 'dc.mayyhem.com'
        MemoryThresholdPercent = 100      # int, not '100'
        LogFile                = $cmbpLog
    }
    if ($m.dp) { $cmbpArgs['DisablePossibleEdges'] = $true }

    Write-Host "=== CMBP [$($m.tag)] as $env:USERNAME -> $cmbpDir"
    $t0 = Get-Date
    Push-Location $cmbpDir
    try { & $cmbp @cmbpArgs *> $cmbpCon } finally { Pop-Location }
    $cmbpSec = [int]((Get-Date) - $t0).TotalSeconds
    $zip = Get-ChildItem $cmbpDir -Filter *.zip -EA SilentlyContinue |
        Sort-Object LastWriteTime -Desc | Select-Object -First 1
    Write-Host ("   CMBP {0}s  zip: {1}" -f $cmbpSec, $(if ($zip) { $zip.Name } else { 'NONE' }))

    # ---------- OpenHound ----------
    $ohDir = Join-Path $base "openhound\$($m.tag)"
    New-Item -ItemType Directory -Force -Path $ohDir | Out-Null
    $ohCon = Join-Path $base "openhound\openhound_$($m.tag)_console.txt"
    # No -u/-p: integrated auth as the current user. --clean guarantees a cold start.
    # --run-all so this produces a graph, matching what CMBP does in one invocation.
    $ohArgs = @('run', 'openhound', 'collect', 'sccm', $ohDir,
        '-m', 'All', '-d', 'mayyhem.com', '--dc', 'dc.mayyhem.com',
        '--clean', '--run-all', '--run-integration-tests')
    if ($zip) { $ohArgs += @('--compare-to-zip', $zip.FullName) }
    if ($m.dp) { $ohArgs += '--disable-possible-edges' }

    Write-Host "=== OpenHound [$($m.tag)] as $env:USERNAME -> $ohDir"
    $t1 = Get-Date
    Push-Location $sccm
    try {
        # --run-integration-tests exits non-zero if any fixture case fails. For the
        # PRIVILEGED run that is a real failure (the full set must pass), unlike the
        # low-priv harness where Tier-D misses are expected -- so surface the code.
        & uv @ohArgs *> $ohCon
        $rc = $LASTEXITCODE
    } finally { Pop-Location }
    $ohSec = [int]((Get-Date) - $t1).TotalSeconds
    Write-Host ("   OpenHound {0}s  exit={1}{2}" -f $ohSec, $rc,
        $(if ($rc -ne 0) { '   <-- INVESTIGATE: privileged run must pass the full fixture set' } else { '' }))

    $results += ("{0,-7} CMBP={1,5}s  OpenHound={2,5}s  oh_exit={3}" -f $m.tag, $cmbpSec, $ohSec, $rc)
}

Write-Host "`n===== PRIVILEGED MATRIX ====="
$results | ForEach-Object { Write-Host $_ }
Write-Host @"

Next, per plan Task 10 Step 4/4b -- nothing on the CLI passes `privileged` yet, so assert
the FULL fixture set in-process:

  from pathlib import Path
  from openhound_sccm.integration import run_integration_tests
  run_integration_tests(Path(r'$base\openhound\pe-on\graph'), privileged=True)   # must be 0

and confirm the privileged-only families are still present (SCCM_FullAdministrator,
SCCM_IsAssigned, SCCM_AllPermissions, the admin-user/security-role/collection nodes,
MSSQL_ServiceAccountFor via SMS_SCI_SysResUse), that no privileged-sourced row carries
assumed=true, and that the CAS site-type inference fired ZERO times (adminservice supplies
real types here, so its INFO line should be absent).
"@
