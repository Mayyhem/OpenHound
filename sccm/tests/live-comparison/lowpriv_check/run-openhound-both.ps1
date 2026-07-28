<#
Runs the SCCM OpenHound extension twice as MAYYHEM\lowpriv (explicit -u/-p; no
netonly needed - the extension builds its own auth from the flags), once with
possible edges ON and once with --disable-possible-edges. Each run self-chains
--run-all, then:
  --run-integration-tests : asserts the built graph vs the mayyhem fixtures
                            (writes integration_results-<ts>.json; exits non-zero
                            if any case fails - tolerated here).
  --compare-to-zip <cmbp> : deep-diffs this run's graph against the matching CMBP
                            zip (writes compare-<ts>.json; always exit 0).
CMBP must have produced its zips first (this reads them from ..\cmbp\<tag>).
#>
$ErrorActionPreference = "Continue"
$base    = $PSScriptRoot
$sccm    = "C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm"

function Invoke-OpenHoundRun {
    param([string]$Tag, [bool]$DisablePossible)

    $outDir  = Join-Path $base "openhound\$Tag"
    $console = Join-Path $base "openhound\openhound_${Tag}_console.txt"
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null

    $cmbpZip = Get-ChildItem -Path (Join-Path $base "cmbp\$Tag") -Filter *.zip -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $cmbpZip) { Write-Host "  !! no CMBP zip for [$Tag]; skipping --compare-to-zip"; }

    $args = @(
        "run","openhound","collect","sccm", $outDir,
        "-m","All",
        "-d","mayyhem.com",
        "--dc","dc.mayyhem.com",
        "-u","lowpriv",
        "-p","password",
        # MANDATORY here: this script reuses openhound\<tag> across runs, and dlt APPENDS a
        # new load package beside the old ones rather than replacing them. Preprocess reads
        # every .jsonl.gz per table, so without --clean the previous run's rows are UNIONed
        # into this run's graph -- and any table this run finds empty keeps the OLD rows
        # entirely. Measured 2026-07-28: 11 of 24 raw tables held rows from two different
        # dates, with exit code 0 and fresh graph/ timestamps hiding it completely.
        "--clean",
        "--run-integration-tests"
    )
    if ($cmbpZip) { $args += @("--compare-to-zip", $cmbpZip.FullName) }
    if ($DisablePossible) { $args += "--disable-possible-edges" }

    Write-Host "==================================================================="
    Write-Host "OpenHound run [$Tag]  disable-possible-edges=$DisablePossible"
    Write-Host "  OutDir      : $outDir"
    Write-Host "  compare-to  : $(if ($cmbpZip) { $cmbpZip.FullName } else { '(none)' })"
    Write-Host "  Console log : $console"
    Write-Host "==================================================================="
    $start = Get-Date
    Push-Location $sccm
    try {
        # --run-integration-tests exits non-zero when any fixture case fails; that
        # is expected for a lowpriv collection, so we capture but do not abort on it.
        & uv @args *> $console
        $rc = $LASTEXITCODE
    } finally { Pop-Location }
    $dur = [int]((Get-Date) - $start).TotalSeconds
    Write-Host "  -> DONE in ${dur}s (collect exit code $rc)"

    $ir = Get-ChildItem -Path $outDir -Filter "integration_results-*.json" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    $cmp = Get-ChildItem -Path $outDir -Filter "compare-*.json" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    Write-Host "  integration_results : $(if ($ir) { $ir.FullName } else { '(missing)' })"
    Write-Host "  compare json        : $(if ($cmp) { $cmp.FullName } else { '(missing)' })"
}

Invoke-OpenHoundRun -Tag "pe-on"  -DisablePossible $false
Invoke-OpenHoundRun -Tag "pe-off" -DisablePossible $true
Write-Host "ALL OPENHOUND RUNS COMPLETE"
