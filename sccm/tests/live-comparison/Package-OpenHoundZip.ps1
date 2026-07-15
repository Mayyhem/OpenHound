<#
.SYNOPSIS
    Package the OpenHound SCCM collector's convert output into a bloodhound-sccm-<timestamp>.zip
    so Invoke-ConfigManBearPigUnitTests.ps1 -SkipCollection can consume it.

.DESCRIPTION
    OpenHound's `convert` stage writes loose JSON files (sccm_nodes-*.json, sccm_edges-*.json,
    ad_nodes-*.json, ad_edges-*.json), each already shaped as { "graph": { "nodes":[], "edges":[] } }
    -- the exact structure the test kit's Get-OutputFromZip merges. It just never zips them.

    The kit globs the most-recent "bloodhound-sccm*.zip" in the directory it runs from and reads
    every *.json inside. We include BOTH the sccm_* (SCCM/MSSQL) and ad_* (Computer/User/Group base
    node) payloads so edge endpoints resolve, mirroring how CMBP bundles AD nodes in its single JSON.

.PARAMETER GraphDir
    The OpenHound convert output directory (contains the *_nodes-*.json / *_edges-*.json files).

.PARAMETER DestDir
    Where to write the zip. The test kit must run from this directory (default: the sccm/ folder
    that holds Invoke-ConfigManBearPigUnitTests.ps1), because it globs the CWD for the zip.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$GraphDir,
    [Parameter(Mandatory = $true)][string]$DestDir
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path $GraphDir)) {
    throw "GraphDir not found: $GraphDir"
}

# Collect the OpenGraph JSON payloads. Accept any *.json so the packaging survives if the
# per-run part counter (-1/-2/...) or the split naming changes.
$jsonFiles = Get-ChildItem -Path $GraphDir -Filter '*.json' -File
if (-not $jsonFiles) {
    throw "No .json files found under $GraphDir - did convert run?"
}
Write-Host "Found $($jsonFiles.Count) JSON file(s) to package:" -ForegroundColor Cyan
$jsonFiles | ForEach-Object { Write-Host "  $($_.Name)  ($([math]::Round($_.Length/1KB,1)) KB)" }

$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$zipName = "bloodhound-sccm-openhound-$timestamp.zip"
$zipPath = Join-Path $DestDir $zipName

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path ($jsonFiles.FullName) -DestinationPath $zipPath -Force

# Bump the mtime so this zip is unambiguously the most-recent bloodhound-sccm*.zip in DestDir,
# guaranteeing -SkipCollection selects it over any earlier CMBP zip.
(Get-Item $zipPath).LastWriteTime = Get-Date

Write-Host "Wrote $zipPath" -ForegroundColor Green
$zipPath
