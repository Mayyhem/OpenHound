<#
Runs ConfigManBearPig.ps1 twice as MAYYHEM\lowpriv (via netonly), once with
possible edges ON (default) and once with -DisablePossibleEdges. Each run gets
its own ZipDir so its single output .zip is easy to locate. CMBP has no
credential parameter, so each invocation is wrapped in the netonly launcher.
#>
$ErrorActionPreference = "Stop"
$base = $PSScriptRoot
$cmbp = "C:\Users\domainadmin\Desktop\OpenHound\sccm\sccm\powershell_deprecated\ConfigManBearPig.ps1"

function Invoke-CmbpRun {
    param([string]$Tag, [bool]$DisablePossible)

    $zipDir  = Join-Path $base "cmbp\$Tag"
    $logFile = Join-Path $base "cmbp\cmbp_$Tag.log"
    $console = Join-Path $base "cmbp\cmbp_${Tag}_console.txt"
    $runner  = Join-Path $base "cmbp\_runner_$Tag.ps1"
    New-Item -ItemType Directory -Force -Path $zipDir | Out-Null

    # Generate a small child runner so we avoid nested command-line quoting and
    # can redirect ALL of CMBP's console streams (*>) to a file.
    #
    # NOTE: we deliberately do NOT pass -ZipDir. CMBP has a bug (line ~10318)
    # where -ZipDir is used as the full Compress-Archive -DestinationPath, so the
    # zip lands as "<dir>.zip" beside the dir instead of a named zip inside it.
    # Its default branch writes bloodhound-sccm-<ts>.zip into the CURRENT
    # directory, and the netonly launcher sets the child's working directory to
    # $zipDir -- so the zip lands correctly there.
    #
    # -MemoryThresholdPercent 100 disables CMBP's self-imposed memory guard. This
    # lab VM sits ~98% physical (hypervisor ballooning), which is NOT a real OOM
    # (commit has headroom); the default 95% guard was aborting collection before
    # the AdminService/HTTP/SMB phases ran.
    $disableArg = if ($DisablePossible) { " -DisablePossibleEdges" } else { "" }
    $runnerBody = @"
`$ErrorActionPreference = 'Continue'
Set-Location '$zipDir'
& '$cmbp' -CollectionMethods All -Domain mayyhem.com -DomainController dc.mayyhem.com ``
    -MemoryThresholdPercent 100 -LogFile '$logFile'$disableArg *> '$console'
"@
    Set-Content -Path $runner -Value $runnerBody -Encoding utf8

    Write-Host "==================================================================="
    Write-Host "CMBP run [$Tag]  DisablePossibleEdges=$DisablePossible"
    Write-Host "  ZipDir : $zipDir"
    Write-Host "  Log    : $logFile"
    Write-Host "==================================================================="
    $start = Get-Date
    & "$base\Run-AsNetOnly.ps1" -UserName "lowpriv" -Domain "MAYYHEM" -Password "password" `
        -CommandLine "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$runner`"" `
        -WorkingDirectory $zipDir -TimeoutSeconds 3600
    $dur = [int]((Get-Date) - $start).TotalSeconds

    $zip = Get-ChildItem -Path $zipDir -Filter *.zip -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($zip) {
        Write-Host "  -> DONE in ${dur}s. Zip: $($zip.FullName) ($([int]($zip.Length/1KB)) KB)"
    } else {
        Write-Host "  -> WARNING in ${dur}s: no .zip produced in $zipDir (check $console / $logFile)"
    }
}

Invoke-CmbpRun -Tag "pe-on"  -DisablePossible $false
Invoke-CmbpRun -Tag "pe-off" -DisablePossible $true
Write-Host "ALL CMBP RUNS COMPLETE"
