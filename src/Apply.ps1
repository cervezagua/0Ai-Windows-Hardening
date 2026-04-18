#
# 0AI v2.5 - Apply.ps1
#
# Entry point for applying privacy / AI-disablement / hardening policies.
#
# Parameters:
#   -Categories <string[]>  Default: AI,PRIV,HARD,AUDIT  (DEBLOAT excluded by default)
#   -WhatIf                 Show plan view and exit without changes
#   -Select <string[]>      Run only named policy IDs (overrides categories)
#   -BackupRoot <string>    Default: $env:USERPROFILE\0AI_Backups
#

[CmdletBinding()]
param(
    [string[]]$Categories = @('AI','PRIV','HARD','AUDIT'),
    [switch]$WhatIf,
    [string[]]$Select = @(),
    [string]$BackupRoot = ''
)

# StrictMode disabled for hashtable-heavy manifest handling
$ErrorActionPreference = 'Stop'

# ---- Admin check ----
function Test-IsAdmin {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

if (-not (Test-IsAdmin)) {
    Write-Host '[!] Run this script as Administrator.' -ForegroundColor Red
    exit 1
}

# ---- Resolve paths ----
$thisDir    = Split-Path -Parent $PSCommandPath
$moduleDir  = Join-Path $thisDir 'module'
$manifestDir = Join-Path $thisDir 'manifest'

if (-not $BackupRoot) {
    $BackupRoot = Join-Path $env:USERPROFILE '0AI_Backups'
}
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$BackupDir = Join-Path $BackupRoot $stamp
if (-not (Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
}

$LogFile   = Join-Path $BackupDir 'apply.log'
$RunJson   = Join-Path $BackupDir 'run.json'
$VerifyTxt = Join-Path $BackupDir 'verification.txt'

'[+] 0AI v2.3 Apply starting'                         | Out-File -Encoding UTF8 -FilePath $LogFile -Append
('[+] BackupDir: ' + $BackupDir)                      | Out-File -Encoding UTF8 -FilePath $LogFile -Append
('[+] Categories: ' + ($Categories -join ','))        | Out-File -Encoding UTF8 -FilePath $LogFile -Append
('[+] PS version: ' + $PSVersionTable.PSVersion)      | Out-File -Encoding UTF8 -FilePath $LogFile -Append

Write-Host ('[+] Backup dir: {0}' -f $BackupDir)

# ---- Restore point (best-effort) ----
try {
    Checkpoint-Computer -Description '0AI_Pre_v2_3' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop | Out-Null
    '[+] Restore point created.' | Out-File -Encoding UTF8 -FilePath $LogFile -Append
} catch {
    ('[!] Restore point unavailable: ' + $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $LogFile -Append
}

# ---- Load modules ----
Import-Module (Join-Path $moduleDir 'OAi.Engine.psm1')    -Force
Import-Module (Join-Path $moduleDir 'OAi.Runner.psm1')    -Force
Import-Module (Join-Path $moduleDir 'OAi.UI.Console.psm1') -Force
Import-Module (Join-Path $moduleDir 'OAi.UI.Plan.psm1')    -Force
Import-Module (Join-Path $moduleDir 'OAi.UI.Launcher.psm1') -Force

# ---- Manifest loader ----
# Note: Import-PowerShellDataFile rejects top-level arrays. Our manifests are
# @(...) at the top level, so we parse via AST and call SafeGetValue(), which
# is the PS-supported "constrained literal eval" path (PS 5.1+).
function _Collect-Hashtables {
    param($Val, [System.Collections.Generic.List[object]]$Acc)
    if ($null -eq $Val) { return }
    if ($Val -is [System.Collections.IDictionary]) { [void]$Acc.Add($Val); return }
    if ($Val -is [System.Collections.IEnumerable] -and $Val -isnot [string]) {
        foreach ($v in $Val) { _Collect-Hashtables -Val $v -Acc $Acc }
        return
    }
    # scalar: ignore
}
function _Load-PolicyManifest {
    param([string]$Path)
    $tokens = $null
    $errs   = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
    if ($errs -and @($errs).Count -gt 0) {
        throw ('parse error in {0}: {1}' -f (Split-Path -Leaf $Path), @($errs)[0].Message)
    }
    $stmts = @($ast.EndBlock.Statements)
    if ($stmts.Count -eq 0) { return ,@() }
    $val = $stmts[0].PipelineElements[0].Expression.SafeGetValue()
    $acc = New-Object System.Collections.Generic.List[object]
    _Collect-Hashtables -Val $val -Acc $acc
    return ,$acc.ToArray()
}

# ---- Load manifest ----
$manifestFiles = Get-ChildItem -Path $manifestDir -Filter '*.psd1' -ErrorAction Stop
$allPolicies = New-Object System.Collections.Generic.List[object]
foreach ($mf in $manifestFiles) {
    try {
        $data = _Load-PolicyManifest -Path $mf.FullName
        foreach ($p in $data) {
            if ($null -ne $p) { $allPolicies.Add($p) }
        }
    } catch {
        ('[!] Failed to load manifest {0}: {1}' -f $mf.Name, $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $LogFile -Append
    }
}
('[+] Loaded {0} policies from {1} manifest files' -f $allPolicies.Count, $manifestFiles.Count) | Out-File -Encoding UTF8 -FilePath $LogFile -Append

# ---- Interactive launcher (only when no CLI params were passed) ----
# If the user double-clicks 0AI_Apply.cmd with no arguments, show the
# dashboard picker. If they pass -Categories / -Select / -WhatIf on the
# command line (automation / CI), skip the menu and honor the params.
if ($PSBoundParameters.Count -eq 0) {
    $decision = Show-LauncherMenu -Manifest $allPolicies.ToArray()
    switch ($decision.Action) {
        'quit' {
            Write-Host '[i] Cancelled by user.'
            exit 0
        }
        'verify' {
            & (Join-Path $thisDir 'Verify.ps1')
            exit $LASTEXITCODE
        }
        'revert' {
            & (Join-Path $thisDir 'Revert.ps1')
            exit $LASTEXITCODE
        }
        'apply' {
            $Categories = $decision.Categories
            $WhatIf     = [bool]$decision.WhatIf
            ('[+] Launcher selection: Categories={0} WhatIf={1}' -f ($Categories -join ','), $WhatIf) |
                Out-File -Encoding UTF8 -FilePath $LogFile -Append
        }
    }
}

# ---- Build plan ----
$plan = New-Plan -Manifest $allPolicies.ToArray() -Categories $Categories -Selected $Select

if ($Categories -notcontains 'DEBLOAT' -and (-not $Select -or $Select.Count -eq 0)) {
    Write-Host '[i] DEBLOAT category excluded by default (destructive Appx removals). Use -Categories AI,PRIV,HARD,DEBLOAT,AUDIT to include.'
}

# ---- WhatIf / dry-run ----
if ($WhatIf) {
    Show-Plan -Plan $plan
    Write-Host ''
    Write-Host '[i] -WhatIf specified: no changes made.'
    exit 0
}

# ---- Execute ----
$queue = New-Object System.Collections.Concurrent.ConcurrentQueue[object]
$uiState = Start-ConsoleUI -PlanResult $plan -EventQueue $queue
try {
    $result = Invoke-Plan -Plan $plan -BackupDir $BackupDir -EventQueue $queue
    Update-ConsoleUI
} finally {
    Stop-ConsoleUI
}

# ---- Persist run.json ----
try {
    $result | ConvertTo-Json -Depth 8 | Out-File -Encoding UTF8 -FilePath $RunJson
} catch {
    ('[!] Failed to write run.json: ' + $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $LogFile -Append
}

# ---- Write verification.txt ----
try {
    '=== 0AI v2.3 verification ===' | Out-File -Encoding UTF8 -FilePath $VerifyTxt
    ('Timestamp : {0}' -f (Get-Date))          | Out-File -Encoding UTF8 -FilePath $VerifyTxt -Append
    ('BackupDir : {0}' -f $BackupDir)          | Out-File -Encoding UTF8 -FilePath $VerifyTxt -Append
    ('Categories: {0}' -f ($Categories -join ',')) | Out-File -Encoding UTF8 -FilePath $VerifyTxt -Append
    ''                                          | Out-File -Encoding UTF8 -FilePath $VerifyTxt -Append
    'Summary:'                                  | Out-File -Encoding UTF8 -FilePath $VerifyTxt -Append
    ($result.Summary | ConvertTo-Json -Depth 3) | Out-File -Encoding UTF8 -FilePath $VerifyTxt -Append
    ''                                          | Out-File -Encoding UTF8 -FilePath $VerifyTxt -Append
    'Per-policy:'                               | Out-File -Encoding UTF8 -FilePath $VerifyTxt -Append
    foreach ($r in $result.Results) {
        ('  [{0,-7}] {1,6} ms  {2}  {3}' -f $r.Status, $r.DurationMs, $r.Id, $r.Message) | Out-File -Encoding UTF8 -FilePath $VerifyTxt -Append
    }
} catch {
    ('[!] Failed to write verification.txt: ' + $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $LogFile -Append
}

Write-Host ''
Write-Host ('[+] Summary: ok={0} warn={1} error={2} skipped={3}' -f $result.Summary.ok, $result.Summary.warn, $result.Summary.error, $result.Summary.skipped)
Write-Host ('[+] Backups + logs: {0}' -f $BackupDir)
Write-Host '[+] Reboot recommended.'
exit 0
