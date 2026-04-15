#
# 0AI v2.3 - Revert.ps1
#
# Finds the newest backup directory under $env:USERPROFILE\0AI_Backups (or a
# user-specified -BackupRoot), reads run.json, and calls Undo-PolicyAction for
# every recorded action.
#

[CmdletBinding()]
param(
    [string]$BackupRoot = '',
    [string]$BackupDir  = ''
)

# StrictMode disabled for hashtable-heavy manifest handling
$ErrorActionPreference = 'Stop'

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

$thisDir     = Split-Path -Parent $PSCommandPath
$moduleDir   = Join-Path $thisDir 'module'
$manifestDir = Join-Path $thisDir 'manifest'

if (-not $BackupRoot) { $BackupRoot = Join-Path $env:USERPROFILE '0AI_Backups' }

if (-not $BackupDir) {
    if (-not (Test-Path $BackupRoot)) {
        Write-Host ('[!] No backup folder found at {0}' -f $BackupRoot) -ForegroundColor Red
        exit 1
    }
    $latest = Get-ChildItem -Path $BackupRoot -Directory -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending |
              Select-Object -First 1
    if (-not $latest) {
        Write-Host '[!] No backup subfolders found.' -ForegroundColor Red
        exit 1
    }
    $BackupDir = $latest.FullName
}

Write-Host ('[+] Using backup folder: {0}' -f $BackupDir)

$runJson = Join-Path $BackupDir 'run.json'
$logFile = Join-Path $BackupDir 'revert.log'

'[+] 0AI v2.3 Revert starting' | Out-File -Encoding UTF8 -FilePath $logFile -Append
('[+] BackupDir: ' + $BackupDir) | Out-File -Encoding UTF8 -FilePath $logFile -Append

if (-not (Test-Path $runJson)) {
    Write-Host ('[!] run.json not found at {0}' -f $runJson) -ForegroundColor Red
    '[!] run.json missing' | Out-File -Encoding UTF8 -FilePath $logFile -Append
    exit 1
}

Import-Module (Join-Path $moduleDir 'OAi.Engine.psm1') -Force

# Import-PowerShellDataFile rejects top-level arrays. Parse via AST + SafeGetValue.
function _Collect-Hashtables {
    param($Val, [System.Collections.Generic.List[object]]$Acc)
    if ($null -eq $Val) { return }
    if ($Val -is [System.Collections.IDictionary]) { [void]$Acc.Add($Val); return }
    if ($Val -is [System.Collections.IEnumerable] -and $Val -isnot [string]) {
        foreach ($v in $Val) { _Collect-Hashtables -Val $v -Acc $Acc }
        return
    }
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

# Load manifest for Kind-specific undo info
$manifestFiles = Get-ChildItem -Path $manifestDir -Filter '*.psd1' -ErrorAction Stop
$policyMap = @{}
foreach ($mf in $manifestFiles) {
    try {
        $data = _Load-PolicyManifest -Path $mf.FullName
        foreach ($p in $data) {
            if ($p -and $p.Id) { $policyMap[$p.Id] = $p }
        }
    } catch {
        ('[!] Failed to load manifest {0}: {1}' -f $mf.Name, $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $logFile -Append
    }
}

try {
    Checkpoint-Computer -Description '0AI_Revert_v2_3' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop | Out-Null
    '[+] Restore point (pre-revert) created.' | Out-File -Encoding UTF8 -FilePath $logFile -Append
} catch {
    ('[!] Restore point unavailable: ' + $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $logFile -Append
}

$run = Get-Content -Path $runJson -Raw | ConvertFrom-Json
$results = @($run.Results)

$counters = @{ ok = 0; warn = 0; error = 0; skipped = 0 }
foreach ($r in $results) {
    $pol = $policyMap[$r.Id]
    if (-not $pol) {
        ('[!] policy not in current manifest: {0}' -f $r.Id) | Out-File -Encoding UTF8 -FilePath $logFile -Append
        $counters.warn++
        continue
    }
    $bf = ''
    if ($r.PSObject.Properties.Name -contains 'BackupFile') { $bf = [string]$r.BackupFile }
    $u = Undo-PolicyAction -Policy $pol -BackupDir $BackupDir -BackupFile $bf
    ('[{0,-7}] {1}  {2}' -f $u.Status, $u.Id, $u.Message) | Out-File -Encoding UTF8 -FilePath $logFile -Append
    Write-Host ('[{0,-7}] {1}  {2}' -f $u.Status, $u.Id, $u.Message)
    switch ($u.Status) {
        'ok'      { $counters.ok++ }
        'warn'    { $counters.warn++ }
        'error'   { $counters.error++ }
        'skipped' { $counters.skipped++ }
    }
}

Write-Host ''
Write-Host ('[+] Revert summary: ok={0} warn={1} error={2} skipped={3}' -f $counters.ok, $counters.warn, $counters.error, $counters.skipped)
Write-Host ('[+] Log: {0}' -f $logFile)
Write-Host '[+] Reboot recommended.'
exit 0
