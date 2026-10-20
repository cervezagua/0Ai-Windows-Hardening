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

# ---- Culture invariance (must run before any other work) ----
# PowerShell's -match / -replace / -like fold case using the CURRENT culture.
# On Turkish and Azeri locales uppercase 'I' (U+0049) folds to dotless 'i'
# (U+0131), which silently breaks both pattern matching and character ranges:
# it mangled report filenames ("AUDIT" -> "AUD_T") and made the AI-candidate
# scanner miss keys literally named "AI". Fixing each call site individually
# is whack-a-mole, so pin the thread to InvariantCulture instead - every
# comparison, format and regex in the kit then behaves identically on every
# Windows display language. DefaultThreadCurrent* covers worker threads (the
# ThreadJob path on PS7+). Pinning UICulture also makes framework/OS error
# messages come back in English, so the access-denied detection in
# OAi.Engine.psm1 works on non-English Windows too.
try {
    $script:OAiCulture = [System.Globalization.CultureInfo]::InvariantCulture
    [System.Globalization.CultureInfo]::DefaultThreadCurrentCulture   = $script:OAiCulture
    [System.Globalization.CultureInfo]::DefaultThreadCurrentUICulture = $script:OAiCulture
    [System.Threading.Thread]::CurrentThread.CurrentCulture   = $script:OAiCulture
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = $script:OAiCulture
} catch {}


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

# Version module first: the log header and restore-point name below call
# Get-OAiVersion, so it must be loaded before any other work.
Import-Module (Join-Path $moduleDir 'OAi.Version.psm1') -Force
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

('[+] 0AI {0} Revert starting' -f (Get-OAiVersion)) | Out-File -Encoding UTF8 -FilePath $logFile -Append
('[+] BackupDir: ' + $BackupDir) | Out-File -Encoding UTF8 -FilePath $logFile -Append

if (-not (Test-Path $runJson)) {
    Write-Host ('[!] run.json not found at {0}' -f $runJson) -ForegroundColor Red
    '[!] run.json missing' | Out-File -Encoding UTF8 -FilePath $logFile -Append
    exit 1
}

Import-Module (Join-Path $moduleDir 'OAi.Manifest.psm1') -Force
Import-Module (Join-Path $moduleDir 'OAi.Engine.psm1') -Force

# Load manifest for Kind-specific undo info
$manifestFiles = Get-ChildItem -Path $manifestDir -Filter '*.psd1' -ErrorAction Stop
$policyMap = @{}
foreach ($mf in $manifestFiles) {
    try {
        $data = Import-OAiManifestFile -Path $mf.FullName
        foreach ($p in $data) {
            if ($p -and $p.Id) { $policyMap[$p.Id] = $p }
        }
    } catch {
        ('[!] Failed to load manifest {0}: {1}' -f $mf.Name, $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $logFile -Append
    }
}

# Ids an older kit version applied that the manifest no longer has. The
# retired list - never the backup file - says which value each one touched.
$retiredMap = @{}
try {
    foreach ($rp in (Get-OAiRetiredPolicies)) {
        if ($rp -and $rp.Id) { $retiredMap[[string]$rp.Id] = $rp }
    }
} catch {
    ('[!] Failed to load retired policy list: ' + $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $logFile -Append
}

function _Undo-RetiredPolicy {
    param($Retired, [string]$BackupDir, [string]$BackupFile)
    $id   = [string]$Retired.Id
    $hive = [string]$Retired.Hive
    if ($Retired.Kind -ne 'Registry' -or @('HKLM','HKCU') -notcontains $hive -or -not $Retired.Key -or -not $Retired.Value) {
        return [pscustomobject]@{ Id = $id; Status = 'warn'; Message = 'retired entry is malformed - skipped' }
    }
    $pol = @{ Id = $id; Kind = 'Registry'; Hive = $hive; Key = [string]$Retired.Key; Value = [string]$Retired.Value }
    $hasBackup = [bool]($BackupFile -and (Test-Path -LiteralPath $BackupFile -PathType Leaf))
    $isJson    = $hasBackup -and ([System.IO.Path]::GetExtension($BackupFile) -eq '.json')
    $prefix    = 'retired in {0}: ' -f $Retired.RetiredIn

    if ($Retired.Cleanup -ne $true -and -not $hasBackup) {
        return [pscustomobject]@{ Id = $id; Status = 'skipped'; Message = ($prefix + ('no snapshot; {0}\{1}!{2} left as-is (still managed by {3})' -f $hive, $pol.Key, $pol.Value, (@($Retired.ReplacedBy) -join ', '))) }
    }

    $u = Undo-PolicyAction -Policy $pol -BackupDir $BackupDir -BackupFile $BackupFile
    $status = $u.Status
    $msg    = $prefix + $u.Message

    if ($Retired.Cleanup -eq $true -and -not $isJson) {
        $path = Join-Path ($hive + ':') $pol.Key
        $exists = $false
        try { $null = Get-ItemProperty -LiteralPath $path -Name $pol.Value -ErrorAction Stop; $exists = $true } catch {}
        if ($exists) {
            try {
                Remove-ItemProperty -LiteralPath $path -Name $pol.Value -Force -ErrorAction Stop
                $msg += ('; removed inert leftover {0}\{1}!{2}' -f $hive, $pol.Key, $pol.Value)
            } catch {
                $status = 'warn'
                $msg += ('; could not remove leftover {0}\{1}!{2}: {3}' -f $hive, $pol.Key, $pol.Value, $_.Exception.Message)
            }
        }
        # With no backup at all, deleting an inert value is the intended
        # outcome, not a degraded one.
        if (-not $hasBackup -and $status -eq 'warn' -and -not $exists) { $status = 'ok' }
    }
    return [pscustomobject]@{ Id = $id; Status = $status; Message = $msg }
}

try {
    Checkpoint-Computer -Description ('0AI_Revert_' + (Get-OAiVersion)) -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop | Out-Null
    '[+] Restore point (pre-revert) created.' | Out-File -Encoding UTF8 -FilePath $logFile -Append
} catch {
    ('[!] Restore point unavailable: ' + $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $logFile -Append
}

$run = Get-Content -Path $runJson -Raw | ConvertFrom-Json
$results = @($run.Results)

$counters = @{ ok = 0; warn = 0; error = 0; skipped = 0 }
foreach ($r in $results) {
    $rid = [string]$r.Id
    $bf = ''
    if ($r.PSObject.Properties.Name -contains 'BackupFile') { $bf = [string]$r.BackupFile }
    if ($rid -and $policyMap.ContainsKey($rid)) {
        $u = Undo-PolicyAction -Policy $policyMap[$rid] -BackupDir $BackupDir -BackupFile $bf
    } elseif ($rid -and $retiredMap.ContainsKey($rid)) {
        try {
            $u = _Undo-RetiredPolicy -Retired $retiredMap[$rid] -BackupDir $BackupDir -BackupFile $bf
        } catch {
            $u = [pscustomobject]@{ Id = $rid; Status = 'error'; Message = ('retired-policy revert failed: ' + $_.Exception.Message) }
        }
    } else {
        $m = ('[warn] {0}: not in current manifest and not a known retired policy - skipped' -f $rid)
        Write-Host $m -ForegroundColor Yellow
        $m | Out-File -Encoding UTF8 -FilePath $logFile -Append
        $counters.warn++
        continue
    }
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
