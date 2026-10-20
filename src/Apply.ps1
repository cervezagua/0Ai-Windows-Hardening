#
# 0AI v2.14.2 - Apply.ps1
#
# Entry point for applying privacy / AI-disablement / hardening policies.
#
# Parameters:
#   -Categories <string[]>  Default: AI,PRIV,HARD,AUDIT  (DEBLOAT excluded by default)
#   -WhatIf                 Show plan view and exit without changes
#   -Select <string[]>      Run only named policy IDs (overrides categories)
#   -BackupRoot <string>    Default: $env:ProgramData\0AI_Backups\<account SID>
#   -AllowUnlockedBackup    Continue if the backup folder cannot be made admin-only
#

[CmdletBinding()]
param(
    [string[]]$Categories = @('AI','PRIV','HARD','AUDIT'),
    [switch]$WhatIf,
    [string[]]$Select = @(),
    [string]$BackupRoot = '',
    # Continue when the backup folder cannot be made admin-only (FAT drive,
    # some network shares). Revert will then ask before trusting it.
    [switch]$AllowUnlockedBackup
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

# Version module first: the log header and restore-point name below call
# Get-OAiVersion, so it must be loaded before any other work.
Import-Module (Join-Path $moduleDir 'OAi.Version.psm1') -Force
Import-Module (Join-Path $moduleDir 'OAi.Manifest.psm1') -Force
Import-Module (Join-Path $moduleDir 'OAi.BackupAcl.psm1') -Force

# ---- Backup folder ----
# Revert trusts these files with admin rights, so they must be beyond the
# reach of programs without admin rights: by default under
# %ProgramData%\0AI_Backups\<account SID>, each run's folder created
# admin-only in one step (see OAi.BackupAcl.psm1).
$stamp = Get-Date -Format 'yyyy-MM-dd_HHmmss'
$customRoot = [bool]$BackupRoot
try {
    if (-not $customRoot) {
        $BackupRoot = Get-OAiBackupHome -Create
    } elseif (-not (Test-Path -LiteralPath $BackupRoot)) {
        New-Item -ItemType Directory -Force -Path $BackupRoot | Out-Null
    }
} catch {
    Write-Host ('[!] Could not prepare the backup folder {0}: {1}' -f $BackupRoot, $_.Exception.Message) -ForegroundColor Red
    Write-Host '    Nothing applied. You can choose another location with -BackupRoot.'
    exit 1
}
$BackupDir = Join-Path $BackupRoot $stamp
$lockMsg = '[+] Backup folder is admin-only (read-only for you).'
try {
    New-OAiLockedDir -Path $BackupDir
} catch {
    $lockErr = $_.Exception.Message
    # FAT / exFAT drives and some network shares have no permissions.
    if (-not $AllowUnlockedBackup) {
        Write-Host ('[!] Could not create an admin-only backup folder {0}: {1}' -f $BackupDir, $lockErr) -ForegroundColor Red
        Write-Host '    Nothing applied. Use another -BackupRoot, or -AllowUnlockedBackup to continue with an unprotected backup.'
        exit 1
    }
    try {
        # New-OAiLockedDir may already have created it before its check
        # failed; reuse it then, but only if it is still empty.
        if (Test-Path -LiteralPath $BackupDir) {
            if (@(Get-ChildItem -LiteralPath $BackupDir -Force).Count -gt 0) { throw 'folder exists and is not empty' }
        } else {
            New-Item -ItemType Directory -Path $BackupDir -ErrorAction Stop | Out-Null
        }
    } catch {
        Write-Host ('[!] Could not create a new backup folder {0}: {1}' -f $BackupDir, $_.Exception.Message) -ForegroundColor Red
        exit 1
    }
    $lockMsg = '[!] Backup folder is NOT admin-only (-AllowUnlockedBackup): ' + $lockErr
    Write-Host $lockMsg -ForegroundColor Yellow
}
# The whole location, not just this folder: folders above it must not let
# other programs rename it away either.
$rootCheck = Test-OAiBackupDirLocked -Path $BackupDir
if (-not $rootCheck.Ok -and -not $AllowUnlockedBackup) {
    Write-Host ('[!] Backups in {0} would not be protected: {1}' -f $BackupRoot, $rootCheck.Reason) -ForegroundColor Red
    Write-Host '    Nothing applied. Use another -BackupRoot, or -AllowUnlockedBackup to continue anyway.'
    try { Remove-Item -LiteralPath $BackupDir -Force -ErrorAction Stop } catch {}
    exit 1
}
if (-not $rootCheck.Ok) {
    $m = '[!] Backups in this location are not protected (' + $rootCheck.Reason + '). Revert will ask before using them.'
    Write-Host $m -ForegroundColor Yellow
    $lockMsg += [Environment]::NewLine + $m
}

$LogFile   = Join-Path $BackupDir 'apply.log'
$RunJson   = Join-Path $BackupDir 'run.json'
$VerifyTxt = Join-Path $BackupDir 'verification.txt'

('[+] 0AI {0} Apply starting' -f (Get-OAiVersion))    | Out-File -Encoding UTF8 -FilePath $LogFile -Append
('[+] BackupDir: ' + $BackupDir)                      | Out-File -Encoding UTF8 -FilePath $LogFile -Append
('[+] Categories: ' + ($Categories -join ','))        | Out-File -Encoding UTF8 -FilePath $LogFile -Append
('[+] PS version: ' + $PSVersionTable.PSVersion)      | Out-File -Encoding UTF8 -FilePath $LogFile -Append
$lockMsg                                              | Out-File -Encoding UTF8 -FilePath $LogFile -Append

Write-Host ('[+] Backup dir: {0}' -f $BackupDir)

# ---- Load modules ----
Import-Module (Join-Path $moduleDir 'OAi.Engine.psm1')    -Force
Import-Module (Join-Path $moduleDir 'OAi.Runner.psm1')    -Force
Import-Module (Join-Path $moduleDir 'OAi.UI.Console.psm1') -Force
Import-Module (Join-Path $moduleDir 'OAi.UI.Plan.psm1')    -Force
Import-Module (Join-Path $moduleDir 'OAi.UI.Launcher.psm1') -Force

# ---- Load manifest ----
$manifestFiles = Get-ChildItem -Path $manifestDir -Filter '*.psd1' -ErrorAction Stop
$allPolicies = New-Object System.Collections.Generic.List[object]
foreach ($mf in $manifestFiles) {
    try {
        $data = Import-OAiManifestFile -Path $mf.FullName
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
# -BackupRoot / -AllowUnlockedBackup only say where backups go; they do not
# pick what to apply, so the menu still shows.
$picks = @($PSBoundParameters.Keys | Where-Object { @('BackupRoot','AllowUnlockedBackup') -notcontains $_ })
if ($picks.Count -eq 0) {
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

# ---- Elevated as a different account? ----
# Printed after the launcher, which clears the screen.
try {
    $interactiveUser = Get-OAiInteractiveUser
    $elevatedUser    = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($interactiveUser -and -not [string]::Equals($interactiveUser, $elevatedUser, [System.StringComparison]::OrdinalIgnoreCase)) {
        $um = ('[!] Running as {0}, but {1} is signed in at this desktop. Per-user (HKCU) policies will land in {0}''s profile, not {1}''s. To cover {1}, run the kit while signed in as {1}, using an admin account of their own.' -f $elevatedUser, $interactiveUser)
        Write-Host $um -ForegroundColor Yellow
        $um | Out-File -Encoding UTF8 -FilePath $LogFile -Append
    }
} catch {}

# ---- Validate -Select ----
# 'powershell -File' (how 0AI_Apply.cmd starts us) passes "-Select A,B" as
# the single string 'A,B', so split on commas here.
$Select = @($Select | ForEach-Object { [string]$_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
if ($Select.Count -gt 0) {
    $retired = @()
    try {
        $retired = Get-OAiRetiredPolicies
    } catch {
        ('[!] Failed to load retired policy list: ' + $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $LogFile -Append
    }
    $unknown = @(Test-OAiSelectIds -Select $Select -LivePolicies $allPolicies.ToArray() -Retired $retired)
    if ($unknown.Count -gt 0) {
        foreach ($u in $unknown) {
            Write-Host ('[!] ' + $u.Message) -ForegroundColor Red
            ('[!] -Select: ' + $u.Message) | Out-File -Encoding UTF8 -FilePath $LogFile -Append
        }
        Write-Host '[!] Nothing applied. Fix the -Select list and run again.' -ForegroundColor Red
        '[!] Aborted: unknown -Select Id(s); nothing applied.' | Out-File -Encoding UTF8 -FilePath $LogFile -Append
        exit 2
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

# ---- Restore point (best-effort) ----
# Created only once the run is certain to change something: after the
# -Select check and the -WhatIf exit, so a dry run or a rejected Id list
# does not leave a restore point behind.
try {
    Checkpoint-Computer -Description ('0AI_Pre_' + (Get-OAiVersion)) -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop | Out-Null
    '[+] Restore point created.' | Out-File -Encoding UTF8 -FilePath $LogFile -Append
} catch {
    ('[!] Restore point unavailable: ' + $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $LogFile -Append
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
    ('=== 0AI {0} verification ===' -f (Get-OAiVersion)) | Out-File -Encoding UTF8 -FilePath $VerifyTxt
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

# ---- Seal the backup ----
# New files normally belong to Administrators already; a "Default owner for
# objects created by members of the Administrators group = Object creator"
# policy would make them the user's, so fix that, then re-check.
try { Set-OAiBackupOwner -Path $BackupDir } catch {
    ('[!] Could not set the owner of the backup files: ' + $_.Exception.Message) | Out-File -Encoding UTF8 -FilePath $LogFile -Append
}
$seal = Test-OAiBackupDirLocked -Path $BackupDir
if ($seal.Ok) {
    '[+] Backup check: admin-only.' | Out-File -Encoding UTF8 -FilePath $LogFile -Append
} else {
    $m = '[!] Backup is not protected against changes without admin rights: ' + $seal.Reason
    Write-Host $m -ForegroundColor Yellow
    $m | Out-File -Encoding UTF8 -FilePath $LogFile -Append
}

Write-Host ''
Write-Host ('[+] Summary: ok={0} warn={1} error={2} skipped={3}' -f $result.Summary.ok, $result.Summary.warn, $result.Summary.error, $result.Summary.skipped)
Write-Host ('[+] Backups + logs: {0}' -f $BackupDir)
Write-Host '[+] Reboot recommended.'
exit 0
