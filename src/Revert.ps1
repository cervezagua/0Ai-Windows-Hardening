#
# 0AI v2.14.6 - Revert.ps1
#
# Finds the newest trusted backup under $env:ProgramData\0AI_Backups\<SID>
# (then the pre-v2.14.2 $env:USERPROFILE\0AI_Backups, or a user-specified
# -BackupRoot), reads run.json, and calls Undo-PolicyAction for every
# recorded action.
#

[CmdletBinding()]
param(
    [string]$BackupRoot = '',
    [string]$BackupDir  = '',
    # Use a backup that programs without admin rights could have changed
    # (one made by v2.14.1 or earlier) without the interactive YES prompt.
    [switch]$AllowUnlockedBackup
)

# StrictMode disabled for hashtable-heavy manifest handling
$ErrorActionPreference = 'Stop'

# ---- Full language mode required ----
# Under Constrained Language Mode (WDAC / AppLocker policies) the .NET calls
# the kit relies on fail midway; stop cleanly instead.
if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') {
    Write-Host ('[!] PowerShell is in {0} mode (set by an application-control policy). 0AI needs FullLanguage mode; nothing was changed.' -f $ExecutionContext.SessionState.LanguageMode) -ForegroundColor Red
    exit 1
}

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
Import-Module (Join-Path $moduleDir 'OAi.BackupAcl.psm1') -Force
Import-Module (Join-Path $moduleDir 'OAi.System.psm1') -Force
$manifestDir = Join-Path $thisDir 'manifest'

Import-Module (Join-Path $moduleDir 'OAi.BackupHistory.psm1') -Force

# ---- Helpers ----
function _Get-BackupFolders {
    # Backups with a run.json, newest first. Folder names are the Apply
    # timestamp (yyyy-MM-dd_HHmmss), which keeps their order even after a
    # Revert writes into a folder. Dry runs (-WhatIf) and rejected -Select
    # lists leave no run.json; imported-* are Revert's own working copies.
    param([string[]]$Roots)
    $all = @(foreach ($root in $Roots) {
            if (Test-Path -LiteralPath $root -PathType Container) {
                Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -notlike 'imported-*' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'run.json') -PathType Leaf) }
            }
        })
    return @($all | Sort-Object Name -Descending)
}

function _Confirm-Untrusted {
    # One YES (or -AllowUnlockedBackup where it applies) before Revert uses
    # data from a backup that programs without admin rights could have changed.
    param([bool]$SwitchApplies, [string]$NonInteractiveNote = 'Not interactive: pass -AllowUnlockedBackup to use it.')
    if ($SwitchApplies) { return $true }
    $interactive = $false
    try { $interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected } catch {}
    if (-not $interactive) {
        Write-Host ('    ' + $NonInteractiveNote)
        return $false
    }
    $ans = Read-Host '    Type YES to use it anyway'
    return (([string]$ans).Trim() -ceq 'YES')
}

function _Read-SmallText {
    # At most 32 MB from one regular file; $null if missing, a link or larger.
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    $it = Get-Item -LiteralPath $Path -Force
    if ((([int]$it.Attributes) -band ([int][System.IO.FileAttributes]::ReparsePoint)) -ne 0) { return $null }
    $cap = 32MB
    $fs = $null
    try {
        $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $buf = New-Object byte[] ($cap + 1)
        $n = 0
        while ($n -lt $buf.Length) {
            $k = $fs.Read($buf, $n, $buf.Length - $n)
            if ($k -le 0) { break }
            $n += $k
        }
    } catch { return $null } finally { if ($fs) { $fs.Dispose() } }
    if ($n -gt $cap) { return $null }
    $ms = New-Object System.IO.MemoryStream -ArgumentList $buf, 0, $n
    $sr = New-Object System.IO.StreamReader -ArgumentList $ms, $true
    try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
}

function _Stage-Copy {
    # Admin-only working copy of an untrusted backup; source.txt records
    # where it came from, so a later Revert knows which run it reverted.
    param([string]$Source)
    $base = 'imported-' + (Get-Date -Format 'yyyy-MM-dd_HHmmss')
    $dest = Join-Path (Get-OAiBackupHome -Create) $base
    $n = 1
    while (Test-Path -LiteralPath $dest) { $n++; $dest = Join-Path (Get-OAiBackupHome) ('{0}-{1}' -f $base, $n) }
    Copy-OAiBackupToLocked -Source $Source -Dest $dest
    [System.IO.File]::WriteAllText((Join-Path $dest 'source.txt'), $Source)
    return $dest
}

$roots = @()
if ($BackupRoot) { $roots = @($BackupRoot) }
else { $roots = @((Get-OAiBackupHome), (Join-Path $env:USERPROFILE '0AI_Backups')) }

# ---- Pick the backup ----
# Default: the admin-only home (%ProgramData%\0AI_Backups\<SID>, v2.14.2+),
# then the old per-profile folder (v2.14.1 and earlier).
if (-not $BackupDir) {
    $candidates = @(_Get-BackupFolders -Roots $roots)
    if ($candidates.Count -eq 0) {
        Write-Host ('[!] No backup with a run.json found in: {0}' -f ($roots -join ', ')) -ForegroundColor Red
        exit 1
    }
    # Prefer the newest trusted backup, so a newer folder some other program
    # dropped does not win - but say so when newer ones were passed over.
    $latest = $null
    $skipped = @()
    foreach ($c in $candidates) {
        if ((Test-OAiBackupDirLocked -Path $c.FullName).Ok) { $latest = $c; break }
        $skipped += $c
    }
    if ($latest -and $skipped.Count -gt 0) {
        Write-Host '[!] Newer backups were skipped because they are not admin-only:' -ForegroundColor Yellow
        foreach ($k in $skipped) { Write-Host ('      {0}' -f $k.FullName) }
        Write-Host '    To revert one of them, pass it with -BackupDir (Revert will ask first).'
    }
    if (-not $latest) { $latest = $candidates[0] }
    $BackupDir = $latest.FullName
}

Write-Host ('[+] Using backup folder: {0}' -f $BackupDir)

# ---- May this backup be trusted? ----
# Checked before anything is read from or written into it. A backup that
# programs without admin rights could change may hold altered "previous"
# values, which Revert would restore with admin rights.
$lock = Test-OAiBackupDirLocked -Path $BackupDir
$lockNote = ''
$selectedUntrusted = $false
if ($lock.Missing) {
    Write-Host ('[!] Backup folder not found: {0}' -f $BackupDir) -ForegroundColor Red
    exit 1
}
$BackupDir    = (Get-Item -LiteralPath $BackupDir -Force).FullName.TrimEnd('\', '/')
$origDir      = $BackupDir
$selectedName = Split-Path -Leaf $BackupDir
if (Test-Path -LiteralPath (Join-Path $origDir 'revert.log') -PathType Leaf) {
    Write-Host '[i] This backup has been reverted before; reverting it again restores the same values.'
}
if (-not $lock.Ok) {
    if ($lock.IsLink) {
        Write-Host ('[!] Not using {0}: {1}.' -f $BackupDir, $lock.Reason) -ForegroundColor Red
        exit 1
    }
    Write-Host ('[!] This backup is not protected against changes by programs without admin rights ({0}).' -f $lock.Reason) -ForegroundColor Yellow
    Write-Host '    Backups made by 0AI v2.14.1 or earlier are like this, as is any backup changed since.'
    Write-Host '    If a program altered it, Revert would restore the altered values. Use it only if you trust this PC.'
    if (-not (_Confirm-Untrusted -SwitchApplies ([bool]$AllowUnlockedBackup))) {
        Write-Host '[i] Revert cancelled; nothing changed.'
        exit 1
    }
    # Work from an admin-only copy, so nothing can swap the files while
    # Revert reads them.
    try {
        $staged = _Stage-Copy -Source $origDir
    } catch {
        Write-Host ('[!] Could not copy the backup to an admin-only folder: {0}' -f $_.Exception.Message) -ForegroundColor Red
        Write-Host '[i] Revert cancelled; nothing changed.'
        exit 1
    }
    $BackupDir = $staged
    $selectedUntrusted = $true
    $lockNote = ('[!] Untrusted backup {0} used after confirmation ({1}); working from admin-only copy {2}' -f $origDir, $lock.Reason, $staged)
    Write-Host ('[i] Working from an admin-only copy: {0}' -f $staged)
}

$runJson = Join-Path $BackupDir 'run.json'
$logFile = Join-Path $BackupDir 'revert.log'

('[+] 0AI {0} Revert starting' -f (Get-OAiVersion)) | Out-File -Encoding UTF8 -FilePath $logFile -Append
('[+] BackupDir: ' + $BackupDir) | Out-File -Encoding UTF8 -FilePath $logFile -Append
if ($lockNote) { $lockNote | Out-File -Encoding UTF8 -FilePath $logFile -Append }

if (-not (Test-Path -LiteralPath $runJson -PathType Leaf)) {
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
    if ($Retired.Kind -eq 'FolderPurge') {
        return [pscustomobject]@{ Id = $id; Status = 'skipped'; Message = ('retired in {0}: FolderPurge is not reversible' -f $Retired.RetiredIn) }
    }
    if ($Retired.Kind -ne 'Registry' -or @('HKLM','HKCU') -notcontains $hive -or -not $Retired.Key -or -not $Retired.Value) {
        return [pscustomobject]@{ Id = $id; Status = 'warn'; Message = 'retired entry is malformed - skipped' }
    }
    $pol = @{ Id = $id; Kind = 'Registry'; Hive = $hive; Key = [string]$Retired.Key; Value = [string]$Retired.Value }
    $resolved  = Resolve-OAiBackupFile -BackupDir $BackupDir -Recorded $BackupFile
    $hasBackup = [bool]$resolved
    $isJson    = $hasBackup -and ([System.IO.Path]::GetExtension($resolved) -eq '.json')
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

$run = Get-Content -LiteralPath $runJson -Raw | ConvertFrom-Json
$results = @($run.Results)

# ---- Snapshots from older backups ----
# A policy that was already in place when this backup's Apply ran was
# skipped without a snapshot. Its value from before the kit first changed
# it is in an older backup; find it there rather than deleting the value
# (or leaving a service as it is).
$fallback = @{}
$needIds = @(foreach ($r in $results) {
        $rid = [string]$r.Id
        if (-not $rid -or -not $policyMap.ContainsKey($rid)) { continue }
        if (@('Registry', 'Service', 'ScheduledTask') -notcontains $policyMap[$rid].Kind) { continue }
        # Only policies Apply skipped (already in place). An 'error' with no
        # snapshot never changed anything, and an 'ok' whose snapshot is gone
        # should not be replaced by an older run's value.
        if ([string]$r.Status -ne 'skipped') { continue }
        $bf = ''
        if ($r.PSObject.Properties.Name -contains 'BackupFile') { $bf = [string]$r.BackupFile }
        if (-not (Resolve-OAiBackupFile -BackupDir $BackupDir -Recorded $bf)) { $rid }
    })
if ($needIds.Count -gt 0) {
    # Reverts done from a working copy are recorded in the copy (source.txt
    # names the original folder).
    $copyReverts = @{}
    $homeDir = Get-OAiBackupHome
    if (Test-Path -LiteralPath $homeDir -PathType Container) {
        foreach ($d in @(Get-ChildItem -LiteralPath $homeDir -Directory -Force -Filter 'imported-*' -ErrorAction SilentlyContinue)) {
            $src = _Read-SmallText (Join-Path $d.FullName 'source.txt')
            $log = _Read-SmallText (Join-Path $d.FullName 'revert.log')
            if ($src -and $log) {
                $key = $src.Trim().TrimEnd('\', '/').ToLowerInvariant()
                if (-not $copyReverts.ContainsKey($key)) { $copyReverts[$key] = @() }
                $copyReverts[$key] = @($copyReverts[$key]) + @(Get-OAiRevertedIds -LogText $log)
            }
        }
    }
    function _Load-Older {
        param([string]$Name, [string]$Dir, [string]$Source, [bool]$Trusted)
        $txt = _Read-SmallText (Join-Path $Dir 'run.json')
        if (-not $txt) { return $null }
        try { $res = @((ConvertFrom-Json -InputObject $txt).Results) } catch { return $null }
        $reverted = @(Get-OAiRevertedIds -LogText (_Read-SmallText (Join-Path $Source 'revert.log')))
        $ck = $Source.ToLowerInvariant()
        if ($copyReverts.ContainsKey($ck)) { $reverted += @($copyReverts[$ck]) }
        return [pscustomobject]@{
            Name        = $Name
            Dir         = $Dir
            Source      = $Source
            Trusted     = $Trusted
            Results     = $res
            Files       = @(Get-ChildItem -LiteralPath $Dir -Force -File -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
            RevertedIds = $reverted
        }
    }
    # Older than what? The selected folder's timestamp, or for a working
    # copy the timestamp of the folder it was copied from.
    $srcOfSelected = ''
    if ($selectedName -like 'imported-*') { $srcOfSelected = _Read-SmallText (Join-Path $BackupDir 'source.txt') }
    if ($selectedUntrusted) { $srcOfSelected = $origDir }
    $cutoff = Get-OAiCutoffName -SelectedName $selectedName -SourcePath $srcOfSelected
    $exclude = @($origDir, $BackupDir)
    if ($srcOfSelected) { $exclude += $srcOfSelected.Trim() }
    $olderFolders = Select-OAiOlderFolders -Folders (_Get-BackupFolders -Roots $roots) -Cutoff $cutoff -Exclude $exclude
    $older = @(foreach ($d in $olderFolders) {
            $chk = Test-OAiBackupDirLocked -Path $d.FullName
            if ($chk.IsLink -or $chk.Missing) { continue }
            $o = _Load-Older -Name $d.Name -Dir $d.FullName -Source $d.FullName -Trusted $chk.Ok
            if ($o) { $o }
        })
    # First plan: untrusted runs may supply snapshots (which leads to the
    # question below) but cannot stop a search (see OAi.BackupHistory.psm1).
    $plan = Select-OAiFallbackSnapshots -Ids $needIds -Older $older
    $untrustedDirs = @($older | Where-Object { -not $_.Trusted } | ForEach-Object { $_.Dir })
    $fromUntrusted = @($plan.Keys | Where-Object { $untrustedDirs -contains $plan[$_].Dir })
    $untrusted = @($older | Where-Object { -not $_.Trusted -and @($fromUntrusted | ForEach-Object { $plan[$_].Dir }) -contains $_.Dir })
    if ($untrusted.Count -gt 0) {
        Write-Host ('[!] {0} setting(s) have no snapshot in this backup. Their earlier values are only in older' -f $fromUntrusted.Count) -ForegroundColor Yellow
        Write-Host '    backups that programs without admin rights could have changed (v2.14.1 or earlier):'
        foreach ($u in $untrusted) { Write-Host ('      {0}' -f $u.Source) }
        Write-Host '    Without them, those registry values are deleted and those services are left as they are.'
        # -AllowUnlockedBackup covers these only when the chosen backup was
        # itself an unprotected one the switch was passed for.
        $useOld = _Confirm-Untrusted -SwitchApplies ([bool]$AllowUnlockedBackup -and $selectedUntrusted) -NonInteractiveNote 'Not interactive: older unprotected backups are not used.'
        $older = @(foreach ($o in $older) {
                if ($o.Trusted) { $o; continue }
                $stub = [pscustomobject]@{ Name = $o.Name; Dir = $o.Dir; Source = $o.Source; Trusted = $false; Results = @(); Files = @(); RevertedIds = @() }
                if (-not $useOld -or @($untrusted | ForEach-Object { $_.Dir }) -notcontains $o.Dir) { $stub; continue }
                $c = $null
                try {
                    $copy = _Stage-Copy -Source $o.Source
                    $c = _Load-Older -Name $o.Name -Dir $copy -Source $o.Source -Trusted $true
                } catch {
                    $m = ('[!] Could not copy older backup {0}: {1}' -f $o.Source, $_.Exception.Message)
                    Write-Host $m -ForegroundColor Yellow
                    $m | Out-File -Encoding UTF8 -FilePath $logFile -Append
                }
                if ($c) {
                    $c
                } else {
                    # Not usable after all; its own revert still counts, as
                    # the user accepted this folder.
                    $stub.Trusted = $true
                    $stub.RevertedIds = $o.RevertedIds
                    $stub
                }
            })
        $plan = Select-OAiFallbackSnapshots -Ids $needIds -Older $older
    }
    $fallback = $plan
    if ($fallback.Count -gt 0) {
        $m = ('[+] {0} setting(s) will be restored from older backups (no snapshot in this one).' -f $fallback.Count)
        Write-Host $m
        $m | Out-File -Encoding UTF8 -FilePath $logFile -Append
    }
}

$rp = Invoke-OAiRestorePoint -Description ('0AI_Revert_' + (Get-OAiVersion))
$rpTag = '[+] '
if ($rp.Status -ne 'created') { $rpTag = '[!] ' }
($rpTag + '(pre-revert) ' + $rp.Message) | Out-File -Encoding UTF8 -FilePath $logFile -Append
if ($rp.Status -ne 'created') { Write-Host ($rpTag + $rp.Message) -ForegroundColor Yellow }

$counters = @{ ok = 0; warn = 0; error = 0; skipped = 0 }
foreach ($r in $results) {
    $rid = [string]$r.Id
    $bf = ''
    if ($r.PSObject.Properties.Name -contains 'BackupFile') { $bf = [string]$r.BackupFile }
    if ($rid -and $fallback.ContainsKey($rid) -and $policyMap.ContainsKey($rid)) {
        $fb = $fallback[$rid]
        $u = Undo-PolicyAction -Policy $policyMap[$rid] -BackupDir $fb.Dir -BackupFile $fb.BackupFile
        $u = [pscustomobject]@{ Id = $u.Id; Status = $u.Status; Message = ('from older backup {0}: {1}' -f $fb.Name, $u.Message) }
    } elseif ($rid -and $policyMap.ContainsKey($rid)) {
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
