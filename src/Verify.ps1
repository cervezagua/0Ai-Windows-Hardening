#
# 0AI v2.14.6 - Verify.ps1
#
# Read-only: queries current state of every manifest policy and prints a
# table showing Id | Expected | Current | Status.
#

[CmdletBinding()]
param(
    # Also check per-user (HKCU) policies in every other profile and the
    # Default profile, as Apply -AllUsers sets them.
    [switch]$AllUsers
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


$thisDir     = Split-Path -Parent $PSCommandPath
$manifestDir = Join-Path $thisDir 'manifest'
$moduleDir   = Join-Path $thisDir 'module'

Import-Module (Join-Path $moduleDir 'OAi.Manifest.psm1') -Force
Import-Module (Join-Path $moduleDir 'OAi.Engine.psm1') -Force
Import-Module (Join-Path $moduleDir 'OAi.System.psm1') -Force
Import-Module (Join-Path $moduleDir 'OAi.Users.psm1') -Force

function _Resolve-Hive { param([string]$H) switch ($H) { 'HKLM' { 'HKLM:' } 'HKCU' { 'HKCU:' } 'HKU' { 'Registry::HKEY_USERS' } default { $H + ':' } } }

$manifestFiles = Get-ChildItem -Path $manifestDir -Filter '*.psd1' -ErrorAction Stop
$all = New-Object System.Collections.Generic.List[object]
foreach ($mf in $manifestFiles) {
    try {
        $data = Import-OAiManifestFile -Path $mf.FullName
        foreach ($p in $data) { if ($p) { $all.Add($p) } }
    } catch {
        Write-Warning ('[!] Failed to load manifest {0}: {1}' -f $mf.Name, $_.Exception.Message)
    }
}

$dn = Get-OAiDomainNote
if ($dn) { Write-Host ('[!] ' + $dn) -ForegroundColor Yellow }

try {
    $interactiveUser = Get-OAiInteractiveUser
    $elevatedUser    = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    if ($interactiveUser -and -not [string]::Equals($interactiveUser, $elevatedUser, [System.StringComparison]::OrdinalIgnoreCase)) {
        Write-Host ('[!] Running as {0}, but {1} is signed in at this desktop. Per-user (HKCU) policies land in {0}''s profile, not {1}''s, and the HKCU results below reflect {0}''s profile. To cover {1}, run the kit while signed in as {1}, using an admin account of their own, or use -AllUsers.' -f $elevatedUser, $interactiveUser) -ForegroundColor Yellow
    }
} catch {}

$mounted = @()
$isAdmin = $false
try { $isAdmin = (New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator) } catch {}
if ($AllUsers -and -not $isAdmin) {
    Write-Host '[!] -AllUsers needs an elevated PowerShell (Run as Administrator) to read other profiles; checking this account only.' -ForegroundColor Yellow
}
if ($AllUsers -and $isAdmin) {
    $targets = @()
    try { $targets = @(Get-OAiUserTargets) } catch {}
    $base = @($all.ToArray())
    foreach ($t in $targets) {
        if (-not (Mount-OAiUserHive -Target $t)) {
            Write-Host ('[!] Could not load the profile of {0}; skipped.' -f $t.Name) -ForegroundColor Yellow
            continue
        }
        $mounted += $t
        foreach ($p in $base) {
            $c = New-OAiTargetPolicy -Policy $p -Target $t
            if ($c) { $all.Add($c) }
        }
    }
    Write-Host ('[i] -AllUsers: also checking {0} other profile(s): {1}' -f $mounted.Count, (($mounted | ForEach-Object { $_.Name }) -join ', '))
}

$rows = New-Object System.Collections.Generic.List[object]
try {
    foreach ($p in $all) {
        $expected = ''
        $current  = ''
        $status   = 'unknown'

        try {
            switch ($p.Kind) {
                'Registry' {
                    $expected = [string]$p.Data
                    $path = Join-Path (_Resolve-Hive $p.Hive) $p.Key
                    try {
                        $cur = Get-ItemProperty -LiteralPath $path -Name $p.Value -ErrorAction Stop
                        $current = [string]$cur.$($p.Value)
                        if ($current -eq $expected) { $status = 'match' } else { $status = 'drift' }
                    } catch {
                        $current = '(not set)'
                        $status  = 'missing'
                    }
                }
                'Service' {
                    $expected = 'Stopped/Disabled'
                    try {
                        $svc = Get-Service -Name $p.Name -ErrorAction Stop
                        $current = ('{0}/{1}' -f $svc.Status, $svc.StartType)
                        if ($svc.Status -eq 'Stopped' -and $svc.StartType -eq 'Disabled') { $status = 'match' } else { $status = 'drift' }
                    } catch {
                        $current = 'n/a: service not installed on this PC'
                        $status  = 'n/a'
                    }
                }
                'ScheduledTask' {
                    $expected = 'Disabled'
                    try {
                        $t = Get-ScheduledTask -TaskPath $p.TaskPath -TaskName $p.TaskName -ErrorAction Stop
                        $current = [string]$t.State
                        if ($current -eq 'Disabled') { $status = 'match' } else { $status = 'drift' }
                    } catch {
                        $current = 'n/a: scheduled task does not exist on this PC'
                        $status  = 'n/a'
                    }
                }
                'AppxRemove' {
                    $expected = 'absent'
                    try {
                        $m = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { $_.Name -match $p.NamePattern -or $_.PackageFamilyName -match $p.NamePattern }
                        if ($m) { $current = ('{0} installed' -f @($m).Count); $status = 'drift' }
                        else    { $current = 'absent'; $status = 'match' }
                    } catch { $current = '(error)'; $status = 'unknown' }
                }
                'DefenderPref' {
                    $expected = [string]$p.Value
                    try {
                        $pref = Get-MpPreference -ErrorAction Stop
                        $current = [string]$pref.$($p.Preference)
                        if ($current -eq $expected) { $status = 'match' } else { $status = 'drift' }
                    } catch { $current = '(unavailable)'; $status = 'unknown' }
                }
                'DefenderAsr' {
                    $expected = ('{0}={1}' -f $p.RuleId, $p.Action)
                    try {
                        $pref = Get-MpPreference -ErrorAction Stop
                        $ids = @($pref.AttackSurfaceReductionRules_Ids)
                        $acts = @($pref.AttackSurfaceReductionRules_Actions)
                        $i = [array]::IndexOf($ids, $p.RuleId)
                        if ($i -ge 0) { $current = [string]$acts[$i]; $status = if ($current -eq 'Enabled' -or $current -eq '1') { 'match' } else { 'drift' } }
                        else { $current = '(not set)'; $status = 'missing' }
                    } catch { $current = '(unavailable)'; $status = 'unknown' }
                }
                'Mitigation' {
                    $expected = ($p.Enable -join ',')
                    $current  = '(see Get-ProcessMitigation -System)'
                    $status   = 'info'
                }
                'FolderPurge' {
                    $expected = 'absent'
                    $pth = [System.Environment]::ExpandEnvironmentVariables($p.Path)
                    if (Test-Path $pth) { $current = 'present'; $status = 'drift' }
                    else                 { $current = 'absent';  $status = 'match' }
                }
                'Report' {
                    $expected = '(read-only)'
                    $current  = '(read-only)'
                    $status   = 'info'
                }
                default {
                    $expected = '?'
                    $current  = '?'
                    $status   = 'unknown'
                }
            }
        } catch {
            $status = 'error'
            $current = $_.Exception.Message
        }
        if (@('missing', 'drift') -contains $status) {
            $na = ''
            try { $na = Get-OAiNotApplicableReason -Policy $p } catch {}
            if ($na) { $current = 'n/a: ' + $na; $status = 'n/a' }
        }

        $rows.Add([pscustomobject]@{
            Id       = $p.Id
            Expected = $expected
            Current  = $current
            Status   = $status
        })
    }
} finally {
    foreach ($t in $mounted) {
        if (-not (Dismount-OAiUserHive -Target $t)) {
            Write-Host ('[!] Could not unload the registry hive of {0} (HKEY_USERS\{1}). Restart Windows before {0} signs in, or they may get a temporary profile.' -f $t.Name, $t.Mount) -ForegroundColor Red
        }
    }
}

$rows | Format-Table -AutoSize
Write-Host ''
Write-Host ('Total: {0}  match: {1}  drift: {2}  missing: {3}  n/a: {4}  other: {5}' -f `
    $rows.Count, `
    @($rows | Where-Object { $_.Status -eq 'match' }).Count, `
    @($rows | Where-Object { $_.Status -eq 'drift' }).Count, `
    @($rows | Where-Object { $_.Status -eq 'missing' }).Count, `
    @($rows | Where-Object { $_.Status -eq 'n/a' }).Count, `
    @($rows | Where-Object { $_.Status -notin @('match','drift','missing','n/a') }).Count)
$naRows = @($rows | Where-Object { $_.Status -eq 'n/a' })
if ($naRows.Count -gt 0) {
    Write-Host ''
    Write-Host 'n/a (cannot apply on this PC; not a failure):'
    foreach ($r in $naRows) { Write-Host ('  {0}: {1}' -f $r.Id, ($r.Current -replace '^n/a: ', '')) }
}
exit 0
