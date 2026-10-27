#
# 0AI v2.15.1 - Snapshot-AIShellVerbs.ps1
#
# Read-only diagnostic. Enumerates the shell verbs and COM registrations
# that Microsoft uses to expose the "AI actions" submenu when you
# right-click an image in File Explorer. Output goes to stdout so you
# can redirect it to a file and share the result.
#
# Nothing is written. Nothing is deleted. Safe to run any time.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File src\Snapshot-AIShellVerbs.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File src\Snapshot-AIShellVerbs.ps1 > ai_verbs.txt
#

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

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

$thisDir = Split-Path -Parent $PSCommandPath

function _Print-Header {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 72)
    Write-Host (' ' + $Text)
    Write-Host ('=' * 72)
}

# Culture-proof case-insensitive match. PowerShell's -match folds case using
# the CURRENT culture: on Turkish / Azeri locales uppercase 'I' folds to
# dotless 'i' (U+0131), so a pattern like 'ai' silently fails to match a key
# named "AI" - this diagnostic would miss the very keys it exists to find.
# CultureInvariant makes the match behave identically on every locale.
function _IMatch {
    param([string]$Text, [string]$Pattern)
    if ($null -eq $Text) { return $false }
    return [System.Text.RegularExpressions.Regex]::IsMatch(
        $Text, $Pattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
}

function _Enum-ShellVerbs {
    param([string]$RootPath)
    if (-not (Test-Path $RootPath)) {
        Write-Host ('  (no key: {0})' -f $RootPath)
        return
    }
    $subs = Get-ChildItem -Path $RootPath -ErrorAction SilentlyContinue
    if (-not $subs) {
        Write-Host ('  (empty: {0})' -f $RootPath)
        return
    }
    foreach ($sk in $subs) {
        $leaf = Split-Path -Leaf $sk.Name
        $vals = @()
        try {
            $props = Get-ItemProperty -Path $sk.PSPath -ErrorAction SilentlyContinue
            if ($props) {
                foreach ($pn in ($props.PSObject.Properties.Name | Where-Object { $_ -notlike 'PS*' })) {
                    $vals += ('{0}={1}' -f $pn, $props.$pn)
                }
            }
        } catch {}
        $tag = ''
        if (_IMatch $leaf 'ai|erase|background|remove|blur|generat|visual') { $tag = '  <-- AI candidate' }
        Write-Host ('  [{0}]{1}' -f $leaf, $tag)
        foreach ($v in $vals) { Write-Host ('    ' + $v) }
    }
}

_Print-Header 'Context'
Write-Host ('Host       : {0}' -f $env:COMPUTERNAME)
Write-Host ('User       : {0}' -f $env:USERNAME)
Write-Host ('OS build   : {0}' -f (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).CurrentBuild)
Write-Host ('UBR        : {0}' -f (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).UBR)
Write-Host ('Timestamp  : {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))

# Shell verbs registered for the generic "image" file association
_Print-Header 'HKLM\...\SystemFileAssociations\image\Shell'
_Enum-ShellVerbs 'HKLM:\SOFTWARE\Classes\SystemFileAssociations\image\Shell'

_Print-Header 'HKCU\...\SystemFileAssociations\image\Shell'
_Enum-ShellVerbs 'HKCU:\SOFTWARE\Classes\SystemFileAssociations\image\Shell'

# Per-extension shell verbs
foreach ($ext in @('.jpg', '.jpeg', '.png', '.bmp', '.gif', '.webp', '.heic')) {
    $p = 'HKLM:\SOFTWARE\Classes\SystemFileAssociations\' + $ext + '\Shell'
    if (Test-Path $p) {
        _Print-Header ('HKLM\...\SystemFileAssociations\' + $ext + '\Shell')
        _Enum-ShellVerbs $p
    }
}

# Paint / Photos app-owned shell verbs
foreach ($p in @(
    'HKLM:\SOFTWARE\Classes\Applications\mspaint.exe\shell',
    'HKLM:\SOFTWARE\Classes\Paint\shell'
)) {
    if (Test-Path $p) {
        _Print-Header $p
        _Enum-ShellVerbs $p
    }
}

# Packaged-app shell verbs (Photos, Paint ship as Appx with AppUserModelID-based verbs)
_Print-Header 'HKCU AppX packages that own "image" verbs'
$appxShell = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\SystemAppData'
if (Test-Path $appxShell) {
    $candidates = Get-ChildItem -Path $appxShell -ErrorAction SilentlyContinue |
        Where-Object { _IMatch $_.Name 'Paint|Photos|Windows\.AI' } |
        Select-Object -ExpandProperty Name
    foreach ($c in $candidates) { Write-Host ('  ' + $c) }
    if (-not $candidates) { Write-Host '  (no Paint/Photos/AI packages registered for this user)' }
}

# Shell extensions registered by CLSID that smell AI
_Print-Header 'Shell extensions with "AI" in name'
$se = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Approved'
if (Test-Path $se) {
    $props = Get-ItemProperty -Path $se -ErrorAction SilentlyContinue
    if ($props) {
        foreach ($name in ($props.PSObject.Properties.Name | Where-Object { $_ -notlike 'PS*' })) {
            $val = $props.$name
            if (_IMatch $val 'ai|erase|background|blur|visual') {
                Write-Host ('  {0}  = {1}' -f $name, $val)
            }
        }
    }
}

# Effective state of the policies the kit writes, so we can correlate.
# Derived from the manifest so this list cannot drift from what Apply writes.
function _Read-RegValue {
    param([string]$Hive, [string]$Key, [string]$Value)
    try {
        $props = Get-ItemProperty -LiteralPath ($Hive + ':\' + $Key) -ErrorAction Stop
        if ($props.PSObject.Properties.Name -contains $Value) { return ,$props.$Value }
    } catch {}
    return $null
}

$aiPolicies = @()
$retired    = @()
try {
    Import-Module (Join-Path (Join-Path $thisDir 'module') 'OAi.Manifest.psm1') -Force -ErrorAction Stop
    $aiAll      = Import-OAiManifestFile -Path (Join-Path (Join-Path $thisDir 'manifest') 'ai.psd1')
    $aiPolicies = @($aiAll | Where-Object { $_.Kind -eq 'Registry' })
    $retired    = Get-OAiRetiredPolicies
} catch {
    Write-Host ('  (could not load manifest: {0})' -f $_.Exception.Message)
}

_Print-Header 'Current state of kit-managed keys (AI manifest)'
foreach ($p in $aiPolicies) {
    $cur = _Read-RegValue -Hive $p.Hive -Key $p.Key -Value $p.Value
    $expected = [string]$p.Data
    if ($null -eq $cur) {
        $state = 'unset'
        $shown = '(unset)'
    } else {
        $shown = (@($cur) | ForEach-Object { [string]$_ }) -join ','
        if ($shown -eq $expected) { $state = 'match' } else { $state = 'mismatch' }
    }
    Write-Host ('  [{0,-8}] {1}' -f $state, $p.Id)
    Write-Host ('             {0}:\{1}!{2} = {3}  (expected {4})' -f $p.Hive, $p.Key, $p.Value, $shown, $expected)
}

_Print-Header 'Leftover values from retired policies'
$leftovers = 0
foreach ($r in $retired) {
    # Cleanup=$false values are still written by a live policy, so their
    # presence is expected, not a leftover.
    if ($r.Kind -ne 'Registry' -or $r.Cleanup -ne $true) { continue }
    $cur = _Read-RegValue -Hive $r.Hive -Key $r.Key -Value $r.Value
    if ($null -eq $cur) { continue }
    $leftovers++
    Write-Host ('  {0}  (retired in {1})' -f $r.Id, $r.RetiredIn)
    Write-Host ('             {0}:\{1}!{2} = {3}  - removed by 0AI_Revert -BackupDir <the backup that recorded this Id>' -f $r.Hive, $r.Key, $r.Value, ((@($cur) | ForEach-Object { [string]$_ }) -join ','))
}
if ($leftovers -eq 0) { Write-Host '  (none)' }

Write-Host ''
Write-Host 'Done. Share the output above if the AI Actions menu still appears'
Write-Host 'after running 0AI_Apply.cmd, and we can target specific verbs in'
Write-Host 'a future manifest bump.'
