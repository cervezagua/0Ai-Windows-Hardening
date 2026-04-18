#
# 0AI v2.5 - Snapshot-AIShellVerbs.ps1
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

function _Print-Header {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 72)
    Write-Host (' ' + $Text)
    Write-Host ('=' * 72)
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
        if ($leaf -match '(?i)ai|erase|background|remove|blur|generat|visual') { $tag = '  <-- AI candidate' }
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
        Where-Object { $_.Name -match '(?i)Paint|Photos|Windows\.AI' } |
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
            if ($val -match '(?i)ai|erase|background|blur|visual') {
                Write-Host ('  {0}  = {1}' -f $name, $val)
            }
        }
    }
}

# Effective state of the policies the kit writes, so we can correlate
_Print-Header 'Current state of kit-managed keys'
$checks = @(
    @{ Hive='HKLM'; Key='SOFTWARE\Policies\Microsoft\Windows\Explorer'; Value='HideAIActionsMenu' }
    @{ Hive='HKCU'; Key='Software\Policies\Microsoft\Windows\Explorer'; Value='HideAIActionsMenu' }
    @{ Hive='HKLM'; Key='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint'; Value='DisableRemoveBackground' }
    @{ Hive='HKLM'; Key='SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint'; Value='DisableGenerativeErase' }
    @{ Hive='HKLM'; Key='SOFTWARE\Policies\Microsoft\Windows\Photos'; Value='DisableAIEditing' }
    @{ Hive='HKLM'; Key='SOFTWARE\Policies\Microsoft\Windows\Photos'; Value='DisableBlurBackground' }
    @{ Hive='HKLM'; Key='SOFTWARE\Policies\Microsoft\Windows\Photos'; Value='DisableEraseObjects' }
)
foreach ($c in $checks) {
    $full = ($c.Hive + ':\' + $c.Key)
    $cur  = $null
    try { $cur = (Get-ItemProperty -Path $full -ErrorAction Stop).$($c.Value) } catch {}
    $tag  = if ($null -eq $cur) { '(unset)' } else { [string]$cur }
    Write-Host ('  {0}!{1} = {2}' -f $full, $c.Value, $tag)
}

Write-Host ''
Write-Host 'Done. Share the output above if the AI Actions menu still appears'
Write-Host 'after running 0AI_Apply.cmd, and we can target specific verbs in'
Write-Host 'a future manifest bump.'
