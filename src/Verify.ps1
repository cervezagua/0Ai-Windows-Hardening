#
# 0AI v2.3 - Verify.ps1
#
# Read-only: queries current state of every manifest policy and prints a
# table showing Id | Expected | Current | Status.
#

[CmdletBinding()]
param()

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


$thisDir     = Split-Path -Parent $PSCommandPath
$manifestDir = Join-Path $thisDir 'manifest'

function _Resolve-Hive { param([string]$H) switch ($H) { 'HKLM' { 'HKLM:' } 'HKCU' { 'HKCU:' } default { $H + ':' } } }

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

$manifestFiles = Get-ChildItem -Path $manifestDir -Filter '*.psd1' -ErrorAction Stop
$all = New-Object System.Collections.Generic.List[object]
foreach ($mf in $manifestFiles) {
    try {
        $data = _Load-PolicyManifest -Path $mf.FullName
        foreach ($p in $data) { if ($p) { $all.Add($p) } }
    } catch {
        Write-Warning ('[!] Failed to load manifest {0}: {1}' -f $mf.Name, $_.Exception.Message)
    }
}

$rows = New-Object System.Collections.Generic.List[object]
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
                    $cur = Get-ItemProperty -Path $path -Name $p.Value -ErrorAction Stop
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
                    $current = '(missing)'
                    $status  = 'missing'
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

    $rows.Add([pscustomobject]@{
        Id       = $p.Id
        Expected = $expected
        Current  = $current
        Status   = $status
    })
}

$rows | Format-Table -AutoSize
Write-Host ''
Write-Host ('Total: {0}  match: {1}  drift: {2}  missing: {3}  other: {4}' -f `
    $rows.Count, `
    @($rows | Where-Object { $_.Status -eq 'match' }).Count, `
    @($rows | Where-Object { $_.Status -eq 'drift' }).Count, `
    @($rows | Where-Object { $_.Status -eq 'missing' }).Count, `
    @($rows | Where-Object { $_.Status -notin @('match','drift','missing') }).Count)
exit 0
