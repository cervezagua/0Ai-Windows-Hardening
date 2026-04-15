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

$thisDir     = Split-Path -Parent $PSCommandPath
$manifestDir = Join-Path $thisDir 'manifest'

function _Resolve-Hive { param([string]$H) switch ($H) { 'HKLM' { 'HKLM:' } 'HKCU' { 'HKCU:' } default { $H + ':' } } }

$manifestFiles = Get-ChildItem -Path $manifestDir -Filter '*.psd1' -ErrorAction Stop
$all = New-Object System.Collections.Generic.List[object]
foreach ($mf in $manifestFiles) {
    try {
        $data = Import-PowerShellDataFile -Path $mf.FullName
        foreach ($p in @($data)) { if ($p) { $all.Add($p) } }
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
