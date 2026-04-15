#
# OAi.UI.Launcher.psm1 - v2.4 dashboard launcher for 0AI Apply
#
# Interactive dashboard: shows per-category compliance from a pre-flight
# verify pass, then lets the user toggle categories with arrow keys and
# run Apply, dry-run, verify, or revert.
#
# Returns a pscustomobject:
#   @{ Action = 'apply'|'dryrun'|'verify'|'revert'|'quit'
#      Categories = @('AI','PRIV',...)
#      WhatIf     = $true|$false }
#
# Non-interactive hosts get the v2.2-equivalent default result.
#
# PS 5.1 compatible: uses [char]27 for ANSI escapes, $Host.UI.RawUI.ReadKey
# for key input, no $PSStyle.
#

# StrictMode disabled for hashtable-heavy manifest handling
$ErrorActionPreference = 'Stop'

$script:ESC = [char]27
$script:BAR_WIDTH = 24
$script:INNER_WIDTH = 66

function _Resolve-Hive {
    param([string]$H)
    switch ($H) {
        'HKLM'  { 'HKLM:' }
        'HKCU'  { 'HKCU:' }
        default { $H + ':' }
    }
}

function _Check-PolicyCompliant {
    # Returns $true if current state matches expected, $false if drift/missing,
    # $null if the policy has no verifiable state (Report / Mitigation).
    param($Policy)
    try {
        switch ($Policy.Kind) {
            'Registry' {
                $path = Join-Path (_Resolve-Hive $Policy.Hive) $Policy.Key
                try {
                    $cur = Get-ItemProperty -Path $path -Name $Policy.Value -ErrorAction Stop
                    return ([string]$cur.$($Policy.Value) -eq [string]$Policy.Data)
                } catch { return $false }
            }
            'Service' {
                try {
                    $svc = Get-Service -Name $Policy.Name -ErrorAction Stop
                    return ($svc.Status -eq 'Stopped' -and $svc.StartType -eq 'Disabled')
                } catch { return $false }
            }
            'AppxRemove' {
                try {
                    $m = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {
                        $_.Name -match $Policy.NamePattern -or $_.PackageFamilyName -match $Policy.NamePattern
                    }
                    return (-not $m)
                } catch { return $null }
            }
            'DefenderPref' {
                try {
                    $pref = Get-MpPreference -ErrorAction Stop
                    return ([string]$pref.$($Policy.Preference) -eq [string]$Policy.Value)
                } catch { return $null }
            }
            'DefenderAsr' {
                try {
                    $pref = Get-MpPreference -ErrorAction Stop
                    $ids  = @($pref.AttackSurfaceReductionRules_Ids)
                    $acts = @($pref.AttackSurfaceReductionRules_Actions)
                    $i = [array]::IndexOf($ids, $Policy.RuleId)
                    if ($i -lt 0) { return $false }
                    $a = [string]$acts[$i]
                    return ($a -eq 'Enabled' -or $a -eq '1')
                } catch { return $null }
            }
            'FolderPurge' {
                $pth = [System.Environment]::ExpandEnvironmentVariables($Policy.Path)
                return (-not (Test-Path $pth))
            }
            'Mitigation' { return $null }
            'Report'     { return $null }
            default      { return $null }
        }
    } catch {
        return $null
    }
}

function _Get-OsBuildInfo {
    try {
        $k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        return [pscustomobject]@{
            Product = [string]$k.ProductName
            Display = [string]$k.DisplayVersion
            Build   = ('{0}.{1}' -f $k.CurrentBuild, $k.UBR)
        }
    } catch {
        return [pscustomobject]@{ Product = 'Windows'; Display = '?'; Build = '?' }
    }
}

function _Make-Bar {
    param([int]$Filled, [int]$Total)
    $w = $script:BAR_WIDTH
    if ($Total -le 0) {
        # info-only category: empty bar
        return ([string]([char]0x2591) * $w)
    }
    $ratio = $Filled / [double]$Total
    $fill = [int][math]::Round($ratio * $w)
    if ($fill -lt 0) { $fill = 0 }
    if ($fill -gt $w) { $fill = $w }
    $block = [char]0x2588  # full block
    $light = [char]0x2591  # light shade
    return (([string]$block * $fill) + ([string]$light * ($w - $fill)))
}

function _Interactive-HostAvailable {
    try {
        if ($null -eq $Host.UI.RawUI) { return $false }
        $null = $Host.UI.RawUI.KeyAvailable
        try {
            if ([Console]::IsInputRedirected) { return $false }
        } catch {}
        return $true
    } catch {
        return $false
    }
}

function _Pad-Interior {
    param([string]$Text)
    if ($Text.Length -ge $script:INNER_WIDTH) {
        return $Text.Substring(0, $script:INNER_WIDTH)
    }
    return $Text.PadRight($script:INNER_WIDTH)
}

function _Build-CategoryStats {
    param($Manifest)
    $categories = @('AI','PRIV','HARD','AUDIT','DEBLOAT')
    $stats = [ordered]@{}
    foreach ($c in $categories) {
        $stats[$c] = [pscustomobject]@{
            Category    = $c
            PolicyCount = 0
            Verifiable  = 0
            Compliant   = 0
            InfoOnly    = 0
            Destructive = $false
        }
    }
    foreach ($p in $Manifest) {
        if (-not $p.Category) { continue }
        if (-not $stats.Contains($p.Category)) { continue }
        $s = $stats[$p.Category]
        $s.PolicyCount++
        if ($p.Destructive) { $s.Destructive = $true }
        $compliant = _Check-PolicyCompliant -Policy $p
        if ($null -eq $compliant) {
            $s.InfoOnly++
        } else {
            $s.Verifiable++
            if ($compliant) { $s.Compliant++ }
        }
    }
    return $stats
}

function _Draw-Dashboard {
    param(
        $Stats,
        [string[]]$Rows,
        $Selected,
        [int]$Cursor,
        [bool]$Dryrun,
        $Os,
        [bool]$Ansi
    )

    $e = $script:ESC

    if ($Ansi) {
        [Console]::Write("$e[2J$e[H")
    } else {
        try { Clear-Host } catch {}
    }

    $top    = ' ' + [string]([char]0x2554) + ([string]([char]0x2550) * $script:INNER_WIDTH) + [string]([char]0x2557)
    $sep    = ' ' + [string]([char]0x2560) + ([string]([char]0x2550) * $script:INNER_WIDTH) + [string]([char]0x2563)
    $bot    = ' ' + [string]([char]0x255A) + ([string]([char]0x2550) * $script:INNER_WIDTH) + [string]([char]0x255D)
    $vbar   = [string]([char]0x2551)
    $hline  = [string]([char]0x2500) * ($script:INNER_WIDTH - 6)

    Write-Host ''
    Write-Host $top
    Write-Host (' ' + $vbar + (_Pad-Interior '   0AI v2.3  -  Windows Hardening Kit') + $vbar)
    Write-Host (' ' + $vbar + (_Pad-Interior ('   build {0}   {1} {2}' -f $Os.Build, $Os.Product, $Os.Display)) + $vbar)
    Write-Host $sep
    Write-Host (' ' + $vbar + (_Pad-Interior '') + $vbar)
    Write-Host (' ' + $vbar + (_Pad-Interior '    Category     Count   Compliance') + $vbar)
    Write-Host (' ' + $vbar + (_Pad-Interior ('   ' + $hline)) + $vbar)

    for ($i = 0; $i -lt $Rows.Count; $i++) {
        $cat   = $Rows[$i]
        $s     = $Stats[$cat]
        $arrow = if ($i -eq $Cursor) { [string]([char]0x25B8) } else { ' ' }
        $mark  = if ($Selected[$cat]) { 'x' } else { ' ' }
        $bar   = _Make-Bar -Filled $s.Compliant -Total $s.Verifiable

        if ($s.Verifiable -gt 0) {
            $frac = ('{0}/{1}' -f $s.Compliant, $s.Verifiable)
            if ($frac.Length -gt 5) { $frac = $frac.Substring(0, 5) }
            $frac = $frac.PadRight(5)
            $delta = $s.Verifiable - $s.Compliant
            if ($delta -eq 0) {
                $status = 'OK    '
            } else {
                $status = (('{0} miss' -f $delta)).PadRight(6)
                if ($status.Length -gt 6) { $status = $status.Substring(0, 6) }
            }
        } else {
            $frac = '  -  '
            $status = 'info  '
        }

        $destMark = if ($s.Destructive) { '!' } else { ' ' }

        $inner = ('  {0} [{1}] {2} {3,3}   {4}  {5}  {6} {7}' -f `
                    $arrow, $mark, $cat.PadRight(8), $s.PolicyCount, $bar, $frac, $status, $destMark)

        $line = ' ' + $vbar + (_Pad-Interior $inner) + $vbar

        if ($Ansi -and $i -eq $Cursor) {
            Write-Host ("$e[7m$line$e[0m")
        } elseif ($Ansi -and $s.Destructive) {
            Write-Host ("$e[31m$line$e[0m")
        } else {
            Write-Host $line
        }
    }

    # Footer counters
    $selCount = 0
    $pending  = 0
    foreach ($cat in $Rows) {
        if ($Selected[$cat]) {
            $selCount += $Stats[$cat].PolicyCount
            $pending  += ($Stats[$cat].Verifiable - $Stats[$cat].Compliant)
        }
    }
    $drTag = if ($Dryrun) { 'ON ' } else { 'OFF' }
    $footer = ('    Selected: {0,3} policies    Pending: {1,2} miss    Dry-run: {2}' -f $selCount, $pending, $drTag)

    Write-Host (' ' + $vbar + (_Pad-Interior '') + $vbar)
    Write-Host (' ' + $vbar + (_Pad-Interior ('   ' + $hline)) + $vbar)
    Write-Host (' ' + $vbar + (_Pad-Interior $footer) + $vbar)
    Write-Host (' ' + $vbar + (_Pad-Interior '') + $vbar)
    Write-Host (' ' + $vbar + (_Pad-Interior '    Up/Dn move   SPACE toggle   ENTER apply   D dry-run') + $vbar)
    Write-Host (' ' + $vbar + (_Pad-Interior '    V verify-only   R revert-latest   Q quit') + $vbar)
    Write-Host $bot
}

function Show-LauncherMenu {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Manifest
    )

    if (-not (_Interactive-HostAvailable)) {
        return [pscustomobject]@{
            Action     = 'apply'
            Categories = @('AI','PRIV','HARD','AUDIT')
            WhatIf     = $false
        }
    }

    Write-Host ''
    Write-Host '[i] Running pre-flight verify...'

    $stats = _Build-CategoryStats -Manifest $Manifest
    $os    = _Get-OsBuildInfo

    $ansi = $false
    try {
        if ($Host -and $Host.UI -and $Host.UI.SupportsVirtualTerminal) {
            $ansi = [bool]$Host.UI.SupportsVirtualTerminal
        }
    } catch { $ansi = $false }

    $rows     = @('AI','PRIV','HARD','AUDIT','DEBLOAT')
    $selected = @{ AI = $true; PRIV = $true; HARD = $true; AUDIT = $true; DEBLOAT = $false }
    $cursor   = 0
    $dryrun   = $false

    while ($true) {
        _Draw-Dashboard -Stats $stats -Rows $rows -Selected $selected -Cursor $cursor -Dryrun $dryrun -Os $os -Ansi $ansi

        $k = $null
        try {
            $k = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        } catch {
            return [pscustomobject]@{ Action = 'quit'; Categories = @(); WhatIf = $false }
        }

        $vk   = [int]$k.VirtualKeyCode
        $char = [string]$k.Character

        if ($vk -eq 38) {
            if ($cursor -gt 0) { $cursor-- }
            continue
        }
        if ($vk -eq 40) {
            if ($cursor -lt ($rows.Count - 1)) { $cursor++ }
            continue
        }
        if ($vk -eq 13) {
            $picked = @($rows | Where-Object { $selected[$_] })
            if ($picked.Count -eq 0) { continue }
            return [pscustomobject]@{
                Action     = 'apply'
                Categories = $picked
                WhatIf     = $dryrun
            }
        }
        if ($vk -eq 32 -or $char -eq ' ') {
            $cat = $rows[$cursor]
            $selected[$cat] = -not $selected[$cat]
            continue
        }

        switch -Regex ($char) {
            '^[dD]$' { $dryrun = -not $dryrun; continue }
            '^[vV]$' { return [pscustomobject]@{ Action='verify'; Categories=@(); WhatIf=$false } }
            '^[rR]$' { return [pscustomobject]@{ Action='revert'; Categories=@(); WhatIf=$false } }
            '^[qQ]$' { return [pscustomobject]@{ Action='quit';   Categories=@(); WhatIf=$false } }
        }
    }
}

Export-ModuleMember -Function Show-LauncherMenu
