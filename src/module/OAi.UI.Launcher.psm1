#
# OAi.UI.Launcher.psm1 - v2.4 arrow-key picker for 0AI Apply (Design 2)
#
# Light-line box + arrow-key + checkbox picker. Shows when the user
# double-clicks 0AI_Apply.cmd with no arguments.
#
# Returns a pscustomobject:
#   @{ Action     = 'apply'|'quit'
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

$script:ESC         = [char]27
$script:INNER_WIDTH = 62

# Short category blurbs shown in each row
$script:CategoryBlurb = @{
    AI      = 'Copilot, Recall, Paint, ...'
    PRIV    = 'Telemetry, CloudContent, ...'
    HARD    = 'Defender, ASR, RDP, Exploit'
    AUDIT   = 'Read-only reports'
    DEBLOAT = '! DESTRUCTIVE Appx removal'
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

function _Count-ByCategory {
    param($Manifest)
    $categories = @('AI','PRIV','HARD','AUDIT','DEBLOAT')
    $stats = [ordered]@{}
    foreach ($c in $categories) {
        $stats[$c] = [pscustomobject]@{
            Category    = $c
            PolicyCount = 0
            Destructive = $false
        }
    }
    foreach ($p in $Manifest) {
        if (-not $p.Category) { continue }
        if (-not $stats.Contains($p.Category)) { continue }
        $stats[$p.Category].PolicyCount++
        if ($p.Destructive) { $stats[$p.Category].Destructive = $true }
    }
    return $stats
}

function _Draw-Picker {
    param(
        $Stats,
        [string[]]$Rows,
        $Selected,
        [int]$Cursor,
        [bool]$Dryrun,
        [bool]$Ansi
    )

    $e = $script:ESC

    if ($Ansi) {
        [Console]::Write("$e[2J$e[H")
    } else {
        try { Clear-Host } catch {}
    }

    # Light-line box-drawing characters
    $cTL = [char]0x250C  # ┌
    $cTR = [char]0x2510  # ┐
    $cBL = [char]0x2514  # └
    $cBR = [char]0x2518  # ┘
    $cML = [char]0x251C  # ├
    $cMR = [char]0x2524  # ┤
    $cH  = [char]0x2500  # ─
    $cV  = [char]0x2502  # │

    $top = ' ' + [string]$cTL + ([string]$cH * $script:INNER_WIDTH) + [string]$cTR
    $sep = ' ' + [string]$cML + ([string]$cH * $script:INNER_WIDTH) + [string]$cMR
    $bot = ' ' + [string]$cBL + ([string]$cH * $script:INNER_WIDTH) + [string]$cBR
    $vb  = [string]$cV

    Write-Host ''
    Write-Host $top
    Write-Host (' ' + $vb + (_Pad-Interior '  0AI v2.3  -  Select categories to apply') + $vb)
    Write-Host (' ' + $vb + (_Pad-Interior '  Up/Dn move   SPACE toggle   ENTER run   D dry-run   Q quit') + $vb)
    Write-Host $sep
    Write-Host (' ' + $vb + (_Pad-Interior '') + $vb)

    for ($i = 0; $i -lt $Rows.Count; $i++) {
        $cat   = $Rows[$i]
        $s     = $Stats[$cat]
        $arrow = if ($i -eq $Cursor) { [string]([char]0x25B8) } else { ' ' }
        $mark  = if ($Selected[$cat]) { 'x' } else { ' ' }

        $blurb = [string]$script:CategoryBlurb[$cat]
        if ($null -eq $blurb) { $blurb = '' }

        $inner = ('  {0} [{1}]  {2} {3,3} policies   {4}' -f `
                    $arrow, $mark, $cat.PadRight(8), $s.PolicyCount, $blurb)

        $line = ' ' + $vb + (_Pad-Interior $inner) + $vb

        if ($Ansi -and $i -eq $Cursor) {
            Write-Host ("$e[7m$line$e[0m")
        } elseif ($Ansi -and $s.Destructive) {
            Write-Host ("$e[31m$line$e[0m")
        } else {
            Write-Host $line
        }
    }

    Write-Host (' ' + $vb + (_Pad-Interior '') + $vb)
    Write-Host $sep

    # Footer: selected + dry-run
    $selCount = 0
    foreach ($cat in $Rows) {
        if ($Selected[$cat]) { $selCount += $Stats[$cat].PolicyCount }
    }
    $drTag = if ($Dryrun) { 'ON ' } else { 'OFF' }
    $footer = ('  {0,3} policies selected    |    dry-run: {1}' -f $selCount, $drTag)

    Write-Host (' ' + $vb + (_Pad-Interior $footer) + $vb)
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

    $stats = _Count-ByCategory -Manifest $Manifest

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
        _Draw-Picker -Stats $stats -Rows $rows -Selected $selected -Cursor $cursor -Dryrun $dryrun -Ansi $ansi

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
            '^[qQ]$' { return [pscustomobject]@{ Action='quit'; Categories=@(); WhatIf=$false } }
        }
    }
}

Export-ModuleMember -Function Show-LauncherMenu
