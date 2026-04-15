#
# OAi.UI.Plan.psm1 - dry-run plan viewer
#
# Renders a plan grouped by Confidence. Falls back to non-interactive print
# when the host does not support ReadKey.
#

# StrictMode disabled for hashtable-heavy manifest handling
$ErrorActionPreference = 'Stop'

function Show-Plan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Plan
    )

    $groups = $Plan.Policies | Group-Object -Property Confidence | Sort-Object Name
    Write-Host ''
    Write-Host '============================================================'
    Write-Host (' 0AI v2.3 plan preview ({0} policies)' -f $Plan.Count)
    Write-Host '============================================================'
    foreach ($g in $groups) {
        Write-Host ''
        Write-Host ('-- {0} ({1}) --' -f $g.Name, $g.Count)
        foreach ($p in $g.Group) {
            $d = if ($p.Destructive) { '!' } else { ' ' }
            Write-Host ('  [{0}] {1,-7} {2,-55} {3}' -f $d, $p.Category, $p.Id, $p.Description)
        }
    }
    Write-Host ''
}

function Read-PlanSelection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Plan
    )

    Show-Plan -Plan $Plan

    # Check for interactive capability
    $canInteract = $false
    try {
        if ($Host.UI.RawUI -and $Host.UI.RawUI.KeyAvailable -ne $null) {
            $canInteract = $true
        }
    } catch { $canInteract = $false }

    if (-not $canInteract) {
        Write-Host '[plan] non-interactive host - returning all non-destructive policies'
        return ($Plan.Policies | Where-Object { -not $_.Destructive } | ForEach-Object { $_.Id })
    }

    Write-Host ''
    Write-Host 'Press Y to apply all, N to cancel, or provide -Select <ids> to pick.'
    try {
        $k = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        if ($k.Character -eq 'y' -or $k.Character -eq 'Y') {
            return ($Plan.Policies | ForEach-Object { $_.Id })
        }
    } catch {}
    return @()
}

Export-ModuleMember -Function Show-Plan, Read-PlanSelection
