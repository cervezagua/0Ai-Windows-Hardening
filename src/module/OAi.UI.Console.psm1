#
# OAi.UI.Console.psm1 - live console UI for v2.3
#
# Drains a ConcurrentQueue populated by the Runner and prints progress.
# ANSI cursor-based progress bars if the host supports virtual terminal;
# plain-text [OK]/[WARN]/[ERROR]/[SKIP] lines otherwise.
#

# StrictMode disabled for hashtable-heavy manifest handling
$ErrorActionPreference = 'Stop'

# PS 5.1 does not recognize `e as the escape character (added in PS 6). Use the
# actual char so ANSI sequences render correctly on Windows PowerShell 5.1.
$script:ESC     = [char]27
$script:UIState = $null

function Start-ConsoleUI {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $PlanResult,
        [Parameter(Mandatory)] $EventQueue
    )

    $ansi = $false
    try {
        if ($Host -and $Host.UI -and $Host.UI.SupportsVirtualTerminal) {
            $ansi = [bool]$Host.UI.SupportsVirtualTerminal
        }
    } catch { $ansi = $false }

    $script:UIState = [pscustomobject]@{
        Queue      = $EventQueue
        Ansi       = $ansi
        Counters   = @{ ok = 0; warn = 0; error = 0; skipped = 0 }
        PlanResult = $PlanResult
        Stopped    = $false
    }

    Write-Host ''
    Write-Host '============================================================'
    Write-Host ' 0AI v2.3 - applying plan'
    Write-Host '============================================================'

    return $script:UIState
}

function Stop-ConsoleUI {
    [CmdletBinding()]
    param()

    if ($null -eq $script:UIState) { return }
    $script:UIState.Stopped = $true

    # Drain any remaining events
    Update-ConsoleUI
    Write-Host ''
    Write-Host '------------------------------------------------------------'
    $c = $script:UIState.Counters
    Write-Host ("Done. ok={0} warn={1} error={2} skipped={3}" -f $c.ok, $c.warn, $c.error, $c.skipped)
    Write-Host '------------------------------------------------------------'
}

function Update-ConsoleUI {
    [CmdletBinding()]
    param()

    if ($null -eq $script:UIState) { return }
    $q = $script:UIState.Queue
    if ($null -eq $q) { return }

    $evt = $null
    while ($q.TryDequeue([ref]$evt)) {
        _Render-Event $evt
    }
}

function _Render-Event {
    param($Evt)

    $tag = switch ($Evt.Status) {
        'ok'      { '[OK]   ' }
        'warn'    { '[WARN] ' }
        'error'   { '[ERROR]' }
        'skipped' { '[SKIP] ' }
        default   { '[?]    ' }
    }

    $c = $script:UIState.Counters
    switch ($Evt.Status) {
        'ok'      { $c.ok++ }
        'warn'    { $c.warn++ }
        'error'   { $c.error++ }
        'skipped' { $c.skipped++ }
    }

    $line = "{0} {1,6} ms  {2}  {3}" -f $tag, $Evt.Ms, $Evt.Id, $Evt.Msg
    if ($script:UIState.Ansi) {
        $e = $script:ESC
        $color = switch ($Evt.Status) {
            'ok'      { "$e[32m" }
            'warn'    { "$e[33m" }
            'error'   { "$e[31m" }
            'skipped' { "$e[90m" }
            default   { "$e[0m" }
        }
        Write-Host ("{0}{1}{2}[0m" -f $color, $line, $e)
    } else {
        Write-Host $line
    }
}

Export-ModuleMember -Function Start-ConsoleUI, Stop-ConsoleUI, Update-ConsoleUI
