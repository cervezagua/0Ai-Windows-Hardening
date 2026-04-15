#
# OAi.Runner.psm1 - orchestration + parallelism for v2.3
#
# Depends on OAi.Engine.psm1 (must be imported before this module).
#
# Exec groups and caps (from architecture doc):
#   reg-safe   -> 16    (parallel-safe)
#   sc-safe    -> 8
#   appx       -> 1     (DISM serializes)
#   defender   -> 1     (Set-MpPreference hates concurrency)
#   mitigation -> 1     (global system-wide)
#   folder     -> 1
#   report     -> 4
#
# Groups themselves run concurrently across categories; per-group caps constrain
# max-in-flight work in that group.
#

$ErrorActionPreference = 'Stop'

$script:ExecGroupCaps = @{
    'reg-safe'   = 16
    'sc-safe'    = 8
    'appx'       = 1
    'defender'   = 1
    'mitigation' = 1
    'folder'     = 1
    'report'     = 4
}

function _ValidExecGroups { return $script:ExecGroupCaps.Keys }

# ---------------------------------------------------------------------------
# New-Plan
# ---------------------------------------------------------------------------

function New-Plan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]]$Manifest,
        [string[]]$Categories = @('AI','PRIV','HARD','AUDIT'),
        [string[]]$Selected = @()
    )

    $filtered = New-Object System.Collections.Generic.List[object]
    foreach ($p in $Manifest) {
        if ($null -eq $p) { continue }
        if ($Selected -and $Selected.Count -gt 0) {
            if ($Selected -notcontains $p.Id) { continue }
        } else {
            if ($Categories -notcontains $p.Category) { continue }
        }
        $filtered.Add($p)
    }

    [pscustomobject]@{
        Categories = $Categories
        Selected   = $Selected
        Policies   = $filtered.ToArray()
        Count      = $filtered.Count
    }
}

# ---------------------------------------------------------------------------
# Invoke-Plan
# ---------------------------------------------------------------------------

function Invoke-Plan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Plan,
        [Parameter(Mandatory)] [string]$BackupDir,
        [object]$EventQueue = $null
    )

    $all = @($Plan.Policies)
    if ($all.Count -eq 0) {
        return [pscustomobject]@{
            Started  = (Get-Date)
            Finished = (Get-Date)
            Results  = @()
            Summary  = @{ total = 0; ok = 0; warn = 0; error = 0; skipped = 0 }
        }
    }

    $byGroup = @{}
    foreach ($p in $all) {
        $g = [string]$p.Group
        if (-not $script:ExecGroupCaps.ContainsKey($g)) {
            # unknown group: treat as serial
            $g = 'reg-safe'
        }
        if (-not $byGroup.ContainsKey($g)) {
            $byGroup[$g] = New-Object System.Collections.Generic.List[object]
        }
        $byGroup[$g].Add($p)
    }

    $started = Get-Date
    $allResults = New-Object System.Collections.Generic.List[object]

    $hasThreadJob = $false
    try {
        if (Get-Command -Name Start-ThreadJob -ErrorAction SilentlyContinue) {
            $hasThreadJob = $true
        }
    } catch {}

    # Launch one "group runner" per exec group. Each group runner processes its
    # own policies up to the group's cap. Groups run concurrently with each
    # other via Start-ThreadJob.
    $groupJobs = @()
    foreach ($g in $byGroup.Keys) {
        $polList = $byGroup[$g]
        $cap = $script:ExecGroupCaps[$g]

        if ($hasThreadJob) {
            $job = Start-ThreadJob -ScriptBlock {
                param($polArr, $cap, $backupDir, $enginePath)
                Import-Module $enginePath -Force
                $results = New-Object System.Collections.Generic.List[object]
                # sub-parallelism inside a group via nested ThreadJobs (bounded)
                $running = @()
                foreach ($pol in $polArr) {
                    while ($running.Count -ge $cap) {
                        $done = Wait-Job -Job $running -Any
                        foreach ($d in @($done)) {
                            $r = Receive-Job -Job $d -ErrorAction SilentlyContinue
                            if ($r) { foreach ($one in @($r)) { $results.Add($one) } }
                            Remove-Job -Job $d -Force -ErrorAction SilentlyContinue
                            $running = @($running | Where-Object { $_.Id -ne $d.Id })
                        }
                    }
                    $running += Start-ThreadJob -ScriptBlock {
                        param($pol, $backupDir, $enginePath)
                        Import-Module $enginePath -Force
                        Invoke-PolicyAction -Policy $pol -BackupDir $backupDir
                    } -ArgumentList $pol, $backupDir, $enginePath
                }
                if ($running.Count -gt 0) {
                    Wait-Job -Job $running | Out-Null
                    foreach ($d in $running) {
                        $r = Receive-Job -Job $d -ErrorAction SilentlyContinue
                        if ($r) { foreach ($one in @($r)) { $results.Add($one) } }
                        Remove-Job -Job $d -Force -ErrorAction SilentlyContinue
                    }
                }
                return , $results.ToArray()
            } -ArgumentList (,$polList.ToArray()), $cap, $BackupDir, (Join-Path $PSScriptRoot 'OAi.Engine.psm1')
            $groupJobs += [pscustomobject]@{ Group = $g; Job = $job }
        } else {
            # fully sequential fallback
            Write-Warning "Start-ThreadJob not available; running group '$g' sequentially"
            foreach ($pol in $polList) {
                $res = Invoke-PolicyAction -Policy $pol -BackupDir $BackupDir
                $allResults.Add($res)
                _Emit-Event -Queue $EventQueue -Result $res -Policy $pol
            }
        }
    }

    if ($hasThreadJob) {
        foreach ($gj in $groupJobs) {
            try {
                Wait-Job -Job $gj.Job | Out-Null
                $out = Receive-Job -Job $gj.Job -ErrorAction SilentlyContinue
                Remove-Job -Job $gj.Job -Force -ErrorAction SilentlyContinue
                if ($out) {
                    foreach ($r in @($out)) {
                        if ($null -ne $r) {
                            $allResults.Add($r)
                            _Emit-Event -Queue $EventQueue -Result $r -Policy $null
                        }
                    }
                }
            } catch {
                Write-Warning ("group '{0}' failed: {1}" -f $gj.Group, $_.Exception.Message)
            }
        }
    }

    $finished = Get-Date
    $summary = @{
        total   = $allResults.Count
        ok      = @($allResults | Where-Object { $_.Status -eq 'ok' }).Count
        warn    = @($allResults | Where-Object { $_.Status -eq 'warn' }).Count
        error   = @($allResults | Where-Object { $_.Status -eq 'error' }).Count
        skipped = @($allResults | Where-Object { $_.Status -eq 'skipped' }).Count
    }

    [pscustomobject]@{
        Started  = $started
        Finished = $finished
        Results  = $allResults.ToArray()
        Summary  = $summary
    }
}

function _Emit-Event {
    param($Queue, $Result, $Policy)
    if ($null -eq $Queue) { return }
    try {
        $evt = [pscustomobject]@{
            Time   = (Get-Date)
            Id     = $Result.Id
            Status = $Result.Status
            Ms     = $Result.DurationMs
            Msg    = $Result.Message
        }
        $Queue.Enqueue($evt)
    } catch {}
}

Export-ModuleMember -Function Invoke-Plan, New-Plan
