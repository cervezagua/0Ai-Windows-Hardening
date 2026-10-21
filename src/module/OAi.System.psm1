#
# OAi.System.psm1 - v2.15.0 system checks shared by Apply / Revert / Verify
#
#   Get-OAiRestorePointResult   decide what happened to a restore point
#                               request (pure; unit-tested)
#   Invoke-OAiRestorePoint      request one and report the real outcome
#   Get-OAiDomainNote           warning text for domain-joined PCs, or ''
#

$ErrorActionPreference = 'Stop'

function Get-OAiRestorePointResult {
    # Windows creates at most one restore point per 24 hours by default
    # (SystemRestorePointCreationFrequency) and then only writes a warning,
    # so "no error" does not mean "created". Compare the points before and
    # after the request instead.
    #   Before / After : sequence numbers of the existing restore points
    #   Latest         : creation time of the newest point before the request
    #   ErrorText      : the request's error message, if it threw
    param([int[]]$Before = @(), [int[]]$After = @(), [string]$Latest = '', [string]$ErrorText = '')
    $maxBefore = -1
    foreach ($n in @($Before)) { if ($n -gt $maxBefore) { $maxBefore = $n } }
    foreach ($n in @($After)) {
        if ($n -gt $maxBefore) { return [pscustomobject]@{ Status = 'created'; Message = 'Restore point created.' } }
    }
    if ($ErrorText) {
        return [pscustomobject]@{ Status = 'unavailable'; Message = ('Restore point unavailable: ' + $ErrorText) }
    }
    if (@($Before).Count -gt 0) {
        $when = 'the last 24 hours'
        if ($Latest) { $when = $Latest }
        return [pscustomobject]@{ Status = 'skipped'; Message = ('Restore point skipped by Windows: one already exists from {0} (Windows creates at most one per 24 hours).' -f $when) }
    }
    return [pscustomobject]@{ Status = 'unavailable'; Message = 'Restore point not created: System Restore is probably turned off for the system drive.' }
}

function _Get-RestorePoints {
    try { return @(Get-ComputerRestorePoint -ErrorAction Stop) } catch { return @() }
}

function Invoke-OAiRestorePoint {
    param([Parameter(Mandatory)][string]$Description)
    if (-not (Get-Command Checkpoint-Computer -ErrorAction SilentlyContinue)) {
        return [pscustomobject]@{ Status = 'unavailable'; Message = 'Restore point unavailable: Checkpoint-Computer needs Windows PowerShell 5.1.' }
    }
    $before = _Get-RestorePoints
    $latest = ''
    if ($before.Count -gt 0) {
        $last = $before | Sort-Object SequenceNumber | Select-Object -Last 1
        try { $latest = $last.ConvertToDateTime($last.CreationTime).ToString('yyyy-MM-dd HH:mm') } catch { $latest = [string]$last.CreationTime }
    }
    $err = ''
    try {
        Checkpoint-Computer -Description $Description -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop -WarningAction SilentlyContinue | Out-Null
    } catch { $err = $_.Exception.Message }
    $after = _Get-RestorePoints
    return Get-OAiRestorePointResult -Before @($before | ForEach-Object { [int]$_.SequenceNumber }) -After @($after | ForEach-Object { [int]$_.SequenceNumber }) -Latest $latest -ErrorText $err
}

function Get-OAiDomainNote {
    try {
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        if ($cs.PartOfDomain) {
            return ('This PC is joined to the domain {0}. Your organisation''s Group Policy can override or undo these settings at the next policy refresh.' -f $cs.Domain)
        }
    } catch {}
    return ''
}

Export-ModuleMember -Function Get-OAiRestorePointResult, Invoke-OAiRestorePoint, Get-OAiDomainNote
