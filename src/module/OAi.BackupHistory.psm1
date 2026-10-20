#
# OAi.BackupHistory.psm1 - v2.14.5 snapshots from older backups
#
# Apply skips a policy that is already in place and takes no snapshot of it.
# After a second Apply, the newest backup therefore has no "before" value
# for most policies, and Revert used to delete them (or leave services as
# they were). Revert now looks for each such Id in older backups: the newest
# older run that recorded a snapshot for it holds the value from before the
# kit last changed it.
#
# A search stops at an older run whose own Revert already restored that Id
# ("[ok     ] <Id>" in its revert.log): that run's "before" value was put back
# then, so anything older is superseded.
#
# Pure functions on plain data; Revert.ps1 does the file system work.
#

$ErrorActionPreference = 'Stop'

function Get-OAiRevertedIds {
    # Ids a revert.log reports as restored. Lines look like
    #   [ok     ] HARD.Defender.PUAProtection  restored PUAProtection=2
    param([string]$LogText)
    $ids = New-Object System.Collections.Generic.List[string]
    if (-not $LogText) { return @() }
    foreach ($line in ($LogText -split "`r?`n")) {
        $m = [regex]::Match($line, '^\[ok\s*\]\s+(\S+)\s')
        if ($m.Success) { $ids.Add($m.Groups[1].Value) }
    }
    return $ids.ToArray()
}

function Select-OAiFallbackSnapshots {
    # Ids   : Ids that have no snapshot in the backup being reverted
    # Older : older backups, NEWEST FIRST, each an object with
    #           Name        folder name (timestamp)
    #           Dir         folder to read the snapshot from
    #           Results     run.json results (objects with Id, BackupFile)
    #           Files       leaf names of the files present in Dir
    #           RevertedIds Ids its own revert.log reports as restored
    # Returns a hashtable Id -> @{ Name; Dir; BackupFile }.
    param([string[]]$Ids, $Older)
    $map = @{}
    foreach ($id in @($Ids)) {
        foreach ($o in @($Older)) {
            if (@($o.RevertedIds) -contains $id) { break }
            $hit = $null
            foreach ($r in @($o.Results)) {
                if ([string]$r.Id -ne $id) { continue }
                $bf = [string]$r.BackupFile
                if (-not $bf) { continue }
                $leaf = @($bf -split '[\\/]')[-1]
                if (@($o.Files) -contains $leaf) { $hit = $leaf; break }
            }
            if ($hit) {
                $map[$id] = @{ Name = $o.Name; Dir = $o.Dir; BackupFile = $hit }
                break
            }
        }
    }
    return $map
}

Export-ModuleMember -Function Get-OAiRevertedIds, Select-OAiFallbackSnapshots
