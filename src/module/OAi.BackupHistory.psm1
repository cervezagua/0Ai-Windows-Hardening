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
# then, so anything older is superseded. Only trusted runs (admin-only, or
# copies the user confirmed) can stop a search: otherwise any program could
# plant a revert.log to suppress a restore.
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
    #           Trusted     only a trusted run's RevertedIds stop a search
    # Returns a hashtable Id -> @{ Name; Dir; BackupFile }.
    param([string[]]$Ids, $Older)
    $map = @{}
    foreach ($id in @($Ids)) {
        foreach ($o in @($Older)) {
            if ($o.Trusted -and @($o.RevertedIds) -contains $id) { break }
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

$script:StampPattern = '^\d{4}-\d{2}-\d{2}_\d{6}$'

function Get-OAiCutoffName {
    # The timestamp that "older" is measured against: the selected folder's
    # own name, or for an imported-* working copy the name of the folder it
    # was copied from. $null (no fallback search) for anything else.
    param([string]$SelectedName, [string]$SourcePath)
    if ($SelectedName -match $script:StampPattern) { return $SelectedName }
    if ($SelectedName -like 'imported-*' -and $SourcePath) {
        # Split by hand: Split-Path only knows the current OS's separator.
        $leaf = @($SourcePath.Trim().TrimEnd('\', '/') -split '[\\/]')[-1]
        if ($leaf -match $script:StampPattern) { return $leaf }
    }
    return $null
}

function Select-OAiOlderFolders {
    # Folders (objects with Name, FullName) that are strictly older than
    # $Cutoff, newest first. Only timestamp-named folders count, and the
    # folders in $Exclude (the selected one and its original) never do.
    param($Folders, [string]$Cutoff, [string[]]$Exclude = @())
    if (-not $Cutoff) { return @() }
    $ex = @($Exclude | Where-Object { $_ } | ForEach-Object { $_.TrimEnd('\', '/').ToLowerInvariant() })
    $keep = @(@($Folders) | Where-Object {
            $_ -and $_.Name -match $script:StampPattern -and
            [string]::CompareOrdinal([string]$_.Name, $Cutoff) -lt 0 -and
            $ex -notcontains ([string]$_.FullName).TrimEnd('\', '/').ToLowerInvariant()
        })
    return @($keep | Sort-Object -Property @{ Expression = { [string]$_.Name } } -Descending)
}

Export-ModuleMember -Function Get-OAiRevertedIds, Select-OAiFallbackSnapshots, Get-OAiCutoffName, Select-OAiOlderFolders
