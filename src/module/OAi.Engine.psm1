#
# OAi.Engine.psm1 - pure primitives for v2.3
#
# No UI, no orchestration. Returns PolicyResult records and never throws to the caller.
#
# A PolicyResult is a [pscustomobject] with:
#   Id         [string]   policy id
#   Status     [string]   'ok' | 'warn' | 'error' | 'skipped'
#   DurationMs [int]      wall-clock ms for the dispatch
#   Message    [string]   human-readable status
#   BackupFile [string]   path to backup snapshot (or empty)
#

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

function _New-Result {
    param(
        [string]$Id,
        [string]$Status,
        [int]$DurationMs,
        [string]$Message = '',
        [string]$BackupFile = ''
    )
    [pscustomobject]@{
        Id         = $Id
        Status     = $Status
        DurationMs = $DurationMs
        Message    = $Message
        BackupFile = $BackupFile
    }
}

function _Resolve-Hive {
    param([string]$Hive)
    switch ($Hive) {
        'HKLM' { return 'HKLM:' }
        'HKCU' { return 'HKCU:' }
        'HKCR' { return 'HKCR:' }
        default { return ($Hive + ':') }
    }
}

function _Sanitize-Filename {
    param([string]$Text)
    if (-not $Text) { return '_' }
    ($Text -replace '[^A-Za-z0-9._-]', '_')
}

# ---------------------------------------------------------------------------
# Test-Precondition
# ---------------------------------------------------------------------------

function Test-Precondition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Policy
    )

    try {
        # MinBuild gate
        if ($Policy.MinBuild -and $Policy.MinBuild -gt 0) {
            try {
                $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
                if ($cv -and $cv.CurrentBuild) {
                    $cb = [int]$cv.CurrentBuild
                    if ($cb -lt [int]$Policy.MinBuild) {
                        return $false
                    }
                }
            } catch {
                # If we can't read the build, assume gate passes (we're probably on Linux test env).
            }
        }

        switch ($Policy.Kind) {
            'Registry' {
                $path = Join-Path (_Resolve-Hive $Policy.Hive) $Policy.Key
                try {
                    $cur = Get-ItemProperty -Path $path -Name $Policy.Value -ErrorAction Stop
                    if ($null -ne $cur.$($Policy.Value) -and $cur.$($Policy.Value) -eq $Policy.Data) {
                        return $false # already applied - skip
                    }
                } catch {
                    # not set -> needs to run
                }
                return $true
            }
            'Service' {
                try {
                    $svc = Get-Service -Name $Policy.Name -ErrorAction Stop
                    if ($svc.Status -eq 'Stopped' -and $svc.StartType -eq 'Disabled') {
                        return $false
                    }
                } catch {
                    return $false # service missing - skip silently
                }
                return $true
            }
            default { return $true }
        }
    } catch {
        return $true
    }
}

# ---------------------------------------------------------------------------
# Backup-PolicyState
# ---------------------------------------------------------------------------

function Backup-PolicyState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string]$BackupDir
    )

    try {
        if (-not (Test-Path $BackupDir)) {
            New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
        }

        switch ($Policy.Kind) {
            'Registry' {
                $fname = '{0}.reg' -f (_Sanitize-Filename ("{0}_{1}" -f $Policy.Hive, $Policy.Key))
                $outFile = Join-Path $BackupDir $fname
                $regPath = ('{0}\{1}' -f $Policy.Hive, $Policy.Key)
                $null = & reg.exe export $regPath $outFile /y 2>&1
                return $outFile
            }
            'Service' {
                $fname = 'service_{0}.json' -f (_Sanitize-Filename $Policy.Name)
                $outFile = Join-Path $BackupDir $fname
                try {
                    $svc = Get-Service -Name $Policy.Name -ErrorAction Stop
                    $wmi = $null
                    try { $wmi = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $Policy.Name) -ErrorAction SilentlyContinue } catch {}
                    $snap = [pscustomobject]@{
                        Name      = $svc.Name
                        Status    = $svc.Status.ToString()
                        StartType = $svc.StartType.ToString()
                        StartMode = if ($wmi) { $wmi.StartMode } else { $null }
                    }
                    $snap | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 -FilePath $outFile
                } catch {
                    '{"error":"service not found"}' | Out-File -Encoding UTF8 -FilePath $outFile
                }
                return $outFile
            }
            'AppxRemove' {
                $fname = 'appx_{0}.json' -f (_Sanitize-Filename $Policy.Id)
                $outFile = Join-Path $BackupDir $fname
                try {
                    $matches = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {
                        $_.Name -match $Policy.NamePattern -or $_.PackageFamilyName -match $Policy.NamePattern
                    } | Select-Object Name, PackageFullName, PackageFamilyName, Version
                    if ($matches) {
                        $matches | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 -FilePath $outFile
                    } else {
                        '[]' | Out-File -Encoding UTF8 -FilePath $outFile
                    }
                } catch {
                    '[]' | Out-File -Encoding UTF8 -FilePath $outFile
                }
                return $outFile
            }
            'DefenderPref' {
                $outFile = Join-Path $BackupDir 'Defender_Prefs_before.json'
                if (-not (Test-Path $outFile)) {
                    try {
                        Get-MpPreference -ErrorAction Stop | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 -FilePath $outFile
                    } catch {
                        '{"error":"Get-MpPreference unavailable"}' | Out-File -Encoding UTF8 -FilePath $outFile
                    }
                }
                return $outFile
            }
            'DefenderAsr' {
                $outFile = Join-Path $BackupDir 'Defender_Prefs_before.json'
                if (-not (Test-Path $outFile)) {
                    try {
                        Get-MpPreference -ErrorAction Stop | ConvertTo-Json -Depth 6 | Out-File -Encoding UTF8 -FilePath $outFile
                    } catch {
                        '{"error":"Get-MpPreference unavailable"}' | Out-File -Encoding UTF8 -FilePath $outFile
                    }
                }
                return $outFile
            }
            'Mitigation' {
                $outFile = Join-Path $BackupDir 'ProcessMitigation_System_before.xml'
                if (-not (Test-Path $outFile)) {
                    try {
                        Get-ProcessMitigation -System -ErrorAction Stop | Out-File -Encoding UTF8 -FilePath $outFile
                    } catch {
                        'unavailable' | Out-File -Encoding UTF8 -FilePath $outFile
                    }
                }
                return $outFile
            }
            'FolderPurge' { return '' }
            'Report'      { return '' }
            default       { return '' }
        }
    } catch {
        return ''
    }
}

# ---------------------------------------------------------------------------
# Invoke-PolicyAction
# ---------------------------------------------------------------------------

function Invoke-PolicyAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string]$BackupDir
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $backupFile = ''

    try {
        if (-not (Test-Precondition -Policy $Policy)) {
            $sw.Stop()
            return (_New-Result -Id $Policy.Id -Status 'skipped' -DurationMs $sw.ElapsedMilliseconds -Message 'already applied or precondition not met')
        }

        $backupFile = Backup-PolicyState -Policy $Policy -BackupDir $BackupDir

        switch ($Policy.Kind) {
            'Registry'    { $msg = _Apply-Registry    -Policy $Policy }
            'Service'     { $msg = _Apply-Service     -Policy $Policy }
            'AppxRemove'  { $msg = _Apply-AppxRemove  -Policy $Policy }
            'DefenderPref' { $msg = _Apply-DefenderPref -Policy $Policy }
            'DefenderAsr'  { $msg = _Apply-DefenderAsr  -Policy $Policy }
            'Mitigation'  { $msg = _Apply-Mitigation  -Policy $Policy }
            'FolderPurge' { $msg = _Apply-FolderPurge -Policy $Policy }
            'Report'      { $msg = _Apply-Report      -Policy $Policy -BackupDir $BackupDir }
            default {
                $sw.Stop()
                return (_New-Result -Id $Policy.Id -Status 'error' -DurationMs $sw.ElapsedMilliseconds -Message "unknown Kind: $($Policy.Kind)" -BackupFile $backupFile)
            }
        }

        $sw.Stop()
        return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message $msg -BackupFile $backupFile)
    } catch {
        $sw.Stop()
        $em = $_.Exception.Message
        return (_New-Result -Id $Policy.Id -Status 'error' -DurationMs $sw.ElapsedMilliseconds -Message $em -BackupFile $backupFile)
    }
}

# ---------------------------------------------------------------------------
# Per-kind apply helpers (private)
# ---------------------------------------------------------------------------

function _Apply-Registry {
    param($Policy)
    $path = Join-Path (_Resolve-Hive $Policy.Hive) $Policy.Key
    if (-not (Test-Path $path)) {
        New-Item -Path $path -Force -ErrorAction Stop | Out-Null
    }
    $propType = $Policy.Type
    if ($propType -eq 'REG_DWORD') { $propType = 'DWord' }
    if ($propType -eq 'REG_SZ')    { $propType = 'String' }
    New-ItemProperty -Path $path -Name $Policy.Value -Value $Policy.Data -PropertyType $propType -Force -ErrorAction Stop | Out-Null
    return "set $($Policy.Hive)\$($Policy.Key)!$($Policy.Value) = $($Policy.Data)"
}

function _Apply-Service {
    param($Policy)
    $ok = $true
    $msgs = @()
    try {
        $svc = Get-Service -Name $Policy.Name -ErrorAction Stop
        if ($svc.Status -ne 'Stopped') {
            try {
                Stop-Service -Name $Policy.Name -Force -ErrorAction Stop
                $msgs += 'stopped'
            } catch {
                $msgs += ('stop-failed: ' + $_.Exception.Message)
                $ok = $false
            }
        }
        try {
            Set-Service -Name $Policy.Name -StartupType Disabled -ErrorAction Stop
            $msgs += 'disabled'
        } catch {
            $msgs += ('disable-failed: ' + $_.Exception.Message)
            $ok = $false
        }
    } catch {
        throw "service '$($Policy.Name)' not found"
    }
    if (-not $ok) { throw ($msgs -join '; ') }
    return ($msgs -join '; ')
}

function _Apply-AppxRemove {
    param($Policy)
    $removed = 0
    $pat = $Policy.NamePattern
    try {
        $list = Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match $pat -or $_.PackageFamilyName -match $pat
        }
        foreach ($p in $list) {
            try {
                Remove-AppxPackage -Package $p.PackageFullName -ErrorAction Stop
                $removed++
            } catch {}
        }
    } catch {}
    if ($Policy.AllUsers) {
        try {
            $list2 = Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -match $pat -or $_.PackageFamilyName -match $pat
            }
            foreach ($p in $list2) {
                try {
                    Remove-AppxPackage -Package $p.PackageFullName -AllUsers -ErrorAction Stop
                    $removed++
                } catch {
                    try {
                        Remove-AppxPackage -Package $p.PackageFullName -ErrorAction Stop
                        $removed++
                    } catch {}
                }
            }
        } catch {}
    }
    if ($Policy.Provisioned) {
        try {
            $prov = Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Where-Object {
                $_.PackageName -match $pat -or $_.DisplayName -match $pat
            }
            foreach ($p in $prov) {
                try {
                    Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null
                    $removed++
                } catch {}
            }
        } catch {}
    }
    return "removed $removed package(s) matching /$pat/"
}

function _Apply-DefenderPref {
    param($Policy)
    $args = @{}
    $args[$Policy.Preference] = $Policy.Value
    Set-MpPreference @args -ErrorAction Stop
    return "Set-MpPreference -$($Policy.Preference) $($Policy.Value)"
}

function _Apply-DefenderAsr {
    param($Policy)
    Add-MpPreference -AttackSurfaceReductionRules_Ids $Policy.RuleId -AttackSurfaceReductionRules_Actions $Policy.Action -ErrorAction Stop
    return "ASR $($Policy.RuleId) = $($Policy.Action)"
}

function _Apply-Mitigation {
    param($Policy)
    $enable = @($Policy.Enable)
    if ($enable.Count -gt 0) {
        Set-ProcessMitigation -System -Enable $enable -ErrorAction Stop
    }
    if ($Policy.Disable -and @($Policy.Disable).Count -gt 0) {
        Set-ProcessMitigation -System -Disable @($Policy.Disable) -ErrorAction Stop
    }
    return ('enabled: ' + ($enable -join ','))
}

function _Apply-FolderPurge {
    param($Policy)
    $p = [System.Environment]::ExpandEnvironmentVariables($Policy.Path)
    if (Test-Path $p) {
        Remove-Item -Path $p -Recurse -Force -ErrorAction SilentlyContinue
        return "purged $p"
    }
    return "nothing to purge at $p"
}

function _Apply-Report {
    param($Policy, [string]$BackupDir)
    $outPath = Join-Path $BackupDir ('report_' + (_Sanitize-Filename $Policy.Id) + '.json')
    try {
        $sb = [scriptblock]::Create($Policy.Script)
        $res = & $sb
        # Always write valid JSON. A $null / empty result must become "[]",
        # not a zero-byte file. ($null | ConvertTo-Json | Out-File drops silently.)
        if ($null -eq $res) { $res = @() }
        $json = ConvertTo-Json -InputObject $res -Depth 6
        if ([string]::IsNullOrEmpty($json)) { $json = '[]' }
        $json | Out-File -Encoding UTF8 -FilePath $outPath
        return "report written: $outPath"
    } catch {
        ('{"error":"' + $_.Exception.Message.Replace('"', "'") + '"}') | Out-File -Encoding UTF8 -FilePath $outPath
        return "report failed (recorded): $outPath"
    }
}

# ---------------------------------------------------------------------------
# Undo-PolicyAction
# ---------------------------------------------------------------------------

function Undo-PolicyAction {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Policy,
        [Parameter(Mandatory)] [string]$BackupDir,
        [string]$BackupFile = ''
    )

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        switch ($Policy.Kind) {
            'Registry' {
                if ($BackupFile -and (Test-Path $BackupFile)) {
                    $null = & reg.exe import $BackupFile 2>&1
                    $sw.Stop()
                    return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message "reg import $BackupFile")
                } else {
                    # best-effort delete
                    $path = Join-Path (_Resolve-Hive $Policy.Hive) $Policy.Key
                    try {
                        Remove-ItemProperty -Path $path -Name $Policy.Value -ErrorAction Stop
                    } catch {}
                    $sw.Stop()
                    return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message 'no backup; deleted value best-effort')
                }
            }
            'Service' {
                if ($BackupFile -and (Test-Path $BackupFile)) {
                    try {
                        $snap = Get-Content -Path $BackupFile -Raw | ConvertFrom-Json
                        if ($snap.StartType) {
                            Set-Service -Name $Policy.Name -StartupType $snap.StartType -ErrorAction Stop
                        }
                        $sw.Stop()
                        return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message ("restored StartType={0}" -f $snap.StartType))
                    } catch {
                        $sw.Stop()
                        return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ('service revert failed: ' + $_.Exception.Message))
                    }
                }
                $sw.Stop()
                return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message 'no service snapshot')
            }
            'AppxRemove' {
                # v2.3 matches v2.2: we do NOT reinstall removed Appx packages.
                $sw.Stop()
                return (_New-Result -Id $Policy.Id -Status 'skipped' -DurationMs $sw.ElapsedMilliseconds -Message 'AppxRemove is not reinstalled (by design)')
            }
            'DefenderPref' {
                try {
                    $prefFile = Join-Path $BackupDir 'Defender_Prefs_before.json'
                    if (Test-Path $prefFile) {
                        $snap = Get-Content -Path $prefFile -Raw | ConvertFrom-Json
                        $val = $snap.$($Policy.Preference)
                        if ($null -ne $val) {
                            $args = @{}
                            $args[$Policy.Preference] = $val
                            Set-MpPreference @args -ErrorAction Stop
                            $sw.Stop()
                            return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message ("restored $($Policy.Preference)=$val"))
                        }
                    }
                    $sw.Stop()
                    return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message 'no defender snapshot')
                } catch {
                    $sw.Stop()
                    return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ('defender revert failed: ' + $_.Exception.Message))
                }
            }
            'DefenderAsr' {
                try {
                    Remove-MpPreference -AttackSurfaceReductionRules_Ids $Policy.RuleId -ErrorAction Stop
                    $sw.Stop()
                    return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message ("removed ASR $($Policy.RuleId)"))
                } catch {
                    $sw.Stop()
                    return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ('ASR remove failed: ' + $_.Exception.Message))
                }
            }
            'Mitigation' {
                try {
                    $en = @($Policy.Enable)
                    if ($en.Count -gt 0) {
                        Set-ProcessMitigation -System -Disable $en -ErrorAction Stop
                    }
                    $sw.Stop()
                    return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message ('disabled: ' + ($en -join ',')))
                } catch {
                    $sw.Stop()
                    return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ('mitigation revert failed: ' + $_.Exception.Message))
                }
            }
            'FolderPurge' {
                $sw.Stop()
                return (_New-Result -Id $Policy.Id -Status 'skipped' -DurationMs $sw.ElapsedMilliseconds -Message 'FolderPurge is not reversible')
            }
            'Report' {
                $sw.Stop()
                return (_New-Result -Id $Policy.Id -Status 'skipped' -DurationMs $sw.ElapsedMilliseconds -Message 'Report is read-only')
            }
            default {
                $sw.Stop()
                return (_New-Result -Id $Policy.Id -Status 'error' -DurationMs $sw.ElapsedMilliseconds -Message "unknown Kind: $($Policy.Kind)")
            }
        }
    } catch {
        $sw.Stop()
        return (_New-Result -Id $Policy.Id -Status 'error' -DurationMs $sw.ElapsedMilliseconds -Message $_.Exception.Message)
    }
}

Export-ModuleMember -Function Invoke-PolicyAction, Test-Precondition, Backup-PolicyState, Undo-PolicyAction
