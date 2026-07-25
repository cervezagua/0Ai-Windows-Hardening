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

function _Describe-RegistryAccess {
    # Best-effort explanation of WHY a registry write was denied. Read-only,
    # never throws - it only ever decorates a warning message.
    #
    # Identities are resolved to well-known SIDs rather than compared by name:
    # "BUILTIN\Administrators" is localized on non-English Windows (German
    # "Administratoren", Turkish "Yoneticiler", ...), so a name match would
    # silently fail on exactly the machines this kit already had locale bugs on.
    param($Policy)
    try {
        $path = Join-Path (_Resolve-Hive $Policy.Hive) $Policy.Key
        if (-not (Test-Path $path)) { return 'key does not exist' }

        $acl    = Get-Acl -Path $path -ErrorAction Stop
        $denies = New-Object System.Collections.Generic.List[string]
        $adminCanWrite = $false

        foreach ($ace in $acl.Access) {
            $sid = $null
            try {
                $sid = $ace.IdentityReference.Translate(
                    [System.Security.Principal.SecurityIdentifier]).Value
            } catch { }
            $isPrivileged = ($sid -eq 'S-1-5-32-544' -or $sid -eq 'S-1-5-18')  # Administrators, SYSTEM
            $rights = [string]$ace.RegistryRights

            if ($ace.AccessControlType -eq 'Deny') {
                [void]$denies.Add([string]$ace.IdentityReference)
            } elseif ($isPrivileged -and $rights -match 'FullControl|SetValue|WriteKey') {
                $adminCanWrite = $true
            }
        }

        $parts = @('owner=' + $acl.Owner)
        if ($denies.Count -gt 0) {
            $parts += ('explicit DENY for ' + (($denies | Select-Object -Unique) -join ', '))
        }
        if (-not $adminCanWrite) { $parts += 'Administrators have no write right' }
        return ($parts -join '; ')
    } catch {
        return ('ACL unreadable: ' + $_.Exception.Message)
    }
}

function _Sanitize-Filename {
    param([string]$Text)
    if (-not $Text) { return '_' }
    # -creplace (case-SENSITIVE), not -replace. PowerShell's -replace is
    # case-insensitive and folds case using the current culture. On Turkish /
    # Azeri locales, uppercase 'I' (U+0049) folds to dotless 'i' (U+0131),
    # which is outside the a-z range - so [^A-Za-z0-9._-] matched every 'I'
    # and mangled report names ("AUDIT" -> "AUD_T", "BuildInfo" -> "Build_nfo").
    # A case-sensitive replace does no case folding, so it is culture-proof.
    ($Text -creplace '[^A-Za-z0-9._-]', '_')
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
                # JSON snapshot of the SINGLE value we are about to change -
                # deliberately not a .reg export. Two reasons:
                #
                # 1. Antivirus. Bitdefender's Antivirus module deleted our
                #    exported HKLM_SOFTWARE_Policies_Microsoft_Dsh.reg and
                #    Advanced Threat Defense then "blocked all applications
                #    involved", which is what made the following write fail
                #    with "unauthorized operation". A script that spawns
                #    reg.exe to dump Policies keys into .reg files in a user
                #    folder looks exactly like malware staging registry
                #    payloads - and .reg files are themselves executable
                #    artifacts (double-clicking one merges it).
                # 2. Correctness. reg export/import round-trips the WHOLE
                #    key, so a revert could resurrect unrelated values or
                #    clobber changes made after apply. A per-value snapshot
                #    reverts exactly what we touched, and can represent
                #    "this value did not exist before" (revert = delete it),
                #    which reg import cannot express at all.
                $fname = 'reg_{0}.json' -f (_Sanitize-Filename ("{0}_{1}_{2}" -f $Policy.Hive, $Policy.Key, $Policy.Value))
                $outFile = Join-Path $BackupDir $fname
                $path = Join-Path (_Resolve-Hive $Policy.Hive) $Policy.Key
                $snap = [ordered]@{
                    Hive    = $Policy.Hive
                    Key     = $Policy.Key
                    Value   = $Policy.Value
                    Existed = $false
                    Type    = $null
                    Data    = $null
                }
                try {
                    $item = Get-Item -Path $path -ErrorAction Stop
                    # GetValueKind throws if the value is absent - that is the
                    # signal for "did not exist", handled by the catch below.
                    $kind = $item.GetValueKind($Policy.Value)
                    $snap.Existed = $true
                    $snap.Type    = $kind.ToString()
                    $snap.Data    = $item.GetValue($Policy.Value)
                } catch {
                    # key or value absent -> Existed stays $false
                }
                ($snap | ConvertTo-Json -Depth 4) | Out-File -Encoding UTF8 -FilePath $outFile
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
        # An access-denied write is an environmental condition, not a kit bug:
        # third-party AV tamper/registry-guard (e.g. Bitdefender) or a
        # TrustedInstaller-protected key can deny an otherwise-valid elevated
        # write. Report it as 'warn' with a clear cause instead of a hard
        # 'error' so the run doesn't look broken - the value simply isn't
        # applied. Genuine failures still surface as 'error'.
        $denied = ($_.Exception -is [System.UnauthorizedAccessException]) -or
                  ($_.Exception -is [System.Security.SecurityException]) -or
                  ($em -match '(?i)unauthorized|access is not allowed|access is denied')
        if ($denied) {
            $wm = 'access denied - not applied: ' + $em
            # For registry writes, say WHY rather than leaving the user to
            # guess. An explicit DENY ace or a non-Administrators owner means
            # something locked the key (some debloat tools do this deliberately
            # so Windows cannot revert their changes); the kit reports it and
            # stops there. It will not seize ownership to force the write -
            # that is a defense-evasion technique, and re-adopting it would
            # undo the AV work done in v2.9.1 and v2.9.4.
            if ($Policy.Kind -eq 'Registry') {
                $wm += ' | key ACL: ' + (_Describe-RegistryAccess -Policy $Policy)
            }
            return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message $wm -BackupFile $backupFile)
        }
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
    try {
        New-ItemProperty -Path $path -Name $Policy.Value -Value $Policy.Data -PropertyType $propType -Force -ErrorAction Stop | Out-Null
    } catch {
        # -Force cannot always overwrite a value that already exists with a
        # different registry type (e.g. a String where we expect a DWord); the
        # write surfaces as an access/type failure. Retry once by deleting the
        # stale value first. If the retry also fails, rethrow the ORIGINAL
        # error so a genuine ACL / AV-tamper denial is still reported as such.
        $orig = $_
        try {
            Remove-ItemProperty -Path $path -Name $Policy.Value -Force -ErrorAction Stop
            New-ItemProperty -Path $path -Name $Policy.Value -Value $Policy.Data -PropertyType $propType -Force -ErrorAction Stop | Out-Null
        } catch {
            throw $orig
        }
    }
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
                $ext = ''
                if ($BackupFile) { $ext = [System.IO.Path]::GetExtension($BackupFile) }

                if ($BackupFile -and (Test-Path $BackupFile) -and $ext -eq '.json') {
                    # v2.9.4+ per-value snapshot.
                    $path = Join-Path (_Resolve-Hive $Policy.Hive) $Policy.Key
                    $snap = Get-Content -Raw -Path $BackupFile | ConvertFrom-Json
                    if ($snap.Existed) {
                        if (-not (Test-Path $path)) {
                            New-Item -Path $path -Force -ErrorAction Stop | Out-Null
                        }
                        $data = $snap.Data
                        # ConvertFrom-Json gives Binary back as an Object[] of
                        # numbers; New-ItemProperty needs a real byte[].
                        if ($snap.Type -eq 'Binary' -and $null -ne $data) { $data = [byte[]]$data }
                        New-ItemProperty -Path $path -Name $snap.Value -Value $data -PropertyType $snap.Type -Force -ErrorAction Stop | Out-Null
                        $sw.Stop()
                        return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message ("restored {0}!{1} = {2}" -f $snap.Key, $snap.Value, $snap.Data))
                    } else {
                        # Value did not exist before we ran - remove it again.
                        try { Remove-ItemProperty -Path $path -Name $Policy.Value -ErrorAction Stop } catch {}
                        $sw.Stop()
                        return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message ("removed {0}!{1} (did not exist before apply)" -f $Policy.Key, $Policy.Value))
                    }
                } elseif ($BackupFile -and (Test-Path $BackupFile)) {
                    # Legacy .reg backup written by v2.9.3 and earlier.
                    $null = & reg.exe import $BackupFile 2>&1
                    $sw.Stop()
                    return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message "reg import $BackupFile (legacy backup)")
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
