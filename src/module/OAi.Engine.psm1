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

# Undo-PolicyAction needs Resolve-OAiBackupFile and Read-OAiRegFileValue. No
# -Force: the entry script has normally imported it already. If this fails,
# every backup-reading undo branch fails closed (the call throws, nothing is
# written).
try { Import-Module (Join-Path $PSScriptRoot 'OAi.Manifest.psm1') -ErrorAction Stop } catch {}

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

function _Ensure-RegistryKey {
    # Not Test-Path + New-Item -Force: on an existing key the registry
    # provider's New-Item -Force deletes and recreates it, so two ThreadJobs
    # racing on the same key could wipe a sibling policy's value.
    # CreateSubKey opens-or-creates atomically and never deletes anything.
    param([string]$Hive, [string]$Key)
    switch ($Hive) {
        'HKLM' { $base = [Microsoft.Win32.RegistryHive]::LocalMachine }
        'HKCU' { $base = [Microsoft.Win32.RegistryHive]::CurrentUser }
        'HKCR' { $base = [Microsoft.Win32.RegistryHive]::ClassesRoot }
        default { throw ('unsupported hive: {0}' -f $Hive) }
    }
    $root = $null
    $sub  = $null
    try {
        $root = [Microsoft.Win32.RegistryKey]::OpenBaseKey($base, [Microsoft.Win32.RegistryView]::Default)
        # Read-only probe first so an existing key never needs KEY_CREATE_SUB_KEY.
        try { $sub = $root.OpenSubKey($Key, $false) } catch { $sub = $null }
        if ($null -eq $sub) {
            $sub = $root.CreateSubKey($Key)
            if ($null -eq $sub) { throw ('could not create {0}\{1}' -f $Hive, $Key) }
        }
    } catch [System.Management.Automation.MethodInvocationException] {
        # Unwrap so Invoke-PolicyAction still sees UnauthorizedAccessException /
        # SecurityException and reports an AV/ACL denial as 'warn'.
        if ($_.Exception.InnerException) { throw $_.Exception.InnerException }
        throw
    } finally {
        if ($null -ne $sub)  { $sub.Dispose() }
        if ($null -ne $root) { $root.Dispose() }
    }
}

function _Same-RegName {
    param([string]$A, [string]$B)
    return [string]::Equals(([string]$A).Trim('\'), ([string]$B).Trim('\'), [System.StringComparison]::OrdinalIgnoreCase)
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
# Get-OAiNotApplicableReason
#   Why a policy cannot apply on this PC, or '' if it can. Apply skips with
#   this reason and Verify reports it as n/a rather than "missing".
#     - MinBuild / MaxBuild: this Windows build is outside the range.
#     - Kind=Service, or RequiresService: the service is not installed
#       (e.g. IsoEnvBroker only exists with experimental agentic features).
#     - UcpdProtected: Windows' UserChoice Protection Driver (UCPD) blocks
#       scripted writes to the value, elevated or not; Group Policy can still
#       set it. The kit does not disable UCPD - it is a Windows protection.
$script:UcpdActive = $null
function _Test-UcpdActive {
    if ($null -ne $script:UcpdActive) { return $script:UcpdActive }
    $active = $false
    try {
        $d = Get-CimInstance -ClassName Win32_SystemDriver -Filter "Name='UCPD'" -ErrorAction Stop
        if ($d) { $active = ([string]$d.State -eq 'Running') }
    } catch {
        try {
            $start = (Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Services\UCPD' -Name Start -ErrorAction Stop).Start
            $active = ([int]$start -ne 4)
        } catch {}
    }
    $script:UcpdActive = $active
    return $active
}

$script:CurrentBuild = $null
function _Get-CurrentBuild {
    # 0 when unknown (e.g. tests off Windows): build gates then pass.
    if ($null -ne $script:CurrentBuild) { return $script:CurrentBuild }
    $b = 0
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
        if ($cv.CurrentBuild) { $b = [int]$cv.CurrentBuild }
    } catch {}
    $script:CurrentBuild = $b
    return $b
}

function _Get-Task {
    # $null when the scheduled task does not exist.
    param($Policy)
    try { return (Get-ScheduledTask -TaskPath $Policy.TaskPath -TaskName $Policy.TaskName -ErrorAction Stop) } catch { return $null }
}

function _Service-Installed {
    param([string]$Name)
    try { $null = Get-Service -Name $Name -ErrorAction Stop; return $true } catch { return $false }
}

function Get-OAiNotApplicableReason {
    param([Parameter(Mandatory)] $Policy)
    $build = _Get-CurrentBuild
    if ($build -gt 0) {
        if ($Policy.MinBuild -and [int]$Policy.MinBuild -gt 0 -and $build -lt [int]$Policy.MinBuild) {
            return ('needs Windows build {0} or later; this PC is {1}' -f $Policy.MinBuild, $build)
        }
        if ($Policy.MaxBuild -and [int]$Policy.MaxBuild -gt 0 -and $build -gt [int]$Policy.MaxBuild) {
            return ('applies up to Windows build {0} only; this PC is {1}' -f $Policy.MaxBuild, $build)
        }
    }
    if ($Policy.Kind -eq 'Service' -and $Policy.Name -and -not (_Service-Installed $Policy.Name)) {
        return ('service {0} is not installed on this PC' -f $Policy.Name)
    }
    if ($Policy.Kind -eq 'ScheduledTask' -and -not (_Get-Task $Policy)) {
        return ('scheduled task {0}{1} does not exist on this PC' -f $Policy.TaskPath, $Policy.TaskName)
    }
    if ($Policy.RequiresService -and -not (_Service-Installed $Policy.RequiresService)) {
        return ('service {0} is not installed on this PC' -f $Policy.RequiresService)
    }
    if ($Policy.UcpdProtected -eq $true -and $Policy.Kind -eq 'Registry' -and (_Test-UcpdActive)) {
        # Already set (e.g. through Group Policy): nothing is blocked.
        try {
            $path = (_Resolve-Hive $Policy.Hive) + '\' + $Policy.Key
            $cur = (Get-ItemProperty -LiteralPath $path -Name $Policy.Value -ErrorAction Stop).($Policy.Value)
            if ([string]$cur -eq [string]$Policy.Data) { return '' }
        } catch {}
        $msg = 'Windows UCPD blocks scripted writes to this value'
        if ($Policy.GroupPolicy) { $msg += '; set it with Group Policy: ' + $Policy.GroupPolicy }
        return $msg
    }
    return ''
}

# ---------------------------------------------------------------------------
# Test-Precondition

function Test-Precondition {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Policy
    )

    try {
        # Build gates (MinBuild / MaxBuild). Unknown build (test env) passes.
        $cb = _Get-CurrentBuild
        if ($cb -gt 0) {
            if ($Policy.MinBuild -and [int]$Policy.MinBuild -gt 0 -and $cb -lt [int]$Policy.MinBuild) { return $false }
            if ($Policy.MaxBuild -and [int]$Policy.MaxBuild -gt 0 -and $cb -gt [int]$Policy.MaxBuild) { return $false }
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
            'ScheduledTask' {
                $t = _Get-Task $Policy
                if (-not $t) { return $false }
                return ([string]$t.State -ne 'Disabled')
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
                    $snap.Data    = $item.GetValue($Policy.Value, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
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
            'ScheduledTask' {
                $fname = 'task_{0}.json' -f (_Sanitize-Filename ($Policy.TaskPath + $Policy.TaskName))
                $outFile = Join-Path $BackupDir $fname
                $t = _Get-Task $Policy
                $snap = [pscustomobject]@{
                    TaskPath = $Policy.TaskPath
                    TaskName = $Policy.TaskName
                    Existed  = [bool]$t
                    State    = $null
                }
                if ($t) { $snap.State = [string]$t.State }
                $snap | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 -FilePath $outFile
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
        $na = Get-OAiNotApplicableReason -Policy $Policy
        if (-not (Test-Precondition -Policy $Policy)) {
            $sw.Stop()
            $why = 'already applied or precondition not met'
            if ($na) { $why = $na }
            return (_New-Result -Id $Policy.Id -Status 'skipped' -DurationMs $sw.ElapsedMilliseconds -Message $why)
        }
        if ($na) {
            $sw.Stop()
            return (_New-Result -Id $Policy.Id -Status 'skipped' -DurationMs $sw.ElapsedMilliseconds -Message $na)
        }

        $backupFile = Backup-PolicyState -Policy $Policy -BackupDir $BackupDir

        switch ($Policy.Kind) {
            'Registry'    { $msg = _Apply-Registry    -Policy $Policy }
            'Service'     { $msg = _Apply-Service     -Policy $Policy }
            'ScheduledTask' {
                Disable-ScheduledTask -TaskPath $Policy.TaskPath -TaskName $Policy.TaskName -ErrorAction Stop | Out-Null
                $msg = ('disabled scheduled task {0}{1}' -f $Policy.TaskPath, $Policy.TaskName)
            }
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
    _Ensure-RegistryKey -Hive $Policy.Hive -Key $Policy.Key
    $propType = $Policy.Type
    if ($propType -eq 'REG_DWORD') { $propType = 'DWord' }
    if ($propType -eq 'REG_SZ')    { $propType = 'String' }
    try {
        New-ItemProperty -LiteralPath $path -Name $Policy.Value -Value $Policy.Data -PropertyType $propType -Force -ErrorAction Stop | Out-Null
    } catch {
        # -Force cannot always overwrite a value that already exists with a
        # different registry type (e.g. a String where we expect a DWord); the
        # write surfaces as an access/type failure. Retry once by deleting the
        # stale value first. If the retry also fails, rethrow the ORIGINAL
        # error so a genuine ACL / AV-tamper denial is still reported as such.
        $orig = $_
        try {
            Remove-ItemProperty -LiteralPath $path -Name $Policy.Value -Force -ErrorAction Stop
            New-ItemProperty -LiteralPath $path -Name $Policy.Value -Value $Policy.Data -PropertyType $propType -Force -ErrorAction Stop | Out-Null
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
                $bf  = Resolve-OAiBackupFile -BackupDir $BackupDir -Recorded $BackupFile
                $ext = ''
                if ($bf) { $ext = [System.IO.Path]::GetExtension($bf) }

                if ($bf -and $ext -eq '.json') {
                    # v2.9.4+ per-value snapshot. The backup folder is
                    # user-writable and Revert runs elevated, so the location
                    # always comes from the manifest; the snapshot only
                    # supplies Existed/Type/Data, and must agree with it.
                    $snap = Get-Content -Raw -LiteralPath $bf | ConvertFrom-Json
                    if (-not ((_Same-RegName $snap.Hive $Policy.Hive) -and (_Same-RegName $snap.Key $Policy.Key) -and (_Same-RegName $snap.Value $Policy.Value))) {
                        $sw.Stop()
                        return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ('snapshot {0} does not match {1}\{2}!{3} - not restored' -f $bf, $Policy.Hive, $Policy.Key, $Policy.Value))
                    }
                    if ($snap.Existed -isnot [bool]) {
                        $sw.Stop()
                        return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ('snapshot {0} has no valid Existed flag - not restored' -f $bf))
                    }
                    $type = [string]$snap.Type
                    if ($snap.Existed -and @('String','ExpandString','DWord','QWord','Binary','MultiString') -notcontains $type) {
                        $sw.Stop()
                        return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ('snapshot {0} has unsupported type "{1}" - not restored' -f $bf, $type))
                    }
                    $path = Join-Path (_Resolve-Hive $Policy.Hive) $Policy.Key
                    if ($snap.Existed) {
                        _Ensure-RegistryKey -Hive $Policy.Hive -Key $Policy.Key
                        $data = $snap.Data
                        # ConvertFrom-Json gives Binary / MultiString back as
                        # Object[]; New-ItemProperty needs typed arrays.
                        if ($type -eq 'Binary' -and $null -ne $data)      { $data = [byte[]]@($data) }
                        if ($type -eq 'MultiString' -and $null -ne $data) { $data = [string[]]@($data) }
                        New-ItemProperty -LiteralPath $path -Name $Policy.Value -Value $data -PropertyType $type -Force -ErrorAction Stop | Out-Null
                        $sw.Stop()
                        return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message ("restored {0}!{1} = {2}" -f $Policy.Key, $Policy.Value, $snap.Data))
                    } else {
                        # Value did not exist before we ran - remove it again.
                        try { Remove-ItemProperty -LiteralPath $path -Name $Policy.Value -ErrorAction Stop } catch {}
                        $sw.Stop()
                        return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message ("removed {0}!{1} (did not exist before apply)" -f $Policy.Key, $Policy.Value))
                    }
                } elseif ($bf) {
                    # Legacy .reg backup (v2.9.3 and earlier). Read once into
                    # memory and take only this policy's value; the file is
                    # never imported, so nothing else in it is ever applied.
                    $r = Read-OAiRegFileValue -Bytes ([System.IO.File]::ReadAllBytes($bf)) -Hive $Policy.Hive -Key $Policy.Key -Value $Policy.Value
                    $path = Join-Path (_Resolve-Hive $Policy.Hive) $Policy.Key
                    $sw.Stop()
                    switch ($r.Status) {
                        'found' {
                            # v2.9.3 and earlier exported one file per key and
                            # overwrote it for each policy on that key, so an
                            # earlier policy's file can hold the value the kit
                            # itself set. Policies already at Data were skipped
                            # without a backup, so this value cannot be the
                            # pre-apply one: treat as no backup.
                            if ($r.Type -eq $Policy.Type -and [string]$r.Data -eq [string]$Policy.Data) {
                                try { Remove-ItemProperty -LiteralPath $path -Name $Policy.Value -ErrorAction Stop } catch {}
                                return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ("legacy backup holds the kit's own value (taken after an earlier policy on this key); deleted {0}!{1} best-effort" -f $Policy.Key, $Policy.Value))
                            }
                            _Ensure-RegistryKey -Hive $Policy.Hive -Key $Policy.Key
                            New-ItemProperty -LiteralPath $path -Name $Policy.Value -Value $r.Data -PropertyType $r.Type -Force -ErrorAction Stop | Out-Null
                            return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message ("restored {0}!{1} = {2} (legacy backup)" -f $Policy.Key, $Policy.Value, $r.Data))
                        }
                        'absent' {
                            try { Remove-ItemProperty -LiteralPath $path -Name $Policy.Value -ErrorAction Stop } catch {}
                            return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message ("removed {0}!{1} (did not exist before apply; legacy backup)" -f $Policy.Key, $Policy.Value))
                        }
                        default {
                            return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ('legacy backup {0} not used: {1}' -f $bf, $r.Reason))
                        }
                    }
                } else {
                    # best-effort delete
                    $path = Join-Path (_Resolve-Hive $Policy.Hive) $Policy.Key
                    try {
                        Remove-ItemProperty -LiteralPath $path -Name $Policy.Value -ErrorAction Stop
                    } catch {}
                    $sw.Stop()
                    return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message 'no backup; deleted value best-effort')
                }
            }
            'Service' {
                $bf = Resolve-OAiBackupFile -BackupDir $BackupDir -Recorded $BackupFile
                if ($bf) {
                    try {
                        $snap = Get-Content -LiteralPath $bf -Raw | ConvertFrom-Json
                        if ($snap.Name -and -not [string]::Equals([string]$snap.Name, [string]$Policy.Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $sw.Stop()
                            return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ('service snapshot is for "{0}", not "{1}" - not restored' -f $snap.Name, $Policy.Name))
                        }
                        if ($snap.StartType -and @('Automatic','Manual','Disabled') -notcontains [string]$snap.StartType) {
                            $sw.Stop()
                            return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ('service snapshot has unsupported StartType "{0}" - not restored' -f $snap.StartType))
                        }
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
            'ScheduledTask' {
                $bf = Resolve-OAiBackupFile -BackupDir $BackupDir -Recorded $BackupFile
                $sw.Stop()
                if (-not $bf) {
                    return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message 'no task snapshot; left as it is')
                }
                try {
                    $snap = Get-Content -LiteralPath $bf -Raw | ConvertFrom-Json
                    if (-not ((_Same-RegName $snap.TaskPath $Policy.TaskPath) -and (_Same-RegName $snap.TaskName $Policy.TaskName))) {
                        return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ('task snapshot does not match {0}{1} - not restored' -f $Policy.TaskPath, $Policy.TaskName))
                    }
                    if ($snap.Existed -eq $true -and [string]$snap.State -ne 'Disabled') {
                        Enable-ScheduledTask -TaskPath $Policy.TaskPath -TaskName $Policy.TaskName -ErrorAction Stop | Out-Null
                        return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message ('re-enabled scheduled task {0}{1}' -f $Policy.TaskPath, $Policy.TaskName))
                    }
                    return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message 'task was already disabled before apply; left disabled')
                } catch {
                    return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message ('task revert failed: ' + $_.Exception.Message))
                }
            }
            'AppxRemove' {
                # v2.3 matches v2.2: we do NOT reinstall removed Appx packages.
                $sw.Stop()
                return (_New-Result -Id $Policy.Id -Status 'skipped' -DurationMs $sw.ElapsedMilliseconds -Message 'AppxRemove is not reinstalled (by design)')
            }
            'DefenderPref' {
                try {
                    $prefFile = Join-Path $BackupDir 'Defender_Prefs_before.json'
                    if (Test-Path -LiteralPath $prefFile -PathType Leaf) {
                        $snap = Get-Content -LiteralPath $prefFile -Raw | ConvertFrom-Json
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
                # Reset to the Windows DEFAULT - never force-disable.
                #
                # This previously ran `Set-ProcessMitigation -System -Disable`,
                # which does not undo the apply: it forces DEP / BottomUp /
                # HighEntropy / SEHOP OFF. Windows 11 enables those by default,
                # so an Apply -> Revert cycle left the machine measurably WEAKER
                # than if the kit had never run - the opposite of what a
                # hardening tool should do on rollback.
                #
                # Microsoft: once Set-ProcessMitigation has written a system
                # value, the only way back to the original NOTSET state is to
                # delete the MitigationOptions value. Note this clears ALL
                # system mitigation overrides, not just the ones the kit set -
                # that is inherent to how Windows stores them (a single packed
                # bitfield), not a choice we can make per-mitigation.
                try {
                    $kern = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
                    $cleared = @()
                    foreach ($v in @('MitigationOptions', 'MitigationAuditOptions')) {
                        try {
                            $null = Get-ItemProperty -Path $kern -Name $v -ErrorAction Stop
                            Remove-ItemProperty -Path $kern -Name $v -Force -ErrorAction Stop
                            $cleared += $v
                        } catch {
                            # value absent = already at Windows default; not an error
                        }
                    }
                    $sw.Stop()
                    if ($cleared.Count -gt 0) {
                        return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message ('reset to Windows defaults (cleared ' + ($cleared -join ', ') + '); reboot required'))
                    }
                    return (_New-Result -Id $Policy.Id -Status 'ok' -DurationMs $sw.ElapsedMilliseconds -Message 'already at Windows defaults (no system override present)')
                } catch {
                    $sw.Stop()
                    $em = $_.Exception.Message
                    $denied = ($_.Exception -is [System.UnauthorizedAccessException]) -or
                              ($_.Exception -is [System.Security.SecurityException]) -or
                              ($em -match '(?i)unauthorized|access is not allowed|access is denied')
                    $msg = if ($denied) { 'access denied - mitigations left as-is: ' + $em } else { 'mitigation reset failed: ' + $em }
                    return (_New-Result -Id $Policy.Id -Status 'warn' -DurationMs $sw.ElapsedMilliseconds -Message $msg)
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

# ---------------------------------------------------------------------------
# Get-OAiInteractiveUser
# ---------------------------------------------------------------------------

function Get-OAiInteractiveUser {
    # DOMAIN\user owning explorer.exe in this process's session - the person
    # at the desktop, who may differ from the elevated account (UAC
    # over-the-shoulder prompt with another admin's credentials). $null on
    # any failure; callers only use it to warn.
    [CmdletBinding()]
    param()
    try {
        $sid = [System.Diagnostics.Process]::GetCurrentProcess().SessionId
        $procs = @(Get-CimInstance -ClassName Win32_Process -Filter ("Name='explorer.exe' AND SessionId={0}" -f $sid) -ErrorAction Stop)
        foreach ($p in $procs) {
            $o = Invoke-CimMethod -InputObject $p -MethodName GetOwner -ErrorAction Stop
            if ($o -and $o.ReturnValue -eq 0 -and $o.User) {
                if ($o.Domain) { return ('{0}\{1}' -f $o.Domain, $o.User) }
                return [string]$o.User
            }
        }
        return $null
    } catch {
        return $null
    }
}

Export-ModuleMember -Function Invoke-PolicyAction, Test-Precondition, Backup-PolicyState, Undo-PolicyAction, Get-OAiInteractiveUser, Get-OAiNotApplicableReason
