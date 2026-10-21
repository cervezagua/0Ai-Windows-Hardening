#
# OAi.Users.psm1 - v2.15.0 per-user (HKCU) policies for every profile
#
# HKCU policies normally reach only the account running the kit. With
# -AllUsers, Apply / Verify / Revert also cover every other local profile
# and the Default profile (which seeds accounts created later), the way
# Sysprep-style tools do:
#
#   - a signed-in user's hive is already loaded as HKEY_USERS\<SID>;
#   - otherwise the profile's NTUSER.DAT is loaded as HKEY_USERS\0AI_<label>
#     with reg.exe load, and unloaded again afterwards (load/unload only:
#     no .reg import, no P/Invoke).
#
# Each HKCU policy gets a copy per profile: Id "<Id>@<label>", Hive "HKU",
# Key "<mount>\<Key>". Its snapshot records "HKCU@<label>" + the original
# Key, so a backup names the user, not where the hive happened to be
# mounted - Revert works whether or not that user is signed in.
#
# Pure functions (unit-tested): Select-OAiUserTargets, New-OAiTargetPolicy,
# Split-OAiTargetId. Windows side: Get-OAiUserTargets, Mount-OAiUserHive,
# Dismount-OAiUserHive.
#

$ErrorActionPreference = 'Stop'

function Split-OAiTargetId {
    # 'AI.X.HKCU@S-1-5-21-1-2-3-1001' -> BaseId 'AI.X.HKCU', Label 'S-1-5-21-...'
    param([string]$Id)
    $i = $Id.LastIndexOf('@')
    if ($i -le 0) { return [pscustomobject]@{ BaseId = $Id; Label = '' } }
    return [pscustomobject]@{ BaseId = $Id.Substring(0, $i); Label = $Id.Substring($i + 1) }
}

function Select-OAiUserTargets {
    # Profiles   : objects with Sid, Path (profile folder), HasHive (NTUSER.DAT
    #              exists), Loaded (HKEY_USERS\<Sid> present)
    # CurrentSid : the account running the kit (already covered as HKCU)
    # DefaultPath: the Default profile folder ('' if unknown)
    # DefaultHasHive: its NTUSER.DAT exists
    # Returns targets: Label, Sid, Name, HivePath, Mount, NeedsLoad.
    param($Profiles, [string]$CurrentSid, [string]$DefaultPath = '', [bool]$DefaultHasHive = $false)
    $out = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($Profiles)) {
        if (-not $p) { continue }
        $sid = [string]$p.Sid
        # Real accounts only: S-1-5-21-* (local and domain users). Not SYSTEM,
        # LocalService, NetworkService, nor the account running the kit.
        if ($sid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { continue }
        if ($sid -eq $CurrentSid) { continue }
        if (-not $p.HasHive -and -not $p.Loaded) { continue }
        $mount = '0AI_' + $sid
        if ($p.Loaded) { $mount = $sid }
        $name = @(([string]$p.Path).TrimEnd('\', '/') -split '[\\/]')[-1]
        $out.Add([pscustomobject]@{
                Label     = $sid
                Sid       = $sid
                Name      = $name
                HivePath  = (([string]$p.Path).TrimEnd('\', '/') + '\NTUSER.DAT')
                Mount     = $mount
                NeedsLoad = (-not $p.Loaded)
            })
    }
    if ($DefaultPath -and $DefaultHasHive) {
        $out.Add([pscustomobject]@{
                Label     = 'Default'
                Sid       = ''
                Name      = 'Default profile (new accounts)'
                HivePath  = ($DefaultPath.TrimEnd('\', '/') + '\NTUSER.DAT')
                Mount     = '0AI_Default'
                NeedsLoad = $true
            })
    }
    return $out.ToArray()
}

function New-OAiTargetPolicy {
    # A copy of an HKCU Registry policy aimed at one target profile, or
    # $null for anything else (only HKCU registry values are per user).
    param([Parameter(Mandatory)] $Policy, [Parameter(Mandatory)] $Target)
    if ($Policy.Kind -ne 'Registry' -or [string]$Policy.Hive -ne 'HKCU') { return $null }
    $copy = @{}
    foreach ($k in @($Policy.Keys)) { $copy[$k] = $Policy[$k] }
    $copy.Id           = ('{0}@{1}' -f $Policy.Id, $Target.Label)
    $copy.Hive         = 'HKU'
    $copy.Key          = ('{0}\{1}' -f $Target.Mount, $Policy.Key)
    $copy.SnapshotHive = ('HKCU@{0}' -f $Target.Label)
    $copy.SnapshotKey  = $Policy.Key
    $copy.TargetLabel  = $Target.Label
    $copy.TargetName   = $Target.Name
    # Serial exec group: other users' hives are handled one write at a time.
    $copy.Group        = 'user'
    return $copy
}

# ---------------------------------------------------------------------------
# Windows side
# ---------------------------------------------------------------------------

function Get-OAiSelfTarget {
    # The running account as a target: its hive is loaded (HKEY_USERS\<SID>).
    # Revert needs it for "<Id>@<own SID>" copies another admin applied.
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    return [pscustomobject]@{
        Label     = $me.User.Value
        Sid       = $me.User.Value
        Name      = @($me.Name -split '\\')[-1]
        HivePath  = ''
        Mount     = $me.User.Value
        NeedsLoad = $false
    }
}

function Get-OAiUserTargets {
    $plKey = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
    $profiles = @(foreach ($k in @(Get-ChildItem -LiteralPath $plKey -ErrorAction SilentlyContinue)) {
            $sid = $k.PSChildName
            $path = ''
            try { $path = [Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty -LiteralPath $k.PSPath -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath) } catch {}
            if (-not $path) { continue }
            [pscustomobject]@{
                Sid     = $sid
                Path    = $path
                HasHive = (Test-Path -LiteralPath (Join-Path $path 'NTUSER.DAT') -PathType Leaf)
                Loaded  = (Test-Path -LiteralPath ('Registry::HKEY_USERS\' + $sid))
            }
        })
    $defaultPath = ''
    try { $defaultPath = [Environment]::ExpandEnvironmentVariables([string](Get-ItemProperty -LiteralPath $plKey -Name Default -ErrorAction Stop).Default) } catch {}
    $defaultHasHive = $false
    if ($defaultPath) { $defaultHasHive = Test-Path -LiteralPath (Join-Path $defaultPath 'NTUSER.DAT') -PathType Leaf }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return Select-OAiUserTargets -Profiles $profiles -CurrentSid $me -DefaultPath $defaultPath -DefaultHasHive $defaultHasHive
}

function _Invoke-RegExe {
    # reg.exe exit code. With $ErrorActionPreference = 'Stop', Windows
    # PowerShell 5.1 turns a native command's first stderr line into a
    # terminating error when stderr is redirected, so run it under
    # 'Continue' and judge it by its exit code only.
    param([string[]]$Arguments)
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $null = & reg.exe @Arguments 2>&1
        return [int]$LASTEXITCODE
    } catch {
        return 1
    } finally {
        $ErrorActionPreference = $old
    }
}

function Mount-OAiUserHive {
    # Returns $true when the target's hive is reachable under
    # HKEY_USERS\<Mount>; loads it first if needed (sets .Loaded).
    param([Parameter(Mandatory)] $Target)
    $Target | Add-Member -NotePropertyName Loaded -NotePropertyValue $false -Force
    try { return (_Mount-Hive $Target) } catch { return $false }
}

function _Mount-Hive {
    param($Target)
    $hku = 'Registry::HKEY_USERS\' + $Target.Mount
    if (-not $Target.NeedsLoad) { return (Test-Path -LiteralPath $hku) }
    if (Test-Path -LiteralPath $hku) {
        # Left over from an interrupted run: use it, and unload it at the end.
        $Target.Loaded = $true
        return $true
    }
    if ((_Invoke-RegExe @('load', ('HKU\' + $Target.Mount), $Target.HivePath)) -ne 0) { return $false }
    $Target.Loaded = $true
    return $true
}

function Dismount-OAiUserHive {
    # Unloads a hive this run loaded. A hive left loaded can make Windows
    # give that user a temporary profile at their next sign-in, so retry,
    # and report failure clearly ($false).
    param([Parameter(Mandatory)] $Target)
    if (-not $Target.Loaded) { return $true }
    try { return (_Dismount-Hive $Target) } catch { return $false }
}

function _Dismount-Hive {
    param($Target)
    for ($i = 0; $i -lt 4; $i++) {
        # Registry handles held by .NET / the provider keep the hive busy.
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        if ((_Invoke-RegExe @('unload', ('HKU\' + $Target.Mount))) -eq 0) { $Target.Loaded = $false; return $true }
        Start-Sleep -Milliseconds 750
    }
    return $false
}

Export-ModuleMember -Function Split-OAiTargetId, Select-OAiUserTargets, New-OAiTargetPolicy, Get-OAiUserTargets, Get-OAiSelfTarget, Mount-OAiUserHive, Dismount-OAiUserHive
