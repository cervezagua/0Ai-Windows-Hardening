#
# Pester tests for -AllUsers targeting (OAi.Users.psm1): which profiles are
# covered, and how a per-user copy of an HKCU policy is built.
#

Describe '0AI per-user targets' {

    BeforeAll {
        $RepoRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path (Join-Path (Join-Path $RepoRoot 'src') 'module') 'OAi.Users.psm1') -Force
        $script:Me    = 'S-1-5-21-111-222-333-1001'
        $script:Other = 'S-1-5-21-111-222-333-1002'
        function Prof([string]$Sid, [string]$Path, [bool]$HasHive = $true, [bool]$Loaded = $false) {
            [pscustomobject]@{ Sid = $Sid; Path = $Path; HasHive = $HasHive; Loaded = $Loaded }
        }
    }

    Context 'Select-OAiUserTargets' {
        It 'keeps other real accounts, drops the running one and service accounts' {
            $p = @((Prof $Me 'C:\Users\me'), (Prof $Other 'C:\Users\anna'), (Prof 'S-1-5-18' 'C:\WINDOWS\system32\config\systemprofile'), (Prof 'S-1-5-19' 'C:\x'), (Prof 'S-1-5-20' 'C:\y'))
            $t = @(Select-OAiUserTargets -Profiles $p -CurrentSid $Me)
            $t.Count | Should -Be 1
            $t[0].Label | Should -Be $Other
            $t[0].Name | Should -Be 'anna'
            $t[0].HivePath | Should -Be 'C:\Users\anna\NTUSER.DAT'
        }
        It 'an offline user is loaded under 0AI_<SID>; a signed-in user uses HKU\<SID>' {
            $t = @(Select-OAiUserTargets -Profiles @((Prof $Other 'C:\Users\anna')) -CurrentSid $Me)
            $t[0].Mount | Should -Be ('0AI_' + $Other)
            $t[0].NeedsLoad | Should -BeTrue
            $t = @(Select-OAiUserTargets -Profiles @((Prof $Other 'C:\Users\anna' $true $true)) -CurrentSid $Me)
            $t[0].Mount | Should -Be $Other
            $t[0].NeedsLoad | Should -BeFalse
        }
        It 'skips a profile with no NTUSER.DAT that is not loaded' {
            @(Select-OAiUserTargets -Profiles @((Prof $Other 'C:\Users\gone' $false $false)) -CurrentSid $Me).Count | Should -Be 0
        }
        It 'adds the Default profile when its hive exists' {
            $t = @(Select-OAiUserTargets -Profiles @() -CurrentSid $Me -DefaultPath 'C:\Users\Default\' -DefaultHasHive $true)
            $t[0].Label | Should -Be 'Default'
            $t[0].Mount | Should -Be '0AI_Default'
            $t[0].HivePath | Should -Be 'C:\Users\Default\NTUSER.DAT'
            @(Select-OAiUserTargets -Profiles @() -CurrentSid $Me -DefaultPath 'C:\Users\Default' -DefaultHasHive $false).Count | Should -Be 0
        }
    }

    Context 'New-OAiTargetPolicy' {
        BeforeAll {
            $script:T = [pscustomobject]@{ Label = $Other; Name = 'anna'; Mount = '0AI_' + $Other }
            $script:Hkcu = @{ Id = 'PRIV.X.HKCU'; Kind = 'Registry'; Category = 'PRIV'; Group = 'reg-safe'; Hive = 'HKCU'; Key = 'Software\Policies\Microsoft\X'; Value = 'V'; Type = 'DWord'; Data = 1 }
        }
        It 'copies an HKCU registry policy to the target hive' {
            $c = New-OAiTargetPolicy -Policy $Hkcu -Target $T
            $c.Id | Should -Be ('PRIV.X.HKCU@' + $Other)
            $c.Hive | Should -Be 'HKU'
            $c.Key | Should -Be ('0AI_' + $Other + '\Software\Policies\Microsoft\X')
            $c.Value | Should -Be 'V'
            $c.Data | Should -Be 1
            $c.Group | Should -Be 'user'
            $c.TargetLabel | Should -Be $Other
        }
        It 'snapshots name the user and the plain key, not the mount' {
            $c = New-OAiTargetPolicy -Policy $Hkcu -Target $T
            $c.SnapshotHive | Should -Be ('HKCU@' + $Other)
            $c.SnapshotKey | Should -Be 'Software\Policies\Microsoft\X'
        }
        It 'does not change the original record' {
            $null = New-OAiTargetPolicy -Policy $Hkcu -Target $T
            $Hkcu.Id | Should -Be 'PRIV.X.HKCU'
            $Hkcu.Hive | Should -Be 'HKCU'
        }
        It 'ignores HKLM and non-registry policies' {
            New-OAiTargetPolicy -Policy @{ Id = 'A'; Kind = 'Registry'; Hive = 'HKLM'; Key = 'K'; Value = 'V' } -Target $T | Should -BeNullOrEmpty
            New-OAiTargetPolicy -Policy @{ Id = 'S'; Kind = 'Service'; Name = 'X' } -Target $T | Should -BeNullOrEmpty
        }
    }

    Context 'Split-OAiTargetId' {
        It 'splits at the last @' {
            $s = Split-OAiTargetId -Id ('PRIV.X.HKCU@' + $Other)
            $s.BaseId | Should -Be 'PRIV.X.HKCU'
            $s.Label | Should -Be $Other
            (Split-OAiTargetId -Id 'PRIV.X.HKCU@Default').Label | Should -Be 'Default'
        }
        It 'a plain Id has no label' {
            $s = Split-OAiTargetId -Id 'PRIV.X.HKCU'
            $s.BaseId | Should -Be 'PRIV.X.HKCU'
            $s.Label | Should -Be ''
        }
    }
}
