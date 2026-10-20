#
# Pester tests for the admin-only backup check (OAi.BackupAcl.psm1).
#
# Only the decision function is tested here: it works on plain data, so it
# runs anywhere. Reading real ACLs needs Windows.
#

Describe '0AI backup folder ACL check' {

    BeforeAll {
        $RepoRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path (Join-Path (Join-Path $RepoRoot 'src') 'module') 'OAi.BackupAcl.psm1') -Force

        $script:SY   = 'S-1-5-18'
        $script:BA   = 'S-1-5-32-544'
        $script:TI   = 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
        $script:User = 'S-1-5-21-1000-2000-3000-1001'
        $script:BU   = 'S-1-5-32-545'

        function Ace([string]$Sid, [int64]$Mask, [bool]$Allow = $true, [bool]$InheritOnly = $false) {
            [pscustomobject]@{ Sid = $Sid; Mask = $Mask; Allow = $Allow; InheritOnly = $InheritOnly }
        }
        # FILE_ALL_ACCESS and read & execute, as New-OAiLockedDir writes them
        $script:FA = 0x1F01FF
        $script:RX = 0x1200A9
        # What a folder ABOVE a backup must not grant (DeleteChild, DELETE,
        # WRITE_DAC, WRITE_OWNER, MAXIMUM_ALLOWED, GENERIC_ALL)
        $script:Replace = 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x02000000 -bor 0x10000000
        # %ProgramData%: Users may create files and folders and write attributes
        $script:UsersCreate = 0x2 -bor 0x4 -bor 0x10 -bor 0x100
    }

    It 'accepts the ACL New-OAiLockedDir writes' {
        $r = Test-OAiAdminOnlyAcl -Owner $BA -Aces @((Ace $SY $FA), (Ace $BA $FA), (Ace $User $RX))
        $r.Ok | Should -BeTrue
    }

    It 'accepts TrustedInstaller and SYSTEM as owner' {
        (Test-OAiAdminOnlyAcl -Owner $TI -Aces @((Ace $BA $FA))).Ok | Should -BeTrue
        (Test-OAiAdminOnlyAcl -Owner $SY -Aces @((Ace $BA $FA))).Ok | Should -BeTrue
    }

    It 'rejects a folder owned by the user' {
        $r = Test-OAiAdminOnlyAcl -Owner $User -Aces @((Ace $BA $FA))
        $r.Ok | Should -BeFalse
        $r.Reason | Should -Match 'owned by'
    }

    It 'rejects a missing DACL' {
        (Test-OAiAdminOnlyAcl -Owner $BA -Aces $null).Ok | Should -BeFalse
    }

    It 'rejects a default profile ACL (user has full control)' {
        (Test-OAiAdminOnlyAcl -Owner $BA -Aces @((Ace $SY $FA), (Ace $BA $FA), (Ace $User $FA))).Ok | Should -BeFalse
    }

    It 'rejects each individual write right for an untrusted SID' {
        foreach ($bit in @(0x2, 0x4, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x02000000, 0x10000000, 0x40000000)) {
            (Test-OAiAdminOnlyAcl -Owner $BA -Aces @((Ace $BU ($RX -bor $bit)))).Ok | Should -BeFalse -Because ('mask bit 0x{0:X}' -f $bit)
        }
    }

    It 'rejects an unknown ACE (mask -1)' {
        (Test-OAiAdminOnlyAcl -Owner $BA -Aces @((Ace 'unknown' -1))).Ok | Should -BeFalse
    }

    It 'ignores deny entries and inherit-only entries' {
        $aces = @((Ace $BA $FA), (Ace $User $FA $false), (Ace $BU $FA $true $true))
        (Test-OAiAdminOnlyAcl -Owner $BA -Aces $aces).Ok | Should -BeTrue
    }

    It 'accepts read-only access for anyone' {
        (Test-OAiAdminOnlyAcl -Owner $BA -Aces @((Ace $BA $FA), (Ace $BU $RX), (Ace 'S-1-1-0' 0x120089))).Ok | Should -BeTrue
    }

    Context 'folders above the backup (replace rights only)' {
        It 'accepts %ProgramData% (Users may create, not delete or rename)' {
            $aces = @((Ace $SY $FA), (Ace $BA $FA), (Ace $BU $RX), (Ace $BU $UsersCreate), (Ace 'S-1-3-0' $FA $true $true))
            (Test-OAiAdminOnlyAcl -Owner $SY -Aces $aces -Mask $Replace).Ok | Should -BeTrue
        }
        It 'rejects a user profile (the user has full control)' {
            $aces = @((Ace $SY $FA), (Ace $BA $FA), (Ace $User $FA))
            (Test-OAiAdminOnlyAcl -Owner $SY -Aces $aces -Mask $Replace).Ok | Should -BeFalse
        }
        It 'rejects DeleteChild alone' {
            (Test-OAiAdminOnlyAcl -Owner $SY -Aces @((Ace $BU ($RX -bor 0x40))) -Mask $Replace).Ok | Should -BeFalse
        }
        It 'rejects a folder the user owns' {
            (Test-OAiAdminOnlyAcl -Owner $User -Aces @((Ace $BA $FA)) -Mask $Replace).Ok | Should -BeFalse
        }
    }

    Context 'OWNER RIGHTS (files a policy makes the user own)' {
        It 'accepts a user-owned file when OWNER RIGHTS is read-only' {
            $aces = @((Ace $SY $FA), (Ace $BA $FA), (Ace 'S-1-3-4' $RX), (Ace $User $RX))
            (Test-OAiAdminOnlyAcl -Owner $User -Aces $aces).Ok | Should -BeTrue
        }
        It 'rejects OWNER RIGHTS that grants write' {
            $aces = @((Ace $BA $FA), (Ace 'S-1-3-4' $FA))
            (Test-OAiAdminOnlyAcl -Owner $User -Aces $aces).Ok | Should -BeFalse
        }
        It 'ignores an inherit-only OWNER RIGHTS entry' {
            $aces = @((Ace $BA $FA), (Ace 'S-1-3-4' $RX $true $true))
            (Test-OAiAdminOnlyAcl -Owner $User -Aces $aces).Ok | Should -BeFalse
        }
        It 'still rejects write granted to the owner by SID' {
            $aces = @((Ace $BA $FA), (Ace 'S-1-3-4' $RX), (Ace $User $FA))
            (Test-OAiAdminOnlyAcl -Owner $User -Aces $aces).Ok | Should -BeFalse
        }
    }
}
