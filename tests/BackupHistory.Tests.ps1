#
# Pester tests for snapshot fallback across older backups (OAi.BackupHistory.psm1).
#

Describe '0AI older-backup snapshot fallback' {

    BeforeAll {
        $RepoRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path (Join-Path (Join-Path $RepoRoot 'src') 'module') 'OAi.BackupHistory.psm1') -Force

        function OldRun([string]$Name, $Results, [string[]]$Files, [string[]]$Reverted = @(), [bool]$Trusted = $true) {
            [pscustomobject]@{ Name = $Name; Dir = "D:\b\$Name"; Results = $Results; Files = $Files; RevertedIds = $Reverted; Trusted = $Trusted }
        }
        function Res([string]$Id, [string]$Bf) { [pscustomobject]@{ Id = $Id; BackupFile = $Bf } }
    }

    It 'uses the newest older run that recorded a snapshot' {
        $older = @(
            (OldRun '2026-10-15_100000' @((Res 'A' ''))                              @()),
            (OldRun '2026-09-01_100000' @((Res 'A' 'C:\old\path\reg_A.json'))        @('reg_A.json')),
            (OldRun '2026-08-01_100000' @((Res 'A' 'reg_A.json'))                    @('reg_A.json'))
        )
        $m = Select-OAiFallbackSnapshots -Ids @('A') -Older $older
        $m['A'].Name | Should -Be '2026-09-01_100000'
        $m['A'].BackupFile | Should -Be 'reg_A.json'
        $m['A'].Dir | Should -Be 'D:\b\2026-09-01_100000'
    }

    It 'ignores a recorded file that is not in the folder' {
        $older = @(
            (OldRun 'b' @((Res 'A' 'reg_A.json')) @('other.json')),
            (OldRun 'a' @((Res 'A' 'reg_A.json')) @('reg_A.json'))
        )
        (Select-OAiFallbackSnapshots -Ids @('A') -Older $older)['A'].Name | Should -Be 'a'
    }

    It 'stops at a run whose revert already restored the Id' {
        $older = @(
            (OldRun 'c' @((Res 'A' '')) @() @('A')),
            (OldRun 'b' @((Res 'A' 'reg_A.json')) @('reg_A.json'))
        )
        (Select-OAiFallbackSnapshots -Ids @('A') -Older $older).ContainsKey('A') | Should -BeFalse
    }

    It 'searches past a revert that did not restore the Id' {
        $older = @(
            (OldRun 'c' @((Res 'S' '')) @() @('OTHER')),
            (OldRun 'b' @((Res 'S' 'service_S.json')) @('service_S.json'))
        )
        (Select-OAiFallbackSnapshots -Ids @('S') -Older $older)['S'].Name | Should -Be 'b'
    }

    It 'a reverted run that also holds the snapshot is not used' {
        $older = @((OldRun 'b' @((Res 'A' 'reg_A.json')) @('reg_A.json') @('A')))
        (Select-OAiFallbackSnapshots -Ids @('A') -Older $older).Count | Should -Be 0
    }

    It 'handles several Ids independently and returns nothing for unknown ones' {
        $older = @(
            (OldRun 'b' @((Res 'A' 'reg_A.json'), (Res 'B' '')) @('reg_A.json')),
            (OldRun 'a' @((Res 'B' 'reg_B.json')) @('reg_B.json'))
        )
        $m = Select-OAiFallbackSnapshots -Ids @('A', 'B', 'C') -Older $older
        $m['A'].Name | Should -Be 'b'
        $m['B'].Name | Should -Be 'a'
        $m.ContainsKey('C') | Should -BeFalse
    }

    It 'parses ok lines from revert.log only' {
        $log = "[+] 0AI v2.14.3 Revert starting`r`n[ok     ] HARD.Defender.PUAProtection  restored PUAProtection=2`r`n[warn   ] PRIV.Service.DiagTrack  no service snapshot`r`n[ok     ] AI.X  removed y`n[skipped] AUDIT.OS.Sku  Report is read-only"
        $ids = @(Get-OAiRevertedIds -LogText $log)
        $ids | Should -Be @('HARD.Defender.PUAProtection', 'AI.X')
    }

    It 'returns nothing for an empty log' {
        @(Get-OAiRevertedIds -LogText '').Count | Should -Be 0
    }

    Context 'trust' {
        It 'an untrusted run cannot stop a search' {
            $older = @(
                [pscustomobject]@{ Name = 'c'; Dir = 'D:\c'; Results = @(); Files = @(); RevertedIds = @('A'); Trusted = $false },
                (OldRun 'b' @((Res 'A' 'reg_A.json')) @('reg_A.json'))
            )
            (Select-OAiFallbackSnapshots -Ids @('A') -Older $older)['A'].Name | Should -Be 'b'
        }
        It 'matches Ids and file names case-insensitively, with / separators' {
            $older = @((OldRun 'b' @((Res 'ai.x' 'C:/x/REG_A.json')) @('reg_a.json')))
            (Select-OAiFallbackSnapshots -Ids @('AI.X') -Older $older)['AI.X'].BackupFile | Should -Be 'REG_A.json'
        }
        It 'tolerates a run with no results or files' {
            $older = @((OldRun 'b' $null $null))
            (Select-OAiFallbackSnapshots -Ids @('A') -Older $older).Count | Should -Be 0
        }
    }

    Context 'which folders count as older' {
        BeforeAll {
            function F([string]$Name, [string]$Root = 'C:\P') { [pscustomobject]@{ Name = $Name; FullName = "$Root\$Name" } }
        }
        It 'cut-off is the selected timestamp' {
            Get-OAiCutoffName -SelectedName '2026-10-20_200839' | Should -Be '2026-10-20_200839'
        }
        It 'a working copy is measured by the folder it came from' {
            Get-OAiCutoffName -SelectedName 'imported-2026-10-21_090000' -SourcePath "C:\Users\u\0AI_Backups\2026-09-01_100000\`r`n" | Should -Be '2026-09-01_100000'
        }
        It 'no cut-off for other names' {
            Get-OAiCutoffName -SelectedName 'my-backup' | Should -BeNullOrEmpty
            Get-OAiCutoffName -SelectedName 'imported-2026-10-21_090000' | Should -BeNullOrEmpty
        }
        It 'keeps only strictly older timestamp folders, newest first, across roots' {
            $folders = @((F '2026-08-01_100000' 'C:\U'), (F '2026-10-20_200839'), (F '2026-10-25_080000'), (F 'imported-2026-01-01_000000'), (F 'notes'), (F '2026-09-01_100000' 'C:\U'))
            $r = @(Select-OAiOlderFolders -Folders $folders -Cutoff '2026-10-20_200839')
            ($r | ForEach-Object { $_.Name }) | Should -Be @('2026-09-01_100000', '2026-08-01_100000')
        }
        It 'excludes the original of a working copy, ignoring case and trailing separators' {
            $folders = @((F '2026-09-01_100000' 'C:\U'), (F '2026-08-01_100000' 'C:\U'))
            $r = @(Select-OAiOlderFolders -Folders $folders -Cutoff '2026-09-02_000000' -Exclude @('c:\u\2026-09-01_100000\'))
            ($r | ForEach-Object { $_.Name }) | Should -Be @('2026-08-01_100000')
        }
        It 'returns nothing without a cut-off' {
            @(Select-OAiOlderFolders -Folders @((F '2026-08-01_100000')) -Cutoff $null).Count | Should -Be 0
        }
    }
}
