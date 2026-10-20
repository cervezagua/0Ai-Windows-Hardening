#
# Pester tests for snapshot fallback across older backups (OAi.BackupHistory.psm1).
#

Describe '0AI older-backup snapshot fallback' {

    BeforeAll {
        $RepoRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path (Join-Path (Join-Path $RepoRoot 'src') 'module') 'OAi.BackupHistory.psm1') -Force

        function OldRun([string]$Name, $Results, [string[]]$Files, [string[]]$Reverted = @()) {
            [pscustomobject]@{ Name = $Name; Dir = "D:\b\$Name"; Results = $Results; Files = $Files; RevertedIds = $Reverted }
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
}
