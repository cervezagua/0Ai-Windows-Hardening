#
# Pester tests for Get-OAiNotApplicableReason (OAi.Engine.psm1): why a policy
# cannot apply on this PC. Windows lookups are mocked, so this runs anywhere.
#

Describe '0AI not-applicable reasons' {

    BeforeAll {
        $RepoRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path (Join-Path (Join-Path $RepoRoot 'src') 'module') 'OAi.Engine.psm1') -Force
    }

    Context 'services' {
        It 'a Service policy whose service is not installed' {
            Mock -ModuleName OAi.Engine _Service-Installed { $false }
            Get-OAiNotApplicableReason -Policy @{ Id = 'S'; Kind = 'Service'; Name = 'IsoEnvBroker' } |
                Should -Be 'service IsoEnvBroker is not installed on this PC'
        }
        It 'a Registry policy that requires a missing service' {
            Mock -ModuleName OAi.Engine _Service-Installed { $false }
            Get-OAiNotApplicableReason -Policy @{ Id = 'R'; Kind = 'Registry'; RequiresService = 'IsoEnvBroker' } |
                Should -Match 'IsoEnvBroker is not installed'
        }
        It 'nothing when the service exists' {
            Mock -ModuleName OAi.Engine _Service-Installed { $true }
            Get-OAiNotApplicableReason -Policy @{ Id = 'R'; Kind = 'Registry'; RequiresService = 'IsoEnvBroker' } | Should -Be ''
        }
    }

    Context 'UCPD-protected values' {
        BeforeAll {
            $script:Dsh = @{ Id = 'D'; Kind = 'Registry'; Hive = 'HKLM'; Key = 'SOFTWARE\Policies\Microsoft\Dsh'; Value = 'AllowNewsAndInterests'; Data = 0; UcpdProtected = $true; GroupPolicy = 'Widgets > Allow widgets = Disabled' }
        }
        It 'blocked while UCPD runs and the value is not set; names the Group Policy route' {
            Mock -ModuleName OAi.Engine _Test-UcpdActive { $true }
            Mock -ModuleName OAi.Engine Get-ItemProperty { throw 'not set' }
            $r = Get-OAiNotApplicableReason -Policy $Dsh
            $r | Should -Match 'UCPD'
            $r | Should -Match 'Allow widgets'
        }
        It 'nothing once the value is already set (e.g. by Group Policy)' {
            Mock -ModuleName OAi.Engine _Test-UcpdActive { $true }
            Mock -ModuleName OAi.Engine Get-ItemProperty { [pscustomobject]@{ AllowNewsAndInterests = 0 } }
            Get-OAiNotApplicableReason -Policy $Dsh | Should -Be ''
        }
        It 'nothing when UCPD is not running' {
            Mock -ModuleName OAi.Engine _Test-UcpdActive { $false }
            Get-OAiNotApplicableReason -Policy $Dsh | Should -Be ''
        }
        It 'unflagged values are never reported' {
            Mock -ModuleName OAi.Engine _Test-UcpdActive { $true }
            $p = $Dsh.Clone(); $p.Remove('UcpdProtected')
            Get-OAiNotApplicableReason -Policy $p | Should -Be ''
        }
    }

    Context 'build gates' {
        It 'below MinBuild' {
            Mock -ModuleName OAi.Engine _Get-CurrentBuild { 26100 }
            Get-OAiNotApplicableReason -Policy @{ Id = 'B'; Kind = 'Registry'; MinBuild = 26200 } | Should -Match 'needs Windows build 26200 or later; this PC is 26100'
        }
        It 'above MaxBuild' {
            Mock -ModuleName OAi.Engine _Get-CurrentBuild { 26300 }
            Get-OAiNotApplicableReason -Policy @{ Id = 'B'; Kind = 'Registry'; MaxBuild = 26200 } | Should -Match 'up to Windows build 26200'
        }
        It 'inside the range, or build unknown' {
            Mock -ModuleName OAi.Engine _Get-CurrentBuild { 26200 }
            Get-OAiNotApplicableReason -Policy @{ Id = 'B'; Kind = 'Registry'; MinBuild = 26100; MaxBuild = 26300 } | Should -Be ''
            Mock -ModuleName OAi.Engine _Get-CurrentBuild { 0 }
            Get-OAiNotApplicableReason -Policy @{ Id = 'B'; Kind = 'Registry'; MinBuild = 99999 } | Should -Be ''
        }
    }
}
