#
# Pester tests for the restore-point outcome decision (OAi.System.psm1).
#

Describe '0AI restore point outcome' {

    BeforeAll {
        $RepoRoot = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path (Join-Path (Join-Path $RepoRoot 'src') 'module') 'OAi.System.psm1') -Force
    }

    It 'created when a newer sequence number appears' {
        (Get-OAiRestorePointResult -Before @(5, 7) -After @(5, 7, 8)).Status | Should -Be 'created'
    }
    It 'created on a PC with no earlier points' {
        (Get-OAiRestorePointResult -Before @() -After @(1)).Status | Should -Be 'created'
    }
    It 'skipped (24-hour limit) when nothing new appears but points exist, naming the last one' {
        $r = Get-OAiRestorePointResult -Before @(5, 7) -After @(5, 7) -Latest '2026-10-21 08:15'
        $r.Status | Should -Be 'skipped'
        $r.Message | Should -Match '2026-10-21 08:15'
    }
    It 'unavailable with the error when the request threw' {
        $r = Get-OAiRestorePointResult -Before @(5) -After @(5) -ErrorText 'System Restore is disabled'
        $r.Status | Should -Be 'unavailable'
        $r.Message | Should -Match 'disabled'
    }
    It 'unavailable when there are no points at all and none was made' {
        (Get-OAiRestorePointResult -Before @() -After @()).Message | Should -Match 'turned off'
    }
    It 'a newer point wins even if an error was reported' {
        (Get-OAiRestorePointResult -Before @(1) -After @(1, 2) -ErrorText 'x').Status | Should -Be 'created'
    }
}
