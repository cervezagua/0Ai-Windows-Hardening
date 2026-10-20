#
# 0AI - module wiring tests (Pester 5 / 6). Static checks, no Windows needed.
#

Describe '0AI module imports' {

    BeforeAll {
        $RepoRoot  = Split-Path -Parent $PSScriptRoot
        $ModuleDir = Join-Path (Join-Path $RepoRoot 'src') 'module'
    }

    It 'no module force-imports another module into its own scope' {
        # Import-Module -Force inside a module unloads the copy the calling
        # script imported (v2.14.3: Get-OAiVersion vanished mid-Apply).
        # OAi.Runner.psm1 is exempt: it imports the engine inside ThreadJob
        # runspaces, which share nothing with the caller.
        $bad = @(Get-ChildItem -LiteralPath $ModuleDir -Filter '*.psm1' |
            Where-Object { $_.Name -ne 'OAi.Runner.psm1' } |
            ForEach-Object {
                $f = $_
                $tokens = $null; $errs = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs)
                $ast.FindAll({ param($n)
                        $n -is [System.Management.Automation.Language.CommandAst] -and
                        $n.GetCommandName() -eq 'Import-Module' -and
                        @($n.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Force' }).Count -gt 0
                    }, $true) | ForEach-Object { '{0}:{1}' -f $f.Name, $_.Extent.StartLineNumber }
            })
        $bad.Count | Should -Be 0 -Because "force-imports: $($bad -join ', ')"
    }
}
