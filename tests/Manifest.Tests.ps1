#
# 0AI v2.3 - Manifest schema tests (Pester v5)
#
# Runs on Windows PowerShell 5.1 or PowerShell 7+, including pwsh on Linux.
# Tests are pure data validation; no Windows cmdlets are invoked.
#
# If Pester is not installed, importing this file still parses cleanly.
#

$ValidCategories = @('AI','PRIV','HARD','DEBLOAT','AUDIT')
$ValidGroups     = @('reg-safe','sc-safe','appx','defender','mitigation','folder','report')
$ValidKinds      = @('Registry','Service','AppxRemove','DefenderPref','DefenderAsr','Mitigation','FolderPurge','Report')

$ManifestRoot = Join-Path (Split-Path -Parent $PSCommandPath) '..\src\manifest'
$ManifestRoot = (Resolve-Path $ManifestRoot).Path

function _Collect-Hashtables {
    param($Val, [System.Collections.Generic.List[object]]$Acc)
    if ($null -eq $Val) { return }
    if ($Val -is [System.Collections.IDictionary]) { [void]$Acc.Add($Val); return }
    if ($Val -is [System.Collections.IEnumerable] -and $Val -isnot [string]) {
        foreach ($v in $Val) { _Collect-Hashtables -Val $v -Acc $Acc }
        return
    }
}
function _Load-PolicyManifest {
    # Import-PowerShellDataFile rejects top-level arrays. Parse via AST + SafeGetValue.
    param([string]$Path)
    $tokens = $null
    $errs   = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
    if ($errs -and @($errs).Count -gt 0) {
        throw ('parse error in {0}: {1}' -f (Split-Path -Leaf $Path), @($errs)[0].Message)
    }
    $stmts = @($ast.EndBlock.Statements)
    if ($stmts.Count -eq 0) { return ,@() }
    $val = $stmts[0].PipelineElements[0].Expression.SafeGetValue()
    $acc = New-Object System.Collections.Generic.List[object]
    _Collect-Hashtables -Val $val -Acc $acc
    return ,$acc.ToArray()
}

function Get-AllPolicies {
    $out = New-Object System.Collections.Generic.List[object]
    Get-ChildItem -Path $ManifestRoot -Filter '*.psd1' | ForEach-Object {
        $file = $_
        $data = _Load-PolicyManifest -Path $file.FullName
        foreach ($p in $data) {
            if ($p) {
                $p['_SourceFile'] = $file.Name
                $out.Add($p)
            }
        }
    }
    return $out.ToArray()
}

Describe '0AI v2.3 manifest schema' {

    BeforeAll {
        $script:Policies = Get-AllPolicies
    }

    It 'loads at least one policy file' {
        (Get-ChildItem -Path $ManifestRoot -Filter '*.psd1').Count | Should -BeGreaterThan 0
    }

    It 'loads at least one policy record' {
        $script:Policies.Count | Should -BeGreaterThan 0
    }

    Context 'per-policy' {
        It 'every policy has a non-empty Id' {
            foreach ($p in $script:Policies) {
                $p.Id | Should -Not -BeNullOrEmpty
            }
        }
        It 'every Id is unique' {
            $ids = $script:Policies | ForEach-Object { $_.Id }
            ($ids | Group-Object | Where-Object { $_.Count -gt 1 }).Count | Should -Be 0
        }
        It 'every Category is valid' {
            foreach ($p in $script:Policies) {
                $ValidCategories -contains $p.Category | Should -BeTrue -Because "policy $($p.Id) has Category=$($p.Category)"
            }
        }
        It 'every Group is valid' {
            foreach ($p in $script:Policies) {
                $ValidGroups -contains $p.Group | Should -BeTrue -Because "policy $($p.Id) has Group=$($p.Group)"
            }
        }
        It 'every Kind is valid' {
            foreach ($p in $script:Policies) {
                $ValidKinds -contains $p.Kind | Should -BeTrue -Because "policy $($p.Id) has Kind=$($p.Kind)"
            }
        }
        It 'every policy has a Description' {
            foreach ($p in $script:Policies) {
                $p.Description | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context 'Kind=Registry' {
        It 'has Hive, Key, Value, Type, Data' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'Registry' }) {
                $p.Hive  | Should -Not -BeNullOrEmpty
                $p.Key   | Should -Not -BeNullOrEmpty
                $p.Value | Should -Not -BeNullOrEmpty
                $p.Type  | Should -Not -BeNullOrEmpty
                $p.ContainsKey('Data') | Should -BeTrue
            }
        }
    }

    Context 'Kind=Service' {
        It 'has Name' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'Service' }) {
                $p.Name | Should -Not -BeNullOrEmpty
            }
        }
    }

    Context 'Kind=AppxRemove' {
        It 'has NamePattern' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'AppxRemove' }) {
                $p.NamePattern | Should -Not -BeNullOrEmpty
            }
        }
        It 'lives in Group=appx' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'AppxRemove' }) {
                $p.Group | Should -Be 'appx' -Because "policy $($p.Id)"
            }
        }
    }

    Context 'Kind=DefenderAsr' {
        It 'has GUID-formatted RuleId' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'DefenderAsr' }) {
                $p.RuleId | Should -Match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
            }
        }
        It 'lives in Group=defender' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'DefenderAsr' }) {
                $p.Group | Should -Be 'defender'
            }
        }
    }

    Context 'Kind=DefenderPref' {
        It 'lives in Group=defender' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'DefenderPref' }) {
                $p.Group | Should -Be 'defender'
            }
        }
    }

    Context 'Kind=Mitigation' {
        It 'lives in Group=mitigation' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'Mitigation' }) {
                $p.Group | Should -Be 'mitigation'
            }
        }
    }
}
