#
# 0AI - Manifest schema tests (Pester 5 / 6)
#
# Runs on Windows PowerShell 5.1 or PowerShell 7+, including pwsh on Linux.
# Tests are pure data validation; no Windows cmdlets are invoked.
#
# Everything the tests use (helpers, valid-value lists, paths) lives in
# BeforeAll: Pester 5+ runs top-level script code only during Discovery, so
# anything defined there is gone by the time the It blocks run.
#
# The loader below is deliberately independent of src/module: the tests are
# an oracle for the data, not a re-run of the project's own parser.
#

Describe '0AI manifest schema' {

    BeforeAll {
        $ValidCategories  = @('AI','PRIV','HARD','DEBLOAT','AUDIT')
        $ValidGroups      = @('reg-safe','sc-safe','appx','defender','mitigation','folder','report')
        $ValidKinds       = @('Registry','Service','AppxRemove','DefenderPref','DefenderAsr','Mitigation','FolderPurge','Report')
        $ValidConfidence  = @('Documented','BestEffort','Community')
        $ValidHives       = @('HKLM','HKCU')
        $ValidRegTypes    = @('DWord','QWord','String','ExpandString','MultiString','Binary')

        $RepoRoot     = Split-Path -Parent (Split-Path -Parent $PSCommandPath)
        $ManifestRoot = Join-Path (Join-Path $RepoRoot 'src') 'manifest'
        $RetiredPath  = Join-Path (Join-Path (Join-Path $RepoRoot 'src') 'retired') 'retired.psd1'

        function _Collect-Hashtables {
            param($Val, [System.Collections.Generic.List[object]]$Acc)
            if ($null -eq $Val) { return }
            if ($Val -is [System.Collections.IDictionary]) { [void]$Acc.Add($Val); return }
            if ($Val -is [System.Collections.IEnumerable] -and $Val -isnot [string]) {
                foreach ($v in $Val) { _Collect-Hashtables -Val $v -Acc $Acc }
                return
            }
        }

        function _Parse-DataFile {
            # Import-PowerShellDataFile mishandles top-level arrays on PS 5.1.
            # Parse via AST + SafeGetValue. Returns @{ Errors; Records }.
            param([string]$Path)
            $tokens = $null
            $errs   = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
            $errList = @()
            if ($errs) { $errList = @($errs | ForEach-Object { $_.Message }) }
            $acc = New-Object System.Collections.Generic.List[object]
            if ($errList.Count -eq 0) {
                $stmts = @($ast.EndBlock.Statements)
                if ($stmts.Count -gt 0) {
                    $val = $stmts[0].PipelineElements[0].Expression.SafeGetValue()
                    _Collect-Hashtables -Val $val -Acc $acc
                }
            }
            return @{ Errors = $errList; Records = $acc.ToArray() }
        }

        function _Load-PolicyManifest {
            param([string]$Path)
            $r = _Parse-DataFile -Path $Path
            if ($r.Errors.Count -gt 0) {
                throw ('parse error in {0}: {1}' -f (Split-Path -Leaf $Path), $r.Errors[0])
            }
            return ,$r.Records
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

        function ConvertTo-IdList {
            # ReplacedBy may come back as $null, a scalar string, or object[]
            # (SafeGetValue returns @() and @('x') both as object[]).
            param($Val)
            if ($null -eq $Val) { return ,@() }
            if ($Val -is [string]) { return ,@($Val) }
            return ,@($Val)
        }

        $script:Policies = Get-AllPolicies
        $script:LiveIds  = @($script:Policies | ForEach-Object { [string]$_.Id })
        $script:Registry = @($script:Policies | Where-Object { $_.Kind -eq 'Registry' })
    }

    It 'loads at least one policy file' {
        @(Get-ChildItem -Path $ManifestRoot -Filter '*.psd1').Count | Should -BeGreaterThan 0
    }

    It 'loads at least one policy record' {
        $script:Policies.Count | Should -BeGreaterThan 0
    }

    Context 'per-policy' {
        It 'every policy has a non-empty Id' {
            foreach ($p in $script:Policies) {
                $p.Id | Should -Not -BeNullOrEmpty -Because "a policy in $($p._SourceFile) has no Id"
            }
        }
        It 'every Id is unique' {
            $dupes = @($script:LiveIds | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
            $dupes.Count | Should -Be 0 -Because "duplicate Ids: $($dupes -join ', ')"
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
                $p.Description | Should -Not -BeNullOrEmpty -Because "policy $($p.Id)"
            }
        }
        It 'every policy has a valid Confidence label' {
            $bad = @($script:Policies | Where-Object { $ValidConfidence -notcontains $_.Confidence } |
                ForEach-Object { '{0} (Confidence={1})' -f $_.Id, $_.Confidence })
            $bad.Count | Should -Be 0 -Because "Confidence must be one of $($ValidConfidence -join '/'); offenders: $($bad -join ', ')"
        }
        It 'every policy has an https DocUrl (Community may leave it empty: no source found)' {
            $bad = @($script:Policies | Where-Object {
                    $url = $_.DocUrl
                    $isHttps = ($url -is [string] -and $url.StartsWith('https://'))
                    $emptyOk = ($_.Confidence -eq 'Community' -and $url -is [string] -and $url -eq '')
                    -not ($isHttps -or $emptyOk)
                } | ForEach-Object { '{0} (Confidence={1}, DocUrl={2})' -f $_.Id, $_.Confidence, $_.DocUrl })
            $bad.Count | Should -Be 0 -Because "Documented/BestEffort need a primary-source https DocUrl; offenders: $($bad -join ', ')"
        }
    }

    Context 'Kind=Registry' {
        It 'has Hive, Key, Value, Type, Data' {
            foreach ($p in $script:Registry) {
                $p.Hive  | Should -Not -BeNullOrEmpty -Because "policy $($p.Id)"
                $p.Key   | Should -Not -BeNullOrEmpty -Because "policy $($p.Id)"
                $p.Value | Should -Not -BeNullOrEmpty -Because "policy $($p.Id)"
                $p.Type  | Should -Not -BeNullOrEmpty -Because "policy $($p.Id)"
                $p.ContainsKey('Data') | Should -BeTrue -Because "policy $($p.Id)"
            }
        }
        It 'Hive is HKLM or HKCU' {
            $bad = @($script:Registry | Where-Object { $ValidHives -notcontains $_.Hive } |
                ForEach-Object { '{0} (Hive={1})' -f $_.Id, $_.Hive })
            $bad.Count | Should -Be 0 -Because "offenders: $($bad -join ', ')"
        }
        It 'Type is a supported registry value type' {
            $bad = @($script:Registry | Where-Object { $ValidRegTypes -notcontains $_.Type } |
                ForEach-Object { '{0} (Type={1})' -f $_.Id, $_.Type })
            $bad.Count | Should -Be 0 -Because "Type must be one of $($ValidRegTypes -join '/'); offenders: $($bad -join ', ')"
        }
        It 'no two policies write the same Hive + Key + Value' {
            $groups = @($script:Registry |
                Group-Object -Property { ('{0}|{1}|{2}' -f $_.Hive, $_.Key, $_.Value).ToLowerInvariant() } |
                Where-Object { $_.Count -gt 1 })
            $msgs = @($groups | ForEach-Object {
                    '{0} <- {1}' -f $_.Name, (($_.Group | ForEach-Object { $_.Id }) -join ' + ')
                })
            $msgs.Count | Should -Be 0 -Because "colliding registry targets: $($msgs -join '; ')"
        }
        It 'no Value name contains wildcard characters (* ? [ ])' {
            # Undo passes Value to -Name, which treats these as wildcards.
            $bad = @($script:Registry | Where-Object { [string]$_.Value -match '[\*\?\[\]]' } |
                ForEach-Object { '{0} (Value={1})' -f $_.Id, $_.Value })
            $bad.Count | Should -Be 0 -Because "offenders: $($bad -join ', ')"
        }
    }

    Context 'Kind=Service' {
        It 'has Name' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'Service' }) {
                $p.Name | Should -Not -BeNullOrEmpty -Because "policy $($p.Id)"
            }
        }
    }

    Context 'Kind=AppxRemove' {
        It 'has NamePattern' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'AppxRemove' }) {
                $p.NamePattern | Should -Not -BeNullOrEmpty -Because "policy $($p.Id)"
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
                $p.RuleId | Should -Match '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$' -Because "policy $($p.Id)"
            }
        }
        It 'lives in Group=defender' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'DefenderAsr' }) {
                $p.Group | Should -Be 'defender' -Because "policy $($p.Id)"
            }
        }
    }

    Context 'Kind=DefenderPref' {
        It 'lives in Group=defender' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'DefenderPref' }) {
                $p.Group | Should -Be 'defender' -Because "policy $($p.Id)"
            }
        }
    }

    Context 'Kind=Mitigation' {
        It 'lives in Group=mitigation' {
            foreach ($p in $script:Policies | Where-Object { $_.Kind -eq 'Mitigation' }) {
                $p.Group | Should -Be 'mitigation' -Because "policy $($p.Id)"
            }
        }
    }

    Context 'retired list (src/retired/retired.psd1)' {

        BeforeAll {
            $script:RetiredExists = Test-Path -LiteralPath $RetiredPath -PathType Leaf
            $script:RetiredErrors = @()
            $script:Retired       = @()
            if ($script:RetiredExists) {
                $r = _Parse-DataFile -Path $RetiredPath
                $script:RetiredErrors = @($r.Errors)
                $script:Retired       = @($r.Records)
            }
        }

        It 'exists' {
            $script:RetiredExists | Should -BeTrue -Because "expected $RetiredPath"
        }

        It 'parses with no errors' {
            $script:RetiredExists | Should -BeTrue -Because "expected $RetiredPath"
            $script:RetiredErrors.Count | Should -Be 0 -Because "parse errors: $($script:RetiredErrors -join '; ')"
        }

        It 'every entry has the required fields' {
            $bad = New-Object System.Collections.Generic.List[string]
            foreach ($e in $script:Retired) {
                $id = $e.Id
                $problems = @()
                if (-not ($id -is [string] -and $id.Length -gt 0)) { $problems += 'Id missing' }
                if (-not ($e.RetiredIn -is [string] -and $e.RetiredIn -match '^v\d+\.\d+(\.\d+)?$')) {
                    $problems += "RetiredIn='$($e.RetiredIn)'"
                }
                if (-not ($e.Reason -is [string] -and $e.Reason.Trim().Length -gt 0)) { $problems += 'Reason empty' }
                if (-not $e.ContainsKey('ReplacedBy')) {
                    $problems += 'ReplacedBy missing'
                } else {
                    foreach ($rid in (ConvertTo-IdList $e.ReplacedBy)) {
                        if (-not ($rid -is [string] -and $rid.Length -gt 0)) { $problems += "ReplacedBy item '$rid'" }
                    }
                }
                if ($e.Kind -eq 'FolderPurge') {
                    if (-not ($e.Path -is [string] -and $e.Path.Length -gt 0)) { $problems += 'Path empty' }
                } elseif ($e.Kind -eq 'Registry') {
                    if ($ValidHives -notcontains $e.Hive) { $problems += "Hive='$($e.Hive)'" }
                    if (-not ($e.Key -is [string] -and $e.Key.Length -gt 0)) { $problems += 'Key empty' }
                    if (-not ($e.Value -is [string] -and $e.Value.Length -gt 0)) { $problems += 'Value empty' }
                    if (-not ($e.Cleanup -is [bool])) { $problems += "Cleanup='$($e.Cleanup)' is not [bool]" }
                } else {
                    $problems += "Kind='$($e.Kind)'"
                }
                if ($problems.Count -gt 0) { $bad.Add(('{0}: {1}' -f $id, ($problems -join ', '))) }
            }
            $bad.Count | Should -Be 0 -Because "offenders: $($bad -join '; ')"
        }

        It 'has no duplicate Ids' {
            $dupes = @($script:Retired | ForEach-Object { [string]$_.Id } | Group-Object |
                Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
            $dupes.Count | Should -Be 0 -Because "duplicate retired Ids: $($dupes -join ', ')"
        }

        It 'no retired Id is still a live Id' {
            $clash = @($script:Retired | Where-Object { $script:LiveIds -contains $_.Id } | ForEach-Object { $_.Id })
            $clash.Count | Should -Be 0 -Because "retired and live at once: $($clash -join ', ')"
        }

        It 'every ReplacedBy Id exists in the live manifest' {
            $missing = New-Object System.Collections.Generic.List[string]
            foreach ($e in $script:Retired) {
                foreach ($rid in (ConvertTo-IdList $e.ReplacedBy)) {
                    if ($script:LiveIds -notcontains $rid) { $missing.Add(('{0} -> {1}' -f $e.Id, $rid)) }
                }
            }
            $missing.Count | Should -Be 0 -Because "ReplacedBy names unknown live Ids: $($missing -join ', ')"
        }

        It 'no retired Value name contains wildcard characters (* ? [ ])' {
            $bad = @($script:Retired | Where-Object { $_.Value -and [string]$_.Value -match '[\*\?\[\]]' } |
                ForEach-Object { '{0} (Value={1})' -f $_.Id, $_.Value })
            $bad.Count | Should -Be 0 -Because "offenders: $($bad -join ', ')"
        }
    }
}
