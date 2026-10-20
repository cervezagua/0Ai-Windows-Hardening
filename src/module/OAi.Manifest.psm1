#
# OAi.Manifest.psm1 - manifest loading and pure validation helpers
#
# Shared by Apply.ps1, Revert.ps1, Verify.ps1 and the snapshot diagnostics.
# Nothing here touches the registry: every function is pure (file reads only).
#

$ErrorActionPreference = 'Stop'

# Import-PowerShellDataFile rejects top-level arrays on PS 5.1. Our manifests
# are @(...) at the top level, so parse via AST and call SafeGetValue(), the
# PS-supported constrained literal eval (no code runs).
function _Collect-Hashtables {
    param($Val, [System.Collections.Generic.List[object]]$Acc)
    if ($null -eq $Val) { return }
    if ($Val -is [System.Collections.IDictionary]) { [void]$Acc.Add($Val); return }
    if ($Val -is [System.Collections.IEnumerable] -and $Val -isnot [string]) {
        foreach ($v in $Val) { _Collect-Hashtables -Val $v -Acc $Acc }
        return
    }
}

function Import-OAiManifestFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$Path
    )
    $leaf = Split-Path -Leaf $Path
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw ('manifest file not found: {0}' -f $Path)
    }
    $tokens = $null
    $errs   = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
    if ($errs -and @($errs).Count -gt 0) {
        throw ('parse error in {0}: {1}' -f $leaf, @($errs)[0].Message)
    }
    $stmts = @($ast.EndBlock.Statements)
    if ($stmts.Count -eq 0) { return ,@() }
    try {
        $val = $stmts[0].PipelineElements[0].Expression.SafeGetValue()
    } catch {
        throw ('invalid data in {0}: {1}' -f $leaf, $_.Exception.Message)
    }
    $acc = New-Object System.Collections.Generic.List[object]
    _Collect-Hashtables -Val $val -Acc $acc
    return ,$acc.ToArray()
}

function Get-OAiRetiredPolicies {
    [CmdletBinding()]
    param(
        [string]$Path = ''
    )
    if (-not $Path) {
        $Path = Join-Path (Join-Path (Split-Path -Parent $PSScriptRoot) 'retired') 'retired.psd1'
    }
    return ,(Import-OAiManifestFile -Path $Path)
}

function Test-OAiSelectIds {
    [CmdletBinding()]
    param(
        [string[]]$Select = @(),
        [object[]]$LivePolicies = @(),
        [object[]]$Retired = @()
    )
    $live = @{}
    foreach ($p in $LivePolicies) {
        if ($null -ne $p -and $p.Id) { $live[[string]$p.Id] = $true }
    }
    $ret = @{}
    foreach ($r in $Retired) {
        if ($null -ne $r -and $r.Id) { $ret[[string]$r.Id] = $r }
    }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($id in $Select) {
        $sid = [string]$id
        if ($sid -and $live.ContainsKey($sid)) { continue }
        if ($sid -and $ret.ContainsKey($sid)) {
            $r = $ret[$sid]
            $repl = @($r.ReplacedBy | Where-Object { $_ })
            $use = 'no replacement'
            if ($repl.Count -gt 0) { $use = ($repl -join ', ') }
            $msg = '{0} was retired in {1}: {2}. Use: {3}' -f $sid, $r.RetiredIn, $r.Reason, $use
            $out.Add([pscustomobject]@{ Id = $sid; Retired = $true; Message = $msg })
        } else {
            $out.Add([pscustomobject]@{ Id = $sid; Retired = $false; Message = ('{0} is not a known policy Id' -f $sid) })
        }
    }
    # Unrolled on purpose: callers wrap the call in @(), and a comma-return
    # would hand them a one-element array holding the real array.
    return $out.ToArray()
}

function Test-OAiRegFileScope {
    # Fail-closed scope check for a legacy .reg backup before `reg import`:
    # true only if every section header targets the policy's own key (or a
    # subkey) and nothing deletes a key.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$RegFilePath,
        [Parameter(Mandatory)] [ValidateSet('HKLM','HKCU')] [string]$Hive,
        [Parameter(Mandatory)] [string]$Key
    )
    try {
        $k = $Key.Trim().Trim('\')
        if (-not $k) { return $false }
        if (-not (Test-Path -LiteralPath $RegFilePath -PathType Leaf)) { return $false }

        if ($Hive -eq 'HKLM') { $roots = @('HKEY_LOCAL_MACHINE', 'HKLM') }
        else                  { $roots = @('HKEY_CURRENT_USER', 'HKCU') }
        $ic = [System.StringComparison]::OrdinalIgnoreCase

        # reg export writes UTF-16LE with BOM; REGEDIT4 files are ANSI.
        # ReadAllText honours a BOM (UTF-16LE/BE, UTF-8) and otherwise reads UTF-8.
        $text = [System.IO.File]::ReadAllText($RegFilePath)
        $headers = 0
        foreach ($raw in ($text -split "\r?\n")) {
            $line = $raw.Trim()
            if (-not $line.StartsWith('[')) { continue }
            $headers++
            if (-not $line.EndsWith(']')) { return $false }
            $section = $line.Substring(1, $line.Length - 2).Trim()
            if ($section.StartsWith('-')) { return $false }
            $section = $section.TrimEnd('\')

            $inScope = $false
            foreach ($root in $roots) {
                $target = $root + '\' + $k
                if ($section.Equals($target, $ic) -or $section.StartsWith($target + '\', $ic)) {
                    $inScope = $true
                    break
                }
            }
            if (-not $inScope) { return $false }
        }
        return ($headers -gt 0)
    } catch {
        return $false
    }
}

Export-ModuleMember -Function Import-OAiManifestFile, Get-OAiRetiredPolicies, Test-OAiSelectIds, Test-OAiRegFileScope
