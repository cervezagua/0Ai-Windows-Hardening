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

function Resolve-OAiBackupFile {
    # A recorded BackupFile comes from run.json, which sits in a user-writable
    # folder while Revert runs elevated. Only its file name is trusted, and only
    # inside BackupDir: the recorded directory is ignored, so it cannot point
    # at another folder, a UNC path or a junction target. Returns $null if no
    # such file exists there.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$BackupDir,
        [string]$Recorded
    )
    if (-not $Recorded) { return $null }
    $leaf = @($Recorded -split '[\\/]')[-1]
    if (-not $leaf -or $leaf -eq '.' -or $leaf -eq '..') { return $null }
    if ($leaf.IndexOfAny([System.IO.Path]::GetInvalidFileNameChars()) -ge 0 -or $leaf.Contains(':')) { return $null }
    $candidate = Join-Path $BackupDir $leaf
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { return $null }
    return $candidate
}

function Read-OAiRegFileValue {
    # Reads ONE value from a legacy (v2.9.3 and earlier) .reg backup, in memory.
    # The file is never handed to reg.exe: a .reg can carry any values under
    # the key it names, so importing it would let a tampered backup set values
    # the kit does not manage. Only the policy's own value, under exactly the
    # policy's key, as a dword or plain string, is ever returned.
    #   Status 'found'   -> Type (DWord|String) and Data
    #   Status 'absent'  -> the key was exported but had no such value
    #   Status 'refused' -> anything unexpected; Reason says why
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [byte[]]$Bytes,
        [Parameter(Mandatory)] [ValidateSet('HKLM','HKCU')] [string]$Hive,
        [Parameter(Mandatory)] [string]$Key,
        [Parameter(Mandatory)] [string]$Value
    )
    function _Refuse([string]$why) { return [pscustomobject]@{ Status = 'refused'; Type = $null; Data = $null; Reason = $why } }
    $ic = [System.StringComparison]::OrdinalIgnoreCase

    # reg export writes UTF-16LE with a BOM; nothing else is accepted.
    if ($Bytes.Length -lt 4 -or $Bytes[0] -ne 0xFF -or $Bytes[1] -ne 0xFE -or ($Bytes.Length % 2) -ne 0) {
        return (_Refuse 'not a UTF-16LE .reg export')
    }
    $text = [System.Text.Encoding]::Unicode.GetString($Bytes, 2, $Bytes.Length - 2)
    if ($text.IndexOf([char]0) -ge 0) { return (_Refuse 'contains NUL') }
    foreach ($c in @([char]0x85, [char]0x2028, [char]0x2029)) {
        if ($text.IndexOf($c) -ge 0) { return (_Refuse 'contains a Unicode line separator') }
    }
    if ($text -match "`r(?!`n)") { return (_Refuse 'contains a bare carriage return') }

    $root = 'HKEY_LOCAL_MACHINE'
    if ($Hive -eq 'HKCU') { $root = 'HKEY_CURRENT_USER' }
    $target = '[' + $root + '\' + $Key.Trim('\') + ']'
    $nameEsc = $Value.Replace('\', '\\').Replace('"', '\"')
    $prefix = '"' + $nameEsc + '"='

    $inTarget = $false
    $sections = 0
    $hits = New-Object System.Collections.Generic.List[string]
    $continued = $false
    foreach ($raw in ($text -split "`r?`n")) {
        $line = $raw.Trim()
        if ($continued) { $continued = $line.EndsWith('\'); continue }
        if ($line.StartsWith('[')) {
            $inTarget = $line.Equals($target, $ic)
            if ($inTarget) { $sections++ }
            continue
        }
        if ($line.EndsWith('\')) { $continued = $true }
        if ($inTarget -and $line.StartsWith($prefix, $ic)) { [void]$hits.Add($line) }
    }
    if ($sections -eq 0) { return (_Refuse ('no section for ' + $target)) }
    if ($sections -gt 1) { return (_Refuse ('section ' + $target + ' appears more than once')) }
    if ($hits.Count -eq 0) { return [pscustomobject]@{ Status = 'absent'; Type = $null; Data = $null; Reason = $null } }
    if ($hits.Count -gt 1) { return (_Refuse 'value appears more than once') }

    $rhs = $hits[0].Substring($prefix.Length).Trim()
    if ($rhs.EndsWith('\')) { return (_Refuse 'multi-line value data') }
    if ($rhs -match '^(?i)dword:([0-9a-f]{8})$') {
        $u = [Convert]::ToUInt32($Matches[1], 16)
        $i = [BitConverter]::ToInt32([BitConverter]::GetBytes($u), 0)
        return [pscustomobject]@{ Status = 'found'; Type = 'DWord'; Data = $i; Reason = $null }
    }
    if ($rhs.Length -ge 2 -and $rhs.StartsWith('"') -and $rhs.EndsWith('"')) {
        $inner = $rhs.Substring(1, $rhs.Length - 2)
        $sb = New-Object System.Text.StringBuilder
        for ($k = 0; $k -lt $inner.Length; $k++) {
            $ch = $inner[$k]
            if ($ch -eq '"') { return (_Refuse 'unescaped quote in string data') }
            if ($ch -eq '\') {
                if ($k + 1 -ge $inner.Length) { return (_Refuse 'dangling escape in string data') }
                $nx = $inner[$k + 1]
                if ($nx -ne '\' -and $nx -ne '"') { return (_Refuse 'unsupported escape in string data') }
                [void]$sb.Append($nx); $k++
                continue
            }
            [void]$sb.Append($ch)
        }
        return [pscustomobject]@{ Status = 'found'; Type = 'String'; Data = $sb.ToString(); Reason = $null }
    }
    return (_Refuse 'only dword and plain string data are restored from legacy backups')
}

Export-ModuleMember -Function Import-OAiManifestFile, Get-OAiRetiredPolicies, Test-OAiSelectIds, Resolve-OAiBackupFile, Read-OAiRegFileValue
