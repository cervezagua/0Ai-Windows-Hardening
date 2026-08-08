#
# 0AI v2.10.0 - Snapshot-CrashEvidence.ps1
#
# Read-only diagnostic. Collects everything needed to work out why a machine
# is bugchecking or killing services, in one command.
#
# Written after a real investigation: a user reported random BSODs plus two
# crashing licensing services and asked whether this kit caused them. Answering
# it took a minidump parse, a driver inventory, an event-log sweep and a
# mitigation check - four separate steps. This script is those four steps.
# (Root cause turned out to be an EXPO memory overclock enabled in BIOS.)
#
# It does NOT parse minidumps - that needs symbols and a debugger. It inventories
# them and tells you the next move.
#
# Nothing is written. Nothing is deleted. Safe to run any time.
# Runs without admin, but reports more with it.
#
# Usage:
#   powershell -NoProfile -ExecutionPolicy Bypass -File src\Snapshot-CrashEvidence.ps1
#   powershell -NoProfile -ExecutionPolicy Bypass -File src\Snapshot-CrashEvidence.ps1 > crash_evidence.txt
#

[CmdletBinding()]
param(
    [int]$Days = 30
)

$ErrorActionPreference = 'Continue'

# ---- Culture invariance (must run before any other work) ----
# Matches the other entry points: PowerShell's -match / -like fold case using
# the current culture, which breaks pattern matching on Turkish/Azeri locales.
try {
    $ci = [System.Globalization.CultureInfo]::InvariantCulture
    [System.Globalization.CultureInfo]::DefaultThreadCurrentCulture   = $ci
    [System.Globalization.CultureInfo]::DefaultThreadCurrentUICulture = $ci
    [System.Threading.Thread]::CurrentThread.CurrentCulture   = $ci
    [System.Threading.Thread]::CurrentThread.CurrentUICulture = $ci
} catch {}

$thisDir = Split-Path -Parent $PSCommandPath
try { Import-Module (Join-Path $thisDir 'module\OAi.Version.psm1') -Force -ErrorAction Stop } catch {}
function _Ver { try { Get-OAiVersion } catch { 'v2.10.0' } }

function _Print-Header {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 72)
    Write-Host (' ' + $Text)
    Write-Host ('=' * 72)
}

function _IsAdmin {
    try {
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $pr = New-Object System.Security.Principal.WindowsPrincipal($id)
        return $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

$since = (Get-Date).AddDays(-$Days)

_Print-Header ('0AI {0} - crash evidence snapshot' -f (_Ver))
Write-Host ('Host       : {0}' -f $env:COMPUTERNAME)
Write-Host ('Elevated   : {0}' -f (_IsAdmin))
Write-Host ('Window     : last {0} days (since {1:yyyy-MM-dd})' -f $Days, $since)
Write-Host ('Timestamp  : {0}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
try {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    Write-Host ('OS         : {0} build {1}.{2}' -f $cv.ProductName, $cv.CurrentBuild, $cv.UBR)
} catch {}

# ---------------------------------------------------------------- minidumps
_Print-Header 'Minidumps'
$mdDir = Join-Path $env:SystemRoot 'Minidump'
if (Test-Path $mdDir) {
    $dumps = Get-ChildItem -Path $mdDir -Filter '*.dmp' -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending
    if ($dumps) {
        foreach ($f in $dumps) {
            Write-Host ('  {0,-28} {1:yyyy-MM-dd HH:mm}  {2,8:N0} KB' -f $f.Name, $f.LastWriteTime, ($f.Length/1KB))
        }
        Write-Host ''
        Write-Host ('  {0} dump(s). If several name DIFFERENT faulting modules, suspect RAM /' -f $dumps.Count)
        Write-Host '  storage / an unstable memory overclock (XMP/EXPO) rather than one driver.'
    } else { Write-Host '  (folder exists but no .dmp files)' }
} else { Write-Host '  (no Minidump folder - crash dumps may be disabled)' }
Write-Host ''
Write-Host '  To identify the faulting module: open the .dmp in WinDbg (Microsoft Store)'
Write-Host '  and run  !analyze -v  - read MODULE_NAME / IMAGE_NAME / FAILURE_BUCKET_ID.'

# ---------------------------------------------------------------- bugchecks
_Print-Header 'Bugcheck events (System log)'
try {
    $bc = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; StartTime=$since} -ErrorAction SilentlyContinue |
            Where-Object { $_.ProviderName -match 'BugCheck' }
    if ($bc) {
        foreach ($e in $bc) {
            Write-Host ('  {0:yyyy-MM-dd HH:mm}  {1}' -f $e.TimeCreated, ($e.Message -replace '\s+', ' ').Trim())
        }
    } else { Write-Host '  (none in window)' }
} catch { Write-Host ('  (unavailable: {0})' -f $_.Exception.Message) }

# ------------------------------------------------- unexpected service stops
_Print-Header 'Unexpected service terminations'
try {
    $svc = Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(7031,7034); StartTime=$since} -ErrorAction SilentlyContinue
    if ($svc) {
        $svc | Group-Object { ($_.Message -split ' service')[0] } |
            Sort-Object Count -Descending | Select-Object -First 20 | ForEach-Object {
                Write-Host ('  {0,3}x  {1}' -f $_.Count, $_.Name)
            }
    } else { Write-Host '  (none in window)' }
} catch { Write-Host ('  (unavailable: {0})' -f $_.Exception.Message) }

# --------------------------------------------------------- security product
_Print-Header 'Registered antivirus products'
try {
    $av = Get-CimInstance -Namespace 'root\SecurityCenter2' -ClassName AntiVirusProduct -ErrorAction Stop
    foreach ($a in $av) { Write-Host ('  {0}   [{1}]' -f $a.displayName, $a.pathToSignedProductExe) }
    if (@($av).Count -gt 1) {
        Write-Host ''
        Write-Host '  More than one AV registered. Two active kernel filter stacks is a'
        Write-Host '  well-known bugcheck source - worth ruling out.'
    }
} catch { Write-Host '  (unavailable - needs a client SKU / WMI access)' }

# -------------------------------------------------------- risky driver scan
_Print-Header 'Loaded third-party kernel drivers of interest'
# Categories that account for most third-party bugchecks. Not accusations -
# just the shortlist worth checking first when a dump has no obvious culprit.
$risky = [ordered]@{
    'Overclock / direct hardware I/O' = 'RyzenMaster|cpuz|AsIO|IOMap|MsIo|uiomap|pwdrvio|CtiAIo|WinRing0|inpout|amifldrv|atillk|EIO|HwRwDrv'
    'Anti-cheat'                      = 'vgk|EasyAntiCheat|BEDaisy|mhyprot|ACE-BASE|ntiolib'
    'Third-party security'            = 'Trufos|bdd|bdel|bdprivmon|ignis|gemma|atc\.sys|klif|klupd|avgntflt|eamonm|SRTSP|ehdrv|cyoptics|SentinelMonitor|CSAgent'
    'Storage / encryption filter'     = 'veracrypt|truecrypt|bestcrypt|dcrypt|EhStorTcgDrv'
    'Virtual / VPN network filter'    = 'ovpn|adgnetwork|tap0901|wintun|wireguard|nordlwf|ExpressVpn'
    'Display'                         = 'nvlddmkm|amdkmdag|igdkmd'
}
try {
    $drv = Get-CimInstance -ClassName Win32_SystemDriver -ErrorAction Stop |
            Where-Object { $_.State -eq 'Running' }
    $found = $false
    foreach ($cat in $risky.Keys) {
        $hits = $drv | Where-Object { $_.PathName -match $risky[$cat] -or $_.Name -match $risky[$cat] }
        if ($hits) {
            $found = $true
            Write-Host ('  [{0}]' -f $cat)
            foreach ($h in $hits) { Write-Host ('     {0,-24} {1}' -f $h.Name, $h.PathName) }
        }
    }
    if (-not $found) { Write-Host '  (none matched the shortlist)' }
    Write-Host ''
    Write-Host ('  {0} running kernel drivers total.' -f @($drv).Count)
    Write-Host '  To catch a driver corrupting kernel memory, run: verifier.exe'
    Write-Host '  -> Standard settings -> all non-Microsoft drivers. The next bugcheck'
    Write-Host '  then names the offender directly. Expect slower boots while enabled.'
} catch { Write-Host ('  (unavailable: {0})' -f $_.Exception.Message) }

# ----------------------------------------------------- mitigation / kit state
_Print-Header 'System exploit mitigation state'
try {
    $kern = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'
    $mo = (Get-ItemProperty -Path $kern -Name 'MitigationOptions' -ErrorAction Stop).MitigationOptions
    Write-Host ('  MitigationOptions override PRESENT: {0}' -f (($mo | ForEach-Object { $_.ToString('x2') }) -join ' '))
    Write-Host '  (a system-wide override is set - Windows defaults are being replaced)'
} catch {
    Write-Host '  MitigationOptions: not set (Windows defaults in effect)'
}
try {
    Get-ProcessMitigation -System -ErrorAction Stop |
        Out-String -Width 120 | ForEach-Object { $_.TrimEnd() } | Write-Host
} catch { Write-Host ('  Get-ProcessMitigation unavailable: {0}' -f $_.Exception.Message) }

# --------------------------------------------------------------- kit history
_Print-Header '0AI run history (for timeline correlation)'
$bk = Join-Path $env:USERPROFILE '0AI_Backups'
if (Test-Path $bk) {
    Get-ChildItem -Path $bk -Directory -ErrorAction SilentlyContinue |
        Sort-Object Name -Descending | Select-Object -First 10 | ForEach-Object {
            Write-Host ('  {0}' -f $_.Name)
        }
    Write-Host ''
    Write-Host '  Compare these dates against the bugcheck dates above. Crashes that'
    Write-Host '  predate the first run, or start well after it, are not from this kit.'
} else { Write-Host '  (no 0AI_Backups folder - kit never run for this user)' }

Write-Host ''
Write-Host 'Done. Note: this kit installs no kernel drivers and its exploit mitigations'
Write-Host 'are user-mode, so it cannot itself produce a kernel bugcheck. Share this'
Write-Host 'output alongside !analyze -v when reporting a crash.'
