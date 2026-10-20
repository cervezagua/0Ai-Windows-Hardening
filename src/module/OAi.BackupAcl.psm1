#
# OAi.BackupAcl.psm1 - v2.14.2 admin-only backup folders
#
# Revert runs elevated and trusts what a backup folder says each setting was
# before Apply. Backups live under %USERPROFILE%, which any program the user
# runs can write, so Apply now creates each backup folder admin-only, and
# Revert checks that a folder is still admin-only before using it.
#
#   Protect-OAiBackupDir      Apply: lock a freshly created backup folder
#   Test-OAiBackupDirLocked   Revert: is the folder (and everything in it)
#                             still writable by Administrators/SYSTEM only?
#   Test-OAiAdminOnlyAcl      the decision itself, on plain data, so it can
#                             be unit-tested without Windows ACL APIs
#

$ErrorActionPreference = 'Stop'

# SYSTEM, Administrators, TrustedInstaller
$script:TrustedSids = @(
    'S-1-5-18',
    'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)

# Any of these rights lets a holder change the object or its permissions:
# WriteData/AddFile, AppendData/AddSubdirectory, WriteEA, DeleteChild,
# WriteAttributes, DELETE, WRITE_DAC, WRITE_OWNER, MAXIMUM_ALLOWED,
# GENERIC_ALL, GENERIC_WRITE.
$script:WriteMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x02000000 -bor 0x10000000 -bor 0x40000000

function Test-OAiAdminOnlyAcl {
    # Owner : owner SID string
    # Aces  : DACL entries as objects with Sid, Mask (int), Allow (bool),
    #         InheritOnly (bool); $null means the object has no DACL at all
    #         (everyone has full access)
    param([string]$Owner, $Aces)
    if ($script:TrustedSids -notcontains $Owner) {
        # The owner can always rewrite the permissions.
        return [pscustomobject]@{ Ok = $false; Reason = ('owned by {0}' -f $Owner) }
    }
    if ($null -eq $Aces) {
        return [pscustomobject]@{ Ok = $false; Reason = 'no access list (everyone has full access)' }
    }
    foreach ($a in @($Aces)) {
        if (-not $a.Allow -or $a.InheritOnly) { continue }
        if (([int64]$a.Mask -band $script:WriteMask) -eq 0) { continue }
        if ($script:TrustedSids -notcontains [string]$a.Sid) {
            return [pscustomobject]@{ Ok = $false; Reason = ('{0} can modify it' -f $a.Sid) }
        }
    }
    return [pscustomobject]@{ Ok = $true; Reason = '' }
}

function _Read-Acl {
    # Windows only: owner SID + DACL of one file or folder as plain data.
    param([string]$Path)
    $sec = Get-Acl -LiteralPath $Path
    $raw = New-Object System.Security.AccessControl.RawSecurityDescriptor -ArgumentList ($sec.GetSecurityDescriptorBinaryForm()), 0
    $aces = $null
    if ($null -ne $raw.DiscretionaryAcl) {
        $aces = @(foreach ($ace in $raw.DiscretionaryAcl) {
            $isAllow = $false
            $sid = ''
            $mask = 0
            if ($ace -is [System.Security.AccessControl.KnownAce]) {
                $sid  = $ace.SecurityIdentifier.Value
                $mask = $ace.AccessMask
                $isAllow = ($ace -is [System.Security.AccessControl.QualifiedAce]) -and ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed)
            } else {
                # Unknown ACE type: treat as a grant to an untrusted SID.
                $isAllow = $true; $sid = 'unknown'; $mask = -1
            }
            [pscustomobject]@{
                Sid         = $sid
                Mask        = $mask
                Allow       = $isAllow
                InheritOnly = (($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0)
            }
        })
    }
    $owner = ''
    if ($null -ne $raw.Owner) { $owner = $raw.Owner.Value }
    return @{ Owner = $owner; Aces = $aces }
}

function _Is-Link {
    param([string]$Path)
    $i = Get-Item -LiteralPath $Path -Force
    return (($i.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
}

function Test-OAiBackupDirLocked {
    # Ok     : the folder and everything in it is admin-only
    # IsLink : the folder or something in it is a junction/symlink; never
    #          use such a folder, whatever the user answers
    param([Parameter(Mandatory)][string]$Path)
    try {
        if (_Is-Link $Path) {
            return [pscustomobject]@{ Ok = $false; IsLink = $true; Reason = 'the folder is a link to another location' }
        }
        $items = @(Get-Item -LiteralPath $Path -Force) + @(Get-ChildItem -LiteralPath $Path -Recurse -Force)
        foreach ($it in $items) {
            if (($it.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                return [pscustomobject]@{ Ok = $false; IsLink = $true; Reason = ('{0} is a link to another location' -f $it.Name) }
            }
            $acl = _Read-Acl -Path $it.FullName
            $r = Test-OAiAdminOnlyAcl -Owner $acl.Owner -Aces $acl.Aces
            if (-not $r.Ok) {
                return [pscustomobject]@{ Ok = $false; IsLink = $false; Reason = ('{0}: {1}' -f $it.Name, $r.Reason) }
            }
        }
        return [pscustomobject]@{ Ok = $true; IsLink = $false; Reason = '' }
    } catch {
        return [pscustomobject]@{ Ok = $false; IsLink = $false; Reason = ('could not read permissions: ' + $_.Exception.Message) }
    }
}

function Protect-OAiBackupDir {
    # Owner Administrators; full control for SYSTEM and Administrators;
    # read-only for the account running the kit so it can open its logs.
    # Inheritance from %USERPROFILE% is cut, and new files inherit this.
    param([Parameter(Mandatory)][string]$Path)
    if (_Is-Link $Path) { throw ('{0} is a link to another location; not locking it' -f $Path) }
    $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $sddl = 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;{0})' -f $me
    $acl = Get-Acl -LiteralPath $Path
    # Owner, group and DACL only: writing the audit section (SACL) needs
    # SeSecurityPrivilege, which an elevated admin token has disabled.
    $sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Group -bor [System.Security.AccessControl.AccessControlSections]::Access
    $acl.SetSecurityDescriptorSddlForm($sddl, $sections)
    Set-Acl -LiteralPath $Path -AclObject $acl
    $r = Test-OAiBackupDirLocked -Path $Path
    if (-not $r.Ok) { throw ('lock did not take effect: ' + $r.Reason) }
}

Export-ModuleMember -Function Test-OAiAdminOnlyAcl, Test-OAiBackupDirLocked, Protect-OAiBackupDir
