#
# OAi.BackupAcl.psm1 - v2.14.2 admin-only backup folders
#
# Revert runs elevated and restores whatever "previous" values a backup
# holds, so a backup must be something no program without admin rights can
# change - and that includes renaming the folder away and putting a forged
# one in its place. Locking a folder is not enough on its own: under
# %USERPROFILE% the user can rename any child folder, locked or not. So:
#
#   - Backups live in %ProgramData%\0AI_Backups\<account SID>\<stamp>,
#     where standard users can create folders but cannot rename or delete
#     anyone else's.
#   - Each folder is created with its admin-only permissions in one call,
#     so there is no moment when it is open to everyone.
#   - Revert trusts a backup only if the folder, everything in it, and
#     every folder above it pass Test-OAiBackupDirLocked.
#
#   Test-OAiAdminOnlyAcl      the decision, on plain data (unit-tested)
#   Test-OAiBackupDirLocked   Revert: may this backup be trusted?
#   Get-OAiBackupHome         the per-account backup folder (-Create makes it)
#   New-OAiLockedDir          create a new admin-only folder atomically
#   Set-OAiBackupOwner        Apply: make Administrators own every file
#   Copy-OAiBackupToLocked    Revert: copy an untrusted backup before use
#

$ErrorActionPreference = 'Stop'

# SYSTEM, Administrators, TrustedInstaller
$script:TrustedSids = @(
    'S-1-5-18',
    'S-1-5-32-544',
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
)

# Rights that let a holder change an object or its permissions:
# WriteData/AddFile, AppendData/AddSubdirectory, WriteEA, DeleteChild,
# WriteAttributes, DELETE, WRITE_DAC, WRITE_OWNER, MAXIMUM_ALLOWED,
# GENERIC_ALL, GENERIC_WRITE.
$script:WriteMask = 0x2 -bor 0x4 -bor 0x10 -bor 0x40 -bor 0x100 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x02000000 -bor 0x10000000 -bor 0x40000000

# Rights on a folder ABOVE the backup that would let a holder rename or
# replace what is below it: DeleteChild, DELETE, WRITE_DAC, WRITE_OWNER,
# MAXIMUM_ALLOWED, GENERIC_ALL. Creating new folders alongside is harmless.
$script:ReplaceMask = 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x02000000 -bor 0x10000000

$script:FileSizeCap = 32MB

function Test-OAiAdminOnlyAcl {
    # Owner : owner SID string
    # Aces  : DACL entries as objects with Sid, Mask (int), Allow (bool),
    #         InheritOnly (bool); $null means no DACL at all (full access
    #         for everyone)
    # Mask  : which rights count as "can change it" (default: any write)
    param([string]$Owner, $Aces, [int64]$Mask = $script:WriteMask)
    if ($script:TrustedSids -notcontains $Owner) {
        # The owner can always rewrite the permissions.
        return [pscustomobject]@{ Ok = $false; Reason = ('owned by {0}' -f $Owner) }
    }
    if ($null -eq $Aces) {
        return [pscustomobject]@{ Ok = $false; Reason = 'no access list (everyone has full access)' }
    }
    foreach ($a in @($Aces)) {
        if (-not $a.Allow -or $a.InheritOnly) { continue }
        if (([int64]$a.Mask -band $Mask) -eq 0) { continue }
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
            if ($ace -is [System.Security.AccessControl.KnownAce]) {
                $sid  = $ace.SecurityIdentifier.Value
                $mask = $ace.AccessMask
                # Anything that is not provably a deny/audit entry counts as
                # a grant (compound ACEs are KnownAce but not QualifiedAce).
                $isAllow = (-not ($ace -is [System.Security.AccessControl.QualifiedAce])) -or
                           ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed)
            } else {
                # Unknown ACE type: treat as a full grant to an untrusted SID.
                $sid = 'unknown'; $mask = -1; $isAllow = $true
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
    param($Item)
    return (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0)
}

function _Walk {
    # Every item under $Path (and $Path itself), one level at a time, never
    # descending into a junction or symlink. Stops at the first link.
    param([string]$Path)
    $root  = Get-Item -LiteralPath $Path -Force
    $items = New-Object System.Collections.Generic.List[object]
    $items.Add($root)
    if (_Is-Link $root) { return @{ Items = $items; Link = $root } }
    $queue = New-Object System.Collections.Generic.Queue[string]
    $queue.Enqueue($root.FullName)
    while ($queue.Count -gt 0) {
        $d = $queue.Dequeue()
        foreach ($c in @(Get-ChildItem -LiteralPath $d -Force)) {
            $items.Add($c)
            if (_Is-Link $c) { return @{ Items = $items; Link = $c } }
            if ($c.PSIsContainer) { $queue.Enqueue($c.FullName) }
        }
    }
    return @{ Items = $items; Link = $null }
}

function _Test-Ancestors {
    # No folder above $Path may be a link, or let an untrusted account
    # rename or replace what is below it.
    param([string]$Path)
    $p = Split-Path -Parent $Path
    while ($p) {
        $it = Get-Item -LiteralPath $p -Force
        if (_Is-Link $it) { return [pscustomobject]@{ Ok = $false; Reason = ('{0} is a link' -f $p) } }
        $acl = _Read-Acl -Path $p
        $r = Test-OAiAdminOnlyAcl -Owner $acl.Owner -Aces $acl.Aces -Mask $script:ReplaceMask
        if (-not $r.Ok) { return [pscustomobject]@{ Ok = $false; Reason = ('{0}: {1}' -f $p, $r.Reason) } }
        $p = Split-Path -Parent $p
    }
    return [pscustomobject]@{ Ok = $true; Reason = '' }
}

function Test-OAiBackupDirLocked {
    # Ok      : the backup can be trusted
    # IsLink  : the folder is or contains a junction/symlink - never use it
    # Missing : the folder does not exist
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return [pscustomobject]@{ Ok = $false; IsLink = $false; Missing = $true; Reason = 'folder not found' }
    }
    try {
        # Links first, so a folder that fails on permissions too is still
        # reported as a link (refused outright, not offered to the user).
        $w = _Walk -Path $Path
        if ($w.Link) {
            return [pscustomobject]@{ Ok = $false; IsLink = $true; Missing = $false; Reason = ('{0} is a link to another location' -f $w.Link.FullName) }
        }
        $a = _Test-Ancestors -Path $Path
        if (-not $a.Ok) {
            return [pscustomobject]@{ Ok = $false; IsLink = $false; Missing = $false; Reason = ('it can be renamed or replaced: ' + $a.Reason) }
        }
        foreach ($it in $w.Items) {
            $acl = _Read-Acl -Path $it.FullName
            $r = Test-OAiAdminOnlyAcl -Owner $acl.Owner -Aces $acl.Aces
            if (-not $r.Ok) {
                return [pscustomobject]@{ Ok = $false; IsLink = $false; Missing = $false; Reason = ('{0}: {1}' -f $it.Name, $r.Reason) }
            }
        }
        return [pscustomobject]@{ Ok = $true; IsLink = $false; Missing = $false; Reason = '' }
    } catch {
        return [pscustomobject]@{ Ok = $false; IsLink = $false; Missing = $false; Reason = ('could not read its permissions: ' + $_.Exception.Message) }
    }
}

function _Sddl {
    param([switch]$NoUserRead, [switch]$UsersList)
    # Owner Administrators; full control for SYSTEM and Administrators;
    # inheritance from the parent cut; new files inherit this.
    $s = 'O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
    if ($UsersList) {
        # Shared root: every user may list it (this folder only).
        $s += '(A;;0x1200a9;;;BU)'
    } elseif (-not $NoUserRead) {
        # Read-only for the account running the kit, so it can open its logs.
        $s += ('(A;OICI;0x1200a9;;;{0})' -f [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    }
    return $s
}

function New-OAiLockedDir {
    # Creates $Path with its admin-only permissions in one call (no window
    # in which it is open to everyone), then proves it is new, empty and
    # admin-only. Throws otherwise.
    param([Parameter(Mandatory)][string]$Path, [switch]$NoUserRead, [switch]$UsersList)
    if (Test-Path -LiteralPath $Path) { throw ('{0} already exists' -f $Path) }
    $ds = New-Object System.Security.AccessControl.DirectorySecurity
    $sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Group -bor [System.Security.AccessControl.AccessControlSections]::Access
    $ds.SetSecurityDescriptorSddlForm((_Sddl -NoUserRead:$NoUserRead -UsersList:$UsersList), $sections)
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        [void][System.IO.Directory]::CreateDirectory($Path, $ds)
    } else {
        [System.IO.FileSystemAclExtensions]::Create((New-Object System.IO.DirectoryInfo -ArgumentList $Path), $ds)
    }
    $it = Get-Item -LiteralPath $Path -Force
    if (_Is-Link $it) { throw ('{0} is a link' -f $Path) }
    if (@(Get-ChildItem -LiteralPath $Path -Force).Count -gt 0) { throw ('{0} is not empty: it was not created by this run' -f $Path) }
    $acl = _Read-Acl -Path $Path
    $r = Test-OAiAdminOnlyAcl -Owner $acl.Owner -Aces $acl.Aces
    if (-not $r.Ok) { throw ('{0} is not admin-only after creation: {1}' -f $Path, $r.Reason) }
}

function _Test-DirItself {
    param([string]$Path)
    $it = Get-Item -LiteralPath $Path -Force
    if (_Is-Link $it) { return $false }
    $acl = _Read-Acl -Path $Path
    return (Test-OAiAdminOnlyAcl -Owner $acl.Owner -Aces $acl.Aces).Ok
}

function _Ensure-LockedDir {
    # Makes sure $Path is an admin-only folder we can build on. One that a
    # standard user created first (allowed in %ProgramData%) is moved aside
    # and replaced; its contents are left untouched for inspection.
    param([string]$Path, [switch]$UsersList)
    if (Test-Path -LiteralPath $Path) {
        if (_Test-DirItself -Path $Path) { return }
        $aside = '{0}.untrusted-{1}' -f (Split-Path -Leaf $Path), (Get-Date -Format 'yyyyMMdd_HHmmss')
        Rename-Item -LiteralPath $Path -NewName $aside
    }
    New-OAiLockedDir -Path $Path -UsersList:$UsersList
}

function Get-OAiBackupHome {
    # %ProgramData%\0AI_Backups\<SID of the account running the kit>
    param([switch]$Create)
    $root = Join-Path $env:ProgramData '0AI_Backups'
    $home_ = Join-Path $root ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
    if ($Create) {
        _Ensure-LockedDir -Path $root -UsersList
        _Ensure-LockedDir -Path $home_
    }
    return $home_
}

function Set-OAiBackupOwner {
    # Files normally get Administrators as owner, but the "Default owner for
    # objects created by members of the Administrators group" policy can make
    # it the user account instead, which would let the user change them.
    param([Parameter(Mandatory)][string]$Path)
    $ba = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList 'S-1-5-32-544'
    foreach ($f in @(Get-ChildItem -LiteralPath $Path -Force -File)) {
        if (_Is-Link $f) { continue }
        $acl = Get-Acl -LiteralPath $f.FullName
        if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-32-544') {
            $acl.SetOwner($ba)
            Set-Acl -LiteralPath $f.FullName -AclObject $acl
        }
    }
}

function Copy-OAiBackupToLocked {
    # Revert, after the user confirmed an untrusted backup: copy its files
    # into a new admin-only folder and read only the copy, so nothing can
    # swap the backup while Revert is using it. Top-level regular files
    # only (backups are flat); the copy is not readable by the user.
    param([Parameter(Mandatory)][string]$Source, [Parameter(Mandatory)][string]$Dest)
    New-OAiLockedDir -Path $Dest -NoUserRead
    foreach ($f in @(Get-ChildItem -LiteralPath $Source -Force -File)) {
        if (_Is-Link $f) { throw ('{0} is a link' -f $f.FullName) }
        if ($f.Length -gt $script:FileSizeCap) { throw ('{0} is larger than expected' -f $f.FullName) }
        [System.IO.File]::WriteAllBytes((Join-Path $Dest $f.Name), [System.IO.File]::ReadAllBytes($f.FullName))
    }
}

Export-ModuleMember -Function Test-OAiAdminOnlyAcl, Test-OAiBackupDirLocked, Get-OAiBackupHome, New-OAiLockedDir, Set-OAiBackupOwner, Copy-OAiBackupToLocked
