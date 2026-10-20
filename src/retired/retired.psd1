#
# 0AI retired policies
#
# Policy Ids that an older kit version applied but the current manifest no
# longer contains. Revert.ps1 uses this list to undo them from old backups;
# Apply.ps1 uses it to explain a retired -Select Id. Hive/Key/Value here are
# the ONLY source Revert trusts for these Ids - never the backup files.
#
# Kept outside src\manifest\ on purpose: Apply/Verify load every *.psd1 there.
#
# Cleanup = $true  : the value is inert (nothing in Windows reads it), so
#                    Revert may delete it when no JSON snapshot shows it
#                    existed before apply.
# Cleanup = $false : the value is still live under another Id; restore it
#                    only from a snapshot.
#
# Deliberately NOT listed: AI.Explorer.BlockAskCopilotShellExt.HKLM (removed
# in v2.9.1). Its backups are v2.9 .reg exports of HKLM\...\Shell Extensions\
# Blocked, and both writing that key and importing such a .reg are what
# Bitdefender Advanced Threat Defense blocked. It stays skipped-with-warning.
#
@(
    @{
        Id         = 'AI.WindowsAI.DisableSettingsAgenticSearch'
        RetiredIn  = 'v2.13.0'
        Reason     = 'not a real Windows policy (carried over from the v2.2 batch file); the real control is DisableSettingsAgent'
        ReplacedBy = @('AI.WindowsAI.DisableSettingsAgent')
        Kind       = 'Registry'
        Hive       = 'HKLM'
        Key        = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Value      = 'DisableSettingsAgenticSearch'
        Cleanup    = $true
    },
    @{
        Id         = 'AI.Paint.DisableRemoveBackground'
        RetiredIn  = 'v2.5'
        Reason     = 'not a real Windows policy; nothing reads this value'
        ReplacedBy = @()
        Kind       = 'Registry'
        Hive       = 'HKLM'
        Key        = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint'
        Value      = 'DisableRemoveBackground'
        Cleanup    = $true
    },
    @{
        Id         = 'AI.Paint.DisableGenerativeErase'
        RetiredIn  = 'v2.5'
        Reason     = 'not a real Windows policy; nothing reads this value'
        ReplacedBy = @()
        Kind       = 'Registry'
        Hive       = 'HKLM'
        Key        = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint'
        Value      = 'DisableGenerativeErase'
        Cleanup    = $true
    },
    @{
        Id         = 'AI.Photos.DisableAIEditing'
        RetiredIn  = 'v2.5'
        Reason     = 'not a real Windows policy; nothing reads this value'
        ReplacedBy = @()
        Kind       = 'Registry'
        Hive       = 'HKLM'
        Key        = 'SOFTWARE\Policies\Microsoft\Windows\Photos'
        Value      = 'DisableAIEditing'
        Cleanup    = $true
    },
    @{
        Id         = 'AI.Photos.DisableBlurBackground'
        RetiredIn  = 'v2.5'
        Reason     = 'not a real Windows policy; nothing reads this value'
        ReplacedBy = @()
        Kind       = 'Registry'
        Hive       = 'HKLM'
        Key        = 'SOFTWARE\Policies\Microsoft\Windows\Photos'
        Value      = 'DisableBlurBackground'
        Cleanup    = $true
    },
    @{
        Id         = 'AI.Photos.DisableEraseObjects'
        RetiredIn  = 'v2.5'
        Reason     = 'not a real Windows policy; nothing reads this value'
        ReplacedBy = @()
        Kind       = 'Registry'
        Hive       = 'HKLM'
        Key        = 'SOFTWARE\Policies\Microsoft\Windows\Photos'
        Value      = 'DisableEraseObjects'
        Cleanup    = $true
    },
    @{
        Id         = 'AI.WindowsAI.DisableRecallDataProviders'
        RetiredIn  = 'v2.14.0'
        Reason     = 'renamed to the .HKLM Id, to pair with the .HKCU entry'
        ReplacedBy = @('AI.WindowsAI.DisableRecallDataProviders.HKLM', 'AI.WindowsAI.DisableRecallDataProviders.HKCU')
        Kind       = 'Registry'
        Hive       = 'HKLM'
        Key        = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Value      = 'DisableRecallDataProviders'
        Cleanup    = $false
    }
)
