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
# Kind = 'FolderPurge' entries carry Path instead of Hive/Key/Value/Cleanup.
# A purge cannot be undone, so Revert only reports them.
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
    },
    @{
        Id         = 'AI.Edge.DiscoverEnabled'
        RetiredIn  = 'v2.14.1'
        Reason     = 'Edge reports "Unknown policy" (Edge 155); the real EdgeDiscoverEnabled has been obsolete since Edge 105'
        ReplacedBy = @('AI.Edge.HubsSidebarEnabled')
        Kind       = 'Registry'
        Hive       = 'HKLM'
        Key        = 'SOFTWARE\Policies\Microsoft\Edge'
        Value      = 'DiscoverEnabled'
        Cleanup    = $true
    },
    @{
        Id         = 'AI.Edge.EdgeCopilotEnabled'
        RetiredIn  = 'v2.14.1'
        Reason     = 'Edge for Windows reports "Unknown policy" (Edge 155); documented for Android / iOS only'
        ReplacedBy = @('AI.Edge.HubsSidebarEnabled')
        Kind       = 'Registry'
        Hive       = 'HKLM'
        Key        = 'SOFTWARE\Policies\Microsoft\Edge'
        Value      = 'EdgeCopilotEnabled'
        Cleanup    = $true
    },
    @{
        Id         = 'AI.SmartActions.SmartActionsState'
        RetiredIn  = 'v2.14.1'
        Reason     = 'no source found; nothing documents this value'
        ReplacedBy = @()
        Kind       = 'Registry'
        Hive       = 'HKCU'
        Key        = 'Software\Microsoft\Windows\CurrentVersion\SmartActions'
        Value      = 'SmartActionsState'
        Cleanup    = $true
    },
    @{
        Id         = 'AI.Narrator.ImageDescriptionsEnabled'
        RetiredIn  = 'v2.14.1'
        Reason     = 'no source found; nothing documents this value'
        ReplacedBy = @()
        Kind       = 'Registry'
        Hive       = 'HKCU'
        Key        = 'Software\Microsoft\Narrator\NoRoam'
        Value      = 'ImageDescriptionsEnabled'
        Cleanup    = $true
    },
    @{
        Id         = 'AI.Search.DisableSearchBoxSuggestions.Search'
        RetiredIn  = 'v2.14.1'
        Reason     = 'Microsoft documents this value under ...\Explorer only'
        ReplacedBy = @('AI.Search.DisableSearchBoxSuggestions.Explorer')
        Kind       = 'Registry'
        Hive       = 'HKLM'
        Key        = 'SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Value      = 'DisableSearchBoxSuggestions'
        Cleanup    = $true
    },
    @{
        Id         = 'AI.Notepad.DisableAIFeatures.Notepad'
        RetiredIn  = 'v2.14.1'
        Reason     = 'no source uses the Microsoft\Notepad key; the documented policy is under WindowsNotepad'
        ReplacedBy = @('AI.Notepad.DisableAIFeatures.WindowsNotepad')
        Kind       = 'Registry'
        Hive       = 'HKLM'
        Key        = 'SOFTWARE\Policies\Microsoft\Notepad'
        Value      = 'DisableAIFeatures'
        Cleanup    = $true
    },
    @{
        Id         = 'AI.Recall.PurgeDataFolder'
        RetiredIn  = 'v2.14.1'
        Reason     = 'deleted a folder Microsoft does not document; AllowRecallEnablement = 0 is the documented way to delete Recall snapshots'
        ReplacedBy = @('AI.WindowsAI.AllowRecallEnablement')
        Kind       = 'FolderPurge'
        Path       = '%LOCALAPPDATA%\Microsoft\Windows\Recall'
    }
)
