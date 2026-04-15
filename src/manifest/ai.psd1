#
# 0AI v2.3 manifest: AI category
#
# Every policy in this file disables an AI surface in Windows / Store apps.
# Values come verbatim from 0AI_Apply_v2_2.bat (legacy/0AI_Apply_v2_2.bat).
#
@(

    # ---- [A1] Windows Copilot (shell integration) ----
    @{
        Id          = 'AI.WindowsCopilot.TurnOffWindowsCopilot.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Turn off Windows Copilot (HKCU)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Policies\Microsoft\Windows\WindowsCopilot'
        Value       = 'TurnOffWindowsCopilot'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.WindowsCopilot.TurnOffWindowsCopilot.HKLM'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Turn off Windows Copilot (HKLM; Pro SKUs ignore HKCU on 24H2+)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
        Value       = 'TurnOffWindowsCopilot'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A2] WindowsAI: Recall / Click-to-Do / Settings agent ----
    @{
        Id          = 'AI.WindowsAI.AllowRecallEnablement'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Block Recall enablement'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'AllowRecallEnablement'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.WindowsAI.AllowRecallExport'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Block Recall export'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'AllowRecallExport'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.WindowsAI.DisableAIDataAnalysis'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Windows AI data analysis'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'DisableAIDataAnalysis'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.WindowsAI.DisableClickToDo'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Click-to-Do'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'DisableClickToDo'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.WindowsAI.DisableRecallDataProviders'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Recall data providers'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'DisableRecallDataProviders'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.WindowsAI.DisableSettingsAgent'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Settings agent'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'DisableSettingsAgent'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.WindowsAI.DisableSettingsAgenticSearch'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Settings agentic search (25H2)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'DisableSettingsAgenticSearch'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A3] Recall data folder purge ----
    @{
        Id          = 'AI.Recall.PurgeDataFolder'
        Category    = 'AI'
        Group       = 'folder'
        Description = 'Best-effort purge of Recall snapshot folder (destructive)'
        MinBuild    = 0
        Kind        = 'FolderPurge'
        Path        = '%LOCALAPPDATA%\Microsoft\Windows\Recall'
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'Documented'
        Reversible  = $false
        Destructive = $true
    },

    # ---- [A4] Classic local-only search ----
    @{
        Id          = 'AI.Search.DisableSearchBoxSuggestions.Search'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable web/Bing search box suggestions (Windows Search policy)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\Windows Search'
        Value       = 'DisableSearchBoxSuggestions'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Search.DisableSearchBoxSuggestions.Explorer'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable web/Bing search box suggestions (Explorer policy)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Value       = 'DisableSearchBoxSuggestions'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Search.BingSearchEnabled'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Bing search in user search box'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\Search'
        Value       = 'BingSearchEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Search.CortanaConsent'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Clear Cortana consent flag'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\Search'
        Value       = 'CortanaConsent'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A5] Suggested Actions + Input Personalization ----
    @{
        Id          = 'AI.SmartActions.SmartActionsState'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Suggested Actions (SmartActions)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\SmartActions'
        Value       = 'SmartActionsState'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-smartactions'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.InputPersonalization.RestrictImplicitTextCollection'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Restrict implicit text collection'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\InputPersonalization'
        Value       = 'RestrictImplicitTextCollection'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-textinput'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.InputPersonalization.RestrictImplicitInkCollection'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Restrict implicit ink collection'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\InputPersonalization'
        Value       = 'RestrictImplicitInkCollection'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-textinput'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A8] Edge AI surfaces ----
    @{
        Id          = 'AI.Edge.HubsSidebarEnabled'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Edge Hubs / Copilot sidebar'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'HubsSidebarEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-policies'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Edge.DiscoverEnabled'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Edge Discover'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'DiscoverEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-policies'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Edge.EdgeCopilotEnabled'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Edge Copilot'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'EdgeCopilotEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-policies'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A16] File Explorer AI Actions context menu ----
    @{
        Id          = 'AI.Explorer.HideAIActionsMenu.HKLM'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Hide File Explorer AI Actions context menu (HKLM)'
        MinBuild    = 26200
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Value       = 'HideAIActionsMenu'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-explorer'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Explorer.HideAIActionsMenu.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Hide File Explorer AI Actions context menu (HKCU)'
        MinBuild    = 26200
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Policies\Microsoft\Windows\Explorer'
        Value       = 'HideAIActionsMenu'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-explorer'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A18] Narrator rich image descriptions ----
    @{
        Id          = 'AI.Narrator.ImageDescriptionsEnabled'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Narrator cloud-assisted rich image descriptions'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Narrator\NoRoam'
        Value       = 'ImageDescriptionsEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-accessibility'
        Confidence  = 'BestEffort'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [B1] Notepad AI (HKLM Notepad namespace) ----
    @{
        Id          = 'AI.Notepad.DisableAIFeatures.Notepad'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Notepad AI features (HKLM Notepad policy)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Notepad'
        Value       = 'DisableAIFeatures'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-notepad'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Notepad.DisableAIFeatures.WindowsNotepad'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Notepad AI features (HKLM WindowsNotepad policy)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\WindowsNotepad'
        Value       = 'DisableAIFeatures'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-notepad'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [B5] Notepad AI (HKCU user-scope) ----
    @{
        Id          = 'AI.Notepad.DisableAIFeatures.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Notepad AI features (HKCU user-scope)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Policies\Microsoft\Windows\WindowsNotepad'
        Value       = 'DisableAIFeatures'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-notepad'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [B2] Paint AI ----
    @{
        Id          = 'AI.Paint.DisableCocreator'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Paint Cocreator'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint'
        Value       = 'DisableCocreator'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-paint'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Paint.DisableGenerativeFill'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Paint Generative Fill'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint'
        Value       = 'DisableGenerativeFill'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-paint'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Paint.DisableImageCreator'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Paint Image Creator'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint'
        Value       = 'DisableImageCreator'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-paint'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [B3] systemAIModels capability = Deny ----
    @{
        Id          = 'AI.Capability.systemAIModels.HKLM'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'systemAIModels capability access = Deny (machine)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels'
        Value       = 'Value'
        Type        = 'String'
        Data        = 'Deny'
        DocUrl      = 'https://learn.microsoft.com/windows/privacy/manage-windows-1809-endpoints'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Capability.systemAIModels.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'systemAIModels capability access = Deny (user)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels'
        Value       = 'Value'
        Type        = 'String'
        Data        = 'Deny'
        DocUrl      = 'https://learn.microsoft.com/windows/privacy/manage-windows-1809-endpoints'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    }
)
