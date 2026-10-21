#
# 0AI v2.3 manifest: AI category
#
# Every policy in this file disables an AI surface in Windows / Store apps.
#
# Confidence says where each registry name comes from - keep it honest:
#   Documented  in Microsoft's policy reference, at the scope (HKLM = Device,
#               HKCU = User) Microsoft documents for it
#   BestEffort  real value, but written at a scope Microsoft does not document
#               (a mirror kept for coverage) - may be ignored by Windows
#   Community   the registry name OR the data written comes only from
#               third-party sources (DocUrl empty = no source found)
# Every entry re-audited against Microsoft sources in v2.14.0. v2.14.1 retired
# seven entries that had no working source (see src\retired\retired.psd1).
#
@(

    # ---- [A1] Windows Copilot (shell integration) ----
    @{
        Id          = 'AI.WindowsCopilot.TurnOffWindowsCopilot.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Turn off Windows Copilot (HKCU, documented scope; deprecated by Microsoft)'
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
        Description = 'Turn off Windows Copilot (HKLM mirror, best-effort; documented scope is HKCU only)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'
        Value       = 'TurnOffWindowsCopilot'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'BestEffort'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A1a] Remove Copilot app (25H2+, Pro/Enterprise/Education) ----
    # The WindowsAI CSP documents this at both Device (HKLM) and User (HKCU)
    # scope, so both entries are Documented. Its edition table says not Pro
    # while its text says Professional applies - Microsoft contradicts itself;
    # on an edition that ignores it the write is a harmless no-op. Also blocks
    # the dockable Copilot sidebar rolling out since May 2026.
    @{
        Id          = 'AI.WindowsCopilot.RemoveMicrosoftCopilotApp.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Remove Microsoft Copilot app (HKCU, documented scope; uninstalls if unused 28 days)'
        MinBuild    = 26200
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'RemoveMicrosoftCopilotApp'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.WindowsCopilot.RemoveMicrosoftCopilotApp.HKLM'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Remove Microsoft Copilot app (HKLM, documented Device scope; uninstalls if unused 28 days)'
        MinBuild    = 26200
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'RemoveMicrosoftCopilotApp'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A1b] Copilot hardware key: strip its AI launch action ----
    # The policy is documented (User scope only, no Device twin), but its
    # documented value is an app AUMID - the app the key should open. "0" is
    # NOT a documented value: third-party guides report it leaves the key
    # inert, plausibly because no app has that AUMID. v2.12.0 shipped this as
    # Documented; corrected to Community in v2.13.0. The supported alternative
    # is Settings > Bluetooth & devices > Keyboard (remap to Right Ctrl).
    @{
        Id          = 'AI.WindowsCopilot.SetCopilotHardwareKey'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Make the Copilot hardware key inert (community value "0"; documented value is an app AUMID)'
        MinBuild    = 26200
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Policies\Microsoft\Windows\CopilotKey'
        Value       = 'SetCopilotHardwareKey'
        Type        = 'String'
        Data        = '0'
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai#setcopilothardwarekey'
        Confidence  = 'Community'
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
        Id          = 'AI.WindowsAI.DisableRecallDataProviders.HKLM'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Recall data providers (HKLM mirror, best-effort; documented scope is HKCU)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'DisableRecallDataProviders'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai'
        Confidence  = 'BestEffort'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.WindowsAI.DisableRecallDataProviders.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Recall data providers (HKCU, documented User scope)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'DisableRecallDataProviders'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai#disablerecalldataproviders'
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

    # ---- [A2a] IsoEnvBroker: experimental agentic features framework ----
    # Microsoft documents the "Experimental agentic features" toggle, but not
    # this service or its Enabled value - both are community-identified. The
    # documented admin control (ConfigureAgentConnectors=2) is Enterprise-only
    # and Insider-only as of Oct 2026, so it is not shipped yet.
    @{
        Id          = 'AI.IsoEnvBroker.Enabled'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable experimental agentic features broker (IsoEnvBroker)'
        MinBuild    = 26200
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SYSTEM\CurrentControlSet\Services\IsoEnvBroker'
        Value       = 'Enabled'
        # Only where the service exists: otherwise this would create a
        # service key for a service that is not installed.
        RequiresService = 'IsoEnvBroker'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://support.microsoft.com/windows/experimental-agentic-features-a25ede8a-e4c2-4841-85a8-44839191dfb3'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Service.IsoEnvBroker'
        Category    = 'AI'
        Group       = 'sc-safe'
        Description = 'Stop and disable IsoEnvBroker (agentic features broker service)'
        MinBuild    = 26200
        Kind        = 'Service'
        Name        = 'IsoEnvBroker'
        State       = 'Stopped'
        StartupType = 'Disabled'
        DocUrl      = 'https://support.microsoft.com/windows/experimental-agentic-features-a25ede8a-e4c2-4841-85a8-44839191dfb3'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A4] Classic local-only search ----
    @{
        Id          = 'AI.Search.DisableSearchBoxSuggestions.Explorer'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable web search box suggestions (HKLM mirror, best-effort; documented scope is HKCU)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Value       = 'DisableSearchBoxSuggestions'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-windowsexplorer'
        Confidence  = 'BestEffort'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Search.DisableSearchBoxSuggestions.Explorer.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable web/Bing + Store search suggestions (HKCU, documented User scope)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Policies\Microsoft\Windows\Explorer'
        Value       = 'DisableSearchBoxSuggestions'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-admx-windowsexplorer'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Search.BingSearchEnabled'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Bing search in user search box (community value; documented route is ConnectedSearchUseWeb)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\Search'
        Value       = 'BingSearchEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Search.CortanaConsent'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Clear Cortana consent flag (community value)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\Search'
        Value       = 'CortanaConsent'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A5] Suggested Actions + Input Personalization ----
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
        DocUrl      = 'https://learn.microsoft.com/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services'
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
        DocUrl      = 'https://learn.microsoft.com/windows/privacy/manage-connections-from-windows-operating-system-components-to-microsoft-services'
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
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/hubssidebarenabled'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A16] File Explorer AI Actions context menu ----
    @{
        Id          = 'AI.Explorer.HideAIActionsMenu.HKLM'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Hide File Explorer AI Actions menu (HKLM; community value, not in Microsoft docs, effect unverified on any build)'
        MinBuild    = 26200
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\Explorer'
        Value       = 'HideAIActionsMenu'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = ''
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Explorer.HideAIActionsMenu.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Hide File Explorer AI Actions menu (HKCU; community value, not in Microsoft docs, effect unverified on any build)'
        MinBuild    = 26200
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Policies\Microsoft\Windows\Explorer'
        Value       = 'HideAIActionsMenu'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = ''
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A16a] "Ask Copilot" File Explorer context / hover shell extension ----
    # KB5101650 (July 2026) surfaced "Ask Copilot" as a File Explorer Home
    # hover action; the same Copilot shell extension also owns the right-click
    # "Ask Copilot" verb (present since 2025). Block the packaged-COM handler
    # by CLSID via the per-user Shell Extensions "Blocked" list.
    #
    # HKCU ONLY (by design). v2.9 also shipped an HKLM twin, but writing a
    # CLSID into the *machine-wide* HKLM\...\Shell Extensions\Blocked list is
    # a recognized defense-evasion technique (MITRE T1112 - disabling shell /
    # security extensions). Bitdefender's tamper / registry-guard module
    # intercepts it: the HKLM write was denied ("unauthorized operation") and
    # the whole apply run was flagged as malware. The per-user HKCU write is
    # not guarded that way and succeeds. It also matches the kit's threat
    # model (no aggressive / undocumented machine-wide techniques). Copilot's
    # removal at the source is handled by RemoveMicrosoftCopilotApp (documented).
    # Community-identified CLSID, reversible.
    @{
        Id          = 'AI.Explorer.BlockAskCopilotShellExt.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Block "Ask Copilot" File Explorer shell extension by CLSID (HKCU)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked'
        Value       = '{CB3B0003-8088-4EDE-8769-8B354AB2FF8C}'
        Type        = 'String'
        Data        = 'Ask Copilot'
        DocUrl      = 'https://learn.microsoft.com/windows/win32/shell/reg-shell-exts'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [B1] Notepad AI (HKLM Notepad namespace) ----
    @{
        Id          = 'AI.Notepad.DisableAIFeatures.WindowsNotepad'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Notepad AI features (HKLM WindowsNotepad, documented machine policy)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\WindowsNotepad'
        Value       = 'DisableAIFeatures'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/manage-notepad'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [B5] Notepad AI (HKCU user-scope) ----
    @{
        Id          = 'AI.Notepad.DisableAIFeatures.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Notepad AI features (HKCU mirror, best-effort; documented policy is machine-wide)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Policies\Microsoft\Windows\WindowsNotepad'
        Value       = 'DisableAIFeatures'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/manage-notepad'
        Confidence  = 'BestEffort'
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
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai#disablecocreator'
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
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai#disablegenerativefill'
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
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai#disableimagecreator'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [B3] systemAIModels capability = Deny ----
    @{
        Id          = 'AI.Capability.systemAIModels.HKLM'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'systemAIModels capability access = Deny (machine; community ConsentStore value)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels'
        Value       = 'Value'
        Type        = 'String'
        Data        = 'Deny'
        DocUrl      = 'https://learn.microsoft.com/windows/ai/apis/get-started'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Capability.systemAIModels.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'systemAIModels capability access = Deny (user; community ConsentStore value)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels'
        Value       = 'Value'
        Type        = 'String'
        Data        = 'Deny'
        DocUrl      = 'https://learn.microsoft.com/windows/ai/apis/get-started'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A8a] Edge AI features (v2.15.0; Microsoft Edge policy reference) ----
    # Entra-only ones affect work/school (Entra ID) Edge profiles, not personal
    # Microsoft accounts; they are harmless elsewhere.
    @{
        Id          = 'AI.Edge.CopilotPageContext'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Edge: Copilot cannot read page content (work/school Entra profiles only; Edge 124+)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'CopilotPageContext'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/copilotpagecontext'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Edge.Microsoft365CopilotChatIconEnabled'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Edge: hide the Microsoft 365 Copilot icon in the toolbar (Entra profiles only; Edge 139+)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'Microsoft365CopilotChatIconEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/microsoft365copilotchaticonenabled'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Edge.EdgeEntraCopilotPageContext'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Edge: Copilot cannot use page content, history or video transcripts (Entra profiles only; Edge 130+)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'EdgeEntraCopilotPageContext'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/edgeentracopilotpagecontext'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Edge.ComposeInlineEnabled'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Edge: turn off Microsoft 365 Copilot inline Rewrite help (Entra profiles only; Edge 115+)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'ComposeInlineEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/composeinlineenabled'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Edge.EdgeHistoryAISearchEnabled'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Edge: AI-powered history search off, exact-match only (Edge 138+)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'EdgeHistoryAISearchEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/edgehistoryaisearchenabled'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Edge.NewTabPageBingChatEnabled'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Edge: remove Bing Chat / Copilot entry points from the new tab page (Edge 117+)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'NewTabPageBingChatEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/newtabpagebingchatenabled'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.Edge.GenAILocalFoundationalModelSettings'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Edge: do not download the on-device GenAI model, delete any existing copy (all profiles; Edge 132+)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'GenAILocalFoundationalModelSettings'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/genailocalfoundationalmodelsettings'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A2b] Recall / Click to Do at user scope (v2.15.0) ----
    # The WindowsAI CSP documents both Device and User scope for these.
    @{
        Id          = 'AI.WindowsAI.DisableAIDataAnalysis.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable saving Recall snapshots for this user (user scope of DisableAIDataAnalysis)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'DisableAIDataAnalysis'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/manage-recall'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'AI.WindowsAI.DisableClickToDo.HKCU'
        Category    = 'AI'
        Group       = 'reg-safe'
        Description = 'Disable Click to Do for this user (user scope; Copilot+ PCs)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Policies\Microsoft\Windows\WindowsAI'
        Value       = 'DisableClickToDo'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/manage-click-to-do'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    }
)
