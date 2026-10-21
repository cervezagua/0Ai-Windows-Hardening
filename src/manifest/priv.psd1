#
# 0AI v2.3 manifest: PRIV category - Privacy & telemetry
#
@(

    # ---- [A6] Telemetry minimization ----
    @{
        Id          = 'PRIV.Service.DiagTrack'
        Category    = 'PRIV'
        Group       = 'sc-safe'
        Description = 'Stop and disable Connected User Experiences and Telemetry (DiagTrack)'
        MinBuild    = 0
        Kind        = 'Service'
        Name        = 'DiagTrack'
        State       = 'Stopped'
        StartupType = 'Disabled'
        DocUrl      = 'https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Service.dmwappushservice'
        Category    = 'PRIV'
        Group       = 'sc-safe'
        Description = 'Stop and disable dmwappushservice (WAP push)'
        MinBuild    = 0
        Kind        = 'Service'
        Name        = 'dmwappushservice'
        State       = 'Stopped'
        StartupType = 'Disabled'
        DocUrl      = 'https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Telemetry.AllowTelemetry.DataCollection'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'AllowTelemetry=0 (Pro/Home silently clamp to 1; Enterprise honors)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection'
        Value       = 'AllowTelemetry'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Telemetry.AllowTelemetry.PoliciesDataCollection'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'AllowTelemetry=0 (Policies mirror)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        Value       = 'AllowTelemetry'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Siuf.NumberOfSIUFInPeriod'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable feedback (SIUF) survey frequency'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Siuf\Rules'
        Value       = 'NumberOfSIUFInPeriod'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Siuf.PeriodInNanoSeconds'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Zero SIUF survey period'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Siuf\Rules'
        Value       = 'PeriodInNanoSeconds'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A9] Advertising ID ----
    @{
        Id          = 'PRIV.AdvertisingInfo.DisabledByGroupPolicy'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Advertising ID disabled by group policy (machine)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo'
        Value       = 'DisabledByGroupPolicy'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.AdvertisingInfo.Enabled.HKCU'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Advertising ID disabled (user)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo'
        Value       = 'Enabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A10] Windows Error Reporting ----
    @{
        Id          = 'PRIV.WER.Disabled.Policy'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable Windows Error Reporting (policy)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'
        Value       = 'Disabled'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-errorreporting'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.WER.Disabled.System'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable Windows Error Reporting (system mirror)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Microsoft\Windows\Windows Error Reporting'
        Value       = 'Disabled'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-errorreporting'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Service.WerSvc'
        Category    = 'PRIV'
        Group       = 'sc-safe'
        Description = 'Stop and disable Windows Error Reporting service (WerSvc)'
        MinBuild    = 0
        Kind        = 'Service'
        Name        = 'WerSvc'
        State       = 'Stopped'
        StartupType = 'Disabled'
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-errorreporting'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A11] Activity history + cross-device clipboard ----
    @{
        Id          = 'PRIV.System.EnableActivityFeed'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable Activity Feed'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\System'
        Value       = 'EnableActivityFeed'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.System.PublishUserActivities'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable publishing user activities'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\System'
        Value       = 'PublishUserActivities'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.System.UploadUserActivities'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable uploading user activities'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\System'
        Value       = 'UploadUserActivities'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.System.AllowCrossDeviceClipboard'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable cross-device clipboard'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\System'
        Value       = 'AllowCrossDeviceClipboard'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A20] Online Speech Recognition ----
    @{
        Id          = 'PRIV.Speech.AllowInputPersonalization'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable online speech recognition / input personalization (policy)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\InputPersonalization'
        Value       = 'AllowInputPersonalization'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Speech.OnlineSpeechPrivacy.HasAccepted'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Clear OnlineSpeechPrivacy HasAccepted flag (user)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy'
        Value       = 'HasAccepted'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A21] Cloud Content / Consumer Features ----
    @{
        Id          = 'PRIV.CloudContent.DisableWindowsConsumerFeatures'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable Windows consumer features (Start/Store promoted apps)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Value       = 'DisableWindowsConsumerFeatures'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-cloudcontent'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.CloudContent.DisableSoftLanding'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable soft landing / Windows tips'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Value       = 'DisableSoftLanding'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-cloudcontent'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.CloudContent.DisableWindowsSpotlightFeatures'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable Windows Spotlight features'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Value       = 'DisableWindowsSpotlightFeatures'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-cloudcontent'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.CloudContent.DisableCloudOptimizedContent'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable cloud-optimized content'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Value       = 'DisableCloudOptimizedContent'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-cloudcontent'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.CloudContent.DisableConsumerAccountStateContent'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable consumer account state content'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Value       = 'DisableConsumerAccountStateContent'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-cloudcontent'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A22] Tailored Experiences with Diagnostic Data ----
    @{
        Id          = 'PRIV.CloudContent.DisableTailoredExperiencesWithDiagnosticData'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable tailored experiences that use diagnostic data (policy)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Value       = 'DisableTailoredExperiencesWithDiagnosticData'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-cloudcontent'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Privacy.TailoredExperiencesWithDiagnosticDataEnabled.HKCU'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Tailored experiences with diagnostic data = off (user)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\Privacy'
        Value       = 'TailoredExperiencesWithDiagnosticDataEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-cloudcontent'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A23] Online Tips in Settings ----
    @{
        Id          = 'PRIV.Explorer.AllowOnlineTips'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable online tips in Settings app'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        Value       = 'AllowOnlineTips'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-settings'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A24] Find My Device ----
    @{
        Id          = 'PRIV.FindMyDevice.AllowFindMyDevice'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable Find My Device'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\FindMyDevice'
        Value       = 'AllowFindMyDevice'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-experience'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A25] Feedback notifications ----
    @{
        Id          = 'PRIV.DataCollection.DoNotShowFeedbackNotifications'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Suppress feedback notifications'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\DataCollection'
        Value       = 'DoNotShowFeedbackNotifications'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-feedback'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A14] Sync provider notifications ----
    @{
        Id          = 'PRIV.Explorer.ShowSyncProviderNotifications'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Disable Explorer/OneDrive sync-provider banners'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        Value       = 'ShowSyncProviderNotifications'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-explorer'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [P20] Edge telemetry and recommendations (v2.15.0) ----
    @{
        Id          = 'PRIV.Edge.DiagnosticData'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Edge: send no diagnostic data (0 = off; Microsoft marks this "not recommended" for managed fleets)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'DiagnosticData'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/diagnosticdata'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Edge.PersonalizationReportingEnabled'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Edge: do not send browsing data for ad/news personalisation'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'PersonalizationReportingEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/personalizationreportingenabled'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Edge.ShowRecommendationsEnabled'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Edge: no feature recommendations or assistance notifications'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'ShowRecommendationsEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/showrecommendationsenabled'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Edge.EdgeShoppingAssistantEnabled'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Edge: shopping features off (price comparison, coupons, express checkout)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'EdgeShoppingAssistantEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/edgeshoppingassistantenabled'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Edge.SpotlightExperiencesAndRecommendationsEnabled'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Edge: Spotlight experiences and recommendations off'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Edge'
        Value       = 'SpotlightExperiencesAndRecommendationsEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/deployedge/microsoft-edge-browser-policies/spotlightexperiencesandrecommendationsenabled'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [P21] Desktop Spotlight (v2.15.0) ----
    # Like most CloudContent policies, honoured on Enterprise/Education only.
    @{
        Id          = 'PRIV.CloudContent.DisableSpotlightCollectionOnDesktop'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Turn off Windows Spotlight on the desktop (CloudContent policy; Enterprise/Education only)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Policies\Microsoft\Windows\CloudContent'
        Value       = 'DisableSpotlightCollectionOnDesktop'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-experience'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [P22] Start / Settings / lock-screen suggestions on Home and Pro (v2.15.0) ----
    # The CloudContent policies above are honoured only on Enterprise and
    # Education. On Home and Pro these per-user preferences are what turn the
    # suggestions off. Microsoft uses them in its VDI optimisation sample
    # without documenting each value, hence Community.
    @{
        Id          = 'PRIV.CDM.SubscribedContent-338388Enabled'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Turn off: Suggestions in Start (ContentDeliveryManager preference)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Value       = 'SubscribedContent-338388Enabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/remote-desktop-services-vdi-optimize-configuration'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.CDM.SubscribedContent-338389Enabled'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Turn off: Tips and suggestions while using Windows (preference)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Value       = 'SubscribedContent-338389Enabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/remote-desktop-services-vdi-optimize-configuration'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.CDM.SubscribedContent-338393Enabled'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Turn off: Suggested content in Settings (preference)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Value       = 'SubscribedContent-338393Enabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/remote-desktop-services-vdi-optimize-configuration'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.CDM.SubscribedContent-353694Enabled'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Turn off: Suggested content in Settings (preference)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Value       = 'SubscribedContent-353694Enabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/remote-desktop-services-vdi-optimize-configuration'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.CDM.SubscribedContent-353696Enabled'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Turn off: Suggested content in Settings (preference)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Value       = 'SubscribedContent-353696Enabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/remote-desktop-services-vdi-optimize-configuration'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.CDM.SystemPaneSuggestionsEnabled'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Turn off: Suggestions in Start (preference)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Value       = 'SystemPaneSuggestionsEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/remote-desktop-services-vdi-optimize-configuration'
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.CDM.SilentInstalledAppsEnabled'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Turn off: automatic install of promoted apps (preference; no Microsoft source)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Value       = 'SilentInstalledAppsEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = ''
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.CDM.SoftLandingEnabled'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Turn off: Windows tips notifications (preference; no Microsoft source)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'
        Value       = 'SoftLandingEnabled'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = ''
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Explorer.Start_IrisRecommendations'
        Category    = 'PRIV'
        Group       = 'reg-safe'
        Description = 'Start: no recommendations for tips, shortcuts and new apps (documented user setting)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKCU'
        Key         = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        Value       = 'Start_IrisRecommendations'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/apps/develop/settings/settings-windows-11'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [P23] Customer Experience Improvement Program tasks (v2.15.0) ----
    # Microsoft's VDI optimisation guide describes the first two as CEIP data
    # collection. Not shipped: Microsoft Compatibility Appraiser, which also
    # feeds Windows Update's upgrade-compatibility checks.
    @{
        Id          = 'PRIV.Task.CEIP.Consolidator'
        Category    = 'PRIV'
        Group       = 'task'
        Description = 'Disable the CEIP Consolidator task (sends usage data if CEIP consent was given)'
        MinBuild    = 0
        Kind        = 'ScheduledTask'
        TaskPath    = '\Microsoft\Windows\Customer Experience Improvement Program\'
        TaskName    = 'Consolidator'
        DocUrl      = 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/remote-desktop-services-vdi-optimize-configuration'
        Confidence  = 'BestEffort'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Task.DiskDiagnosticDataCollector'
        Category    = 'PRIV'
        Group       = 'task'
        Description = 'Disable the disk diagnostic data collector task (reports disk/system info to Microsoft under CEIP)'
        MinBuild    = 0
        Kind        = 'ScheduledTask'
        TaskPath    = '\Microsoft\Windows\DiskDiagnostic\'
        TaskName    = 'Microsoft-Windows-DiskDiagnosticDataCollector'
        DocUrl      = 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/remote-desktop-services-vdi-optimize-configuration'
        Confidence  = 'BestEffort'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'PRIV.Task.CEIP.UsbCeip'
        Category    = 'PRIV'
        Group       = 'task'
        Description = 'Disable the CEIP UsbCeip task (USB usage data; no Microsoft description)'
        MinBuild    = 0
        Kind        = 'ScheduledTask'
        TaskPath    = '\Microsoft\Windows\Customer Experience Improvement Program\'
        TaskName    = 'UsbCeip'
        DocUrl      = ''
        Confidence  = 'Community'
        Reversible  = $true
        Destructive = $false
    }
)
