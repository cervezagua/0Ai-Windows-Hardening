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
    }
)
