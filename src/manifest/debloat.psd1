#
# 0AI v2.3 manifest: DEBLOAT category - Destructive Appx removal
# NOT run by default. Requires explicit -Categories DEBLOAT.
#
@(

    # ---- [A7] Widgets / WebExperience ----
    @{
        Id          = 'DEBLOAT.Appx.WebExperience'
        Category    = 'DEBLOAT'
        Group       = 'appx'
        Description = 'Remove Widgets / WebExperience Appx package (installed + provisioned)'
        MinBuild    = 0
        Kind        = 'AppxRemove'
        NamePattern = 'WebExperience'
        AllUsers    = $true
        Provisioned = $true
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-newsandinterests'
        Confidence  = 'Documented'
        Reversible  = $false
        Destructive = $true
    },
    @{
        Id          = 'DEBLOAT.Dsh.AllowNewsAndInterests'
        Category    = 'DEBLOAT'
        Group       = 'reg-safe'
        Description = 'Policy: block News and Interests (Dsh)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Dsh'
        Value       = 'AllowNewsAndInterests'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-newsandinterests'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'DEBLOAT.Dsh.AllowWidgets'
        Category    = 'DEBLOAT'
        Group       = 'reg-safe'
        Description = 'Policy: block Widgets (Dsh)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Dsh'
        Value       = 'AllowWidgets'
        Type        = 'DWord'
        Data        = 0
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-newsandinterests'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A15] Phone Link / YourPhone / CrossDevice ----
    @{
        Id          = 'DEBLOAT.Appx.PhoneLinkCrossDevice'
        Category    = 'DEBLOAT'
        Group       = 'appx'
        Description = 'Remove Phone Link / YourPhone / CrossDevice Appx packages'
        MinBuild    = 0
        Kind        = 'AppxRemove'
        NamePattern = 'YourPhone|PhoneLink|CrossDevice'
        AllUsers    = $true
        Provisioned = $true
        DocUrl      = 'https://learn.microsoft.com/windows/application-management/apps-in-windows-11'
        Confidence  = 'Documented'
        Reversible  = $false
        Destructive = $true
    }
)
