#
# 0AI v2.3 manifest: AUDIT category - Read-only state reports
# None of these policies change state.
#
@(

    # ---- [A19] Microsoft.Windows.AI.* component snapshot ----
    @{
        Id          = 'AUDIT.AI.ComponentSnapshot'
        Category    = 'AUDIT'
        Group       = 'report'
        Description = 'Snapshot Microsoft.Windows.AI.* Appx component versions'
        MinBuild    = 0
        Kind        = 'Report'
        Script      = 'try { Get-AppxPackage Microsoft.Windows.AI.* -ErrorAction SilentlyContinue | Select-Object Name,Version,PackageFullName } catch { @() }'
        DocUrl      = 'https://learn.microsoft.com/windows/application-management/apps-in-windows-11'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [C4] Smart App Control state ----
    @{
        Id          = 'AUDIT.SmartAppControl.State'
        Category    = 'AUDIT'
        Group       = 'report'
        Description = 'Report Smart App Control state (KB5083769)'
        MinBuild    = 0
        Kind        = 'Report'
        Script      = 'try { Get-MpComputerStatus | Select-Object SmartAppControlState,SmartAppControlExpiration } catch { [pscustomobject]@{ Error = "Get-MpComputerStatus unavailable" } }'
        DocUrl      = 'https://learn.microsoft.com/windows/apps/develop/smart-app-control/overview'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- OS build + UBR ----
    @{
        Id          = 'AUDIT.OS.BuildInfo'
        Category    = 'AUDIT'
        Group       = 'report'
        Description = 'OS build, UBR, display version, product name, edition'
        MinBuild    = 0
        Kind        = 'Report'
        Script      = 'try { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue | Select-Object ProductName,DisplayVersion,CurrentBuild,UBR,EditionID } catch { [pscustomobject]@{ Error = "Unable to read CurrentVersion" } }'
        DocUrl      = 'https://learn.microsoft.com/windows/release-health/'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- Effective telemetry level ----
    @{
        Id          = 'AUDIT.Telemetry.EffectiveLevel'
        Category    = 'AUDIT'
        Group       = 'report'
        Description = 'Effective AllowTelemetry value (SKU-clamped on Pro/Home)'
        MinBuild    = 0
        Kind        = 'Report'
        Script      = 'try { $d = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -ErrorAction SilentlyContinue; [pscustomobject]@{ AllowTelemetry = $d.AllowTelemetry } } catch { [pscustomobject]@{ AllowTelemetry = $null } }'
        DocUrl      = 'https://learn.microsoft.com/windows/privacy/configure-windows-diagnostic-data-in-your-organization'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- SKU ----
    @{
        Id          = 'AUDIT.OS.Sku'
        Category    = 'AUDIT'
        Group       = 'report'
        Description = 'Windows SKU / edition'
        MinBuild    = 0
        Kind        = 'Report'
        Script      = 'try { Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue | Select-Object Caption,OperatingSystemSKU,Version,BuildNumber } catch { [pscustomobject]@{ Error = "CIM unavailable" } }'
        DocUrl      = 'https://learn.microsoft.com/windows/release-health/'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    }
)
