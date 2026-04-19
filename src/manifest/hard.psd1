#
# 0AI v2.3 manifest: HARD category - Security hardening
#
@(

    # ---- [A13] Disable RDP service ----
    @{
        Id          = 'HARD.RDP.fDenyTSConnections'
        Category    = 'HARD'
        Group       = 'reg-safe'
        Description = 'Deny Terminal Services connections'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SYSTEM\CurrentControlSet\Control\Terminal Server'
        Value       = 'fDenyTSConnections'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-remotedesktopservices'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'HARD.Service.TermService'
        Category    = 'HARD'
        Group       = 'sc-safe'
        Description = 'Stop and disable Remote Desktop Services (TermService)'
        MinBuild    = 0
        Kind        = 'Service'
        Name        = 'TermService'
        State       = 'Stopped'
        StartupType = 'Disabled'
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-remotedesktopservices'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [A17] RDP client hardening ----
    @{
        Id          = 'HARD.TerminalServices.DisablePasswordSaving'
        Category    = 'HARD'
        Group       = 'reg-safe'
        Description = 'Do not allow passwords to be saved (Terminal Services client GP)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
        Value       = 'DisablePasswordSaving'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows/client-management/mdm/policy-csp-remotedesktopservices'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'HARD.CredentialsDelegation.RestrictedRemoteAdministration'
        Category    = 'HARD'
        Group       = 'reg-safe'
        Description = 'Require Restricted Admin for RDP client'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
        Value       = 'RestrictedRemoteAdministration'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'HARD.CredentialsDelegation.RestrictedRemoteAdministrationType'
        Category    = 'HARD'
        Group       = 'reg-safe'
        Description = 'Restricted Admin type = Restricted Admin (1)'
        MinBuild    = 0
        Kind        = 'Registry'
        Hive        = 'HKLM'
        Key         = 'SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
        Value       = 'RestrictedRemoteAdministrationType'
        Type        = 'DWord'
        Data        = 1
        DocUrl      = 'https://learn.microsoft.com/windows-server/remote/remote-desktop-services/clients/remote-desktop-allow-access'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [C1] Defender PUA Protection ----
    @{
        Id          = 'HARD.Defender.PUAProtection'
        Category    = 'HARD'
        Group       = 'defender'
        Description = 'Defender PUA Protection = Block'
        MinBuild    = 0
        Kind        = 'DefenderPref'
        Preference  = 'PUAProtection'
        Value       = 2
        DocUrl      = 'https://learn.microsoft.com/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [C2] Defender ASR subset ----
    @{
        Id          = 'HARD.Defender.ASR.BlockExecutableContentFromEmail'
        Category    = 'HARD'
        Group       = 'defender'
        Description = 'ASR: Block executable content from email client and webmail'
        MinBuild    = 0
        Kind        = 'DefenderAsr'
        RuleId      = 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550'
        Action      = 'Enabled'
        DocUrl      = 'https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'HARD.Defender.ASR.BlockOfficeChildProcess'
        Category    = 'HARD'
        Group       = 'defender'
        Description = 'ASR: Block all Office applications from creating child processes'
        MinBuild    = 0
        Kind        = 'DefenderAsr'
        RuleId      = 'd3e037e1-3eb8-44c8-a917-57927947596d'
        Action      = 'Enabled'
        DocUrl      = 'https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'HARD.Defender.ASR.BlockJSVBSDownloadedContent'
        Category    = 'HARD'
        Group       = 'defender'
        Description = 'ASR: Block JavaScript or VBScript from launching downloaded executable content'
        MinBuild    = 0
        Kind        = 'DefenderAsr'
        RuleId      = '5beb7efe-fd9a-4556-801d-275e5ffc04cc'
        Action      = 'Enabled'
        DocUrl      = 'https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'HARD.Defender.ASR.BlockObfuscatedScripts'
        Category    = 'HARD'
        Group       = 'defender'
        Description = 'ASR: Block execution of potentially obfuscated scripts'
        MinBuild    = 0
        Kind        = 'DefenderAsr'
        RuleId      = '9e6ea88d-6e13-4ec2-b7e2-5b56f6b457ff'
        Action      = 'Enabled'
        DocUrl      = 'https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'HARD.Defender.ASR.BlockUntrustedUnsignedProcessesUSB'
        Category    = 'HARD'
        Group       = 'defender'
        Description = 'ASR: Block untrusted and unsigned processes that run from USB'
        MinBuild    = 0
        Kind        = 'DefenderAsr'
        RuleId      = 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
        Action      = 'Enabled'
        DocUrl      = 'https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'HARD.Defender.ASR.BlockOfficeAppInjection'
        Category    = 'HARD'
        Group       = 'defender'
        Description = 'ASR: Block Office applications from injecting code into other processes'
        MinBuild    = 0
        Kind        = 'DefenderAsr'
        RuleId      = 'd1e49aac-8f56-4280-b9ba-993a6d77406c'
        Action      = 'Enabled'
        DocUrl      = 'https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },
    @{
        Id          = 'HARD.Defender.ASR.BlockCredStealingLsass'
        Category    = 'HARD'
        Group       = 'defender'
        Description = 'ASR: Block credential stealing from lsass.exe'
        MinBuild    = 0
        Kind        = 'DefenderAsr'
        RuleId      = 'c1db55ab-c21a-4637-bb3f-a12568109d35'
        Action      = 'Enabled'
        DocUrl      = 'https://learn.microsoft.com/defender-endpoint/attack-surface-reduction-rules-reference'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    },

    # ---- [C3] Exploit Protection ----
    @{
        Id          = 'HARD.Mitigation.System'
        Category    = 'HARD'
        Group       = 'mitigation'
        Description = 'System-wide exploit mitigations (DEP/SEHOP/BottomUp/HighEntropy)'
        MinBuild    = 0
        Kind        = 'Mitigation'
        Enable      = @('DEP', 'BottomUp', 'HighEntropy', 'SEHOP')
        Disable     = @()
        DocUrl      = 'https://learn.microsoft.com/defender-endpoint/exploit-protection-reference'
        Confidence  = 'Documented'
        Reversible  = $true
        Destructive = $false
    }
)
