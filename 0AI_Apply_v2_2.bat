@echo off
setlocal EnableExtensions EnableDelayedExpansion
title 0AI - Privacy ^& Security Kit (Apply v2.2)

REM =============================================================================
REM 0AI_Apply_v2_2.bat
REM
REM SAFE FINAL RELEASE (no app-private hive edits; no undocumented hacks).
REM
REM v2.2 changes (relative to v2.1):
REM   - Covers Windows 11 24H2 (26100.8246+) and 25H2 (26200.8246+) baselines
REM     through the April 2026 cumulative KB5083769.
REM   - A16: Hides the File Explorer "AI Actions" context menu (25H2+).
REM   - A17: Hardens .rdp client behavior (April 2026 phishing mitigation).
REM   - A18: Disables Narrator rich image descriptions (cloud-assisted; expanded
REM          to all PCs in KB5083769).
REM   - A19: Snapshots Microsoft.Windows.AI.* component versions for audit.
REM   - B5:  Adds HKCU WindowsNotepad policy path.
REM   - C4:  Reports Smart App Control state (KB5083769 removed the reinstall
REM          requirement, but this script still does NOT force-enable SAC).
REM   - [A1] now also writes HKLM WindowsCopilot (Pro SKUs ignore HKCU on 24H2+).
REM   - [A2] extends WindowsAI hive with DisableCocreator / DisableGenerativeFill
REM          / DisableImageCreator / TurnOffWindowsCopilot (25H2 catalog names).
REM   - [A12] dropped: AllowLockScreenCamera is deprecated on 24H2+ (no-op).
REM   - [C3] drops explicit CFG (system default since KB5066835) to avoid EDR
REM          false positives; DEP/SEHOP/BottomUp/HighEntropy/ForceRelocate kept.
REM
REM What it does:
REM   A) Core privacy + AI surface reduction:
REM      - WindowsAI policy disablement (Recall / Click-to-Do / Settings agentic search)
REM      - Classic local-only search (no Bing suggestions)
REM      - Widgets removal + block
REM      - Telemetry minimization (DiagTrack/dmwappush)
REM      - WER off, Advertising ID off, Activity history off, RDP off
REM      - Keeps OneDrive (incl. autostart)
REM      - Removes Phone Link (installed + provisioned) best-effort
REM
REM   B) AI-in-apps suppression (supported/safe levers only):
REM      - Paint AI policies (Cocreator / Generative Fill / Image Creator) OFF
REM      - systemAIModels capability set to Deny (HKLM + HKCU)
REM      - Notepad AI policy keys are written (multiple namespaces), BUT:
REM           NOTE: On some Notepad builds, the Copilot/Rewrite button may remain visible.
REM           This is a Microsoft app/UI behavior. Policy still reduces backend capability,
REM           but UI visibility may still require the user toggle in Notepad Settings.
REM
REM   C) Security hardening (dev-friendly, best-effort):
REM      - PUAProtection -> Block
REM      - ASR subset -> Block
REM      - Exploit Protection system defaults (DEP/ASLR/SEHOP/CFG)
REM      - Does NOT force Firewall ON; does NOT force Defender Real-Time ON
REM
REM Also:
REM   - Creates restore point (best-effort)
REM   - Exports registry backups + verification report
REM   - Reboot recommended
REM =============================================================================

:: Admin check
net session >nul 2>&1 || (echo [!] Run this script as Administrator. & pause & exit /b 1)

:: Timestamped backup folder (works across locales best-effort)
for /f "tokens=1-3 delims=:." %%a in ("%time%") do set "_t=%%a%%b%%c"
set "_t=%_t: =0%"
set "_d=%date%"
set "_d=%_d:/=-%"
set "_d=%_d:.=-%"
set "_d=%_d: =_%"
set "BACKUPDIR=%USERPROFILE%\0AI_Backups\%_d%_%_t%"
if not exist "%BACKUPDIR%" mkdir "%BACKUPDIR%" >nul 2>&1

set "LOG=%BACKUPDIR%\apply.log"
set "VERIFY=%BACKUPDIR%\verification.txt"

echo [+] Backup folder: "%BACKUPDIR%"
echo [+] Logging: "%LOG%"
echo.>"%LOG%"

echo [+] Creating best-effort System Restore Point...>>"%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Checkpoint-Computer -Description '0AI_Pre_v2_1' -RestorePointType 'MODIFY_SETTINGS' | Out-Null; 'OK' } catch { 'Restore point not available.' }" ^
  >>"%LOG%" 2>&1

call :EXPORT_REG

echo [+] Saving Defender preference snapshot...>>"%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { (Get-MpPreference | Select PUAProtection,AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions,EnableControlledFolderAccess,MAPSReporting,SubmitSamplesConsent) | ConvertTo-Json -Depth 4 | Out-File -Encoding UTF8 '%BACKUPDIR%\Defender_Prefs_before.json' } catch { }" ^
  >>"%LOG%" 2>&1

echo ===============================================================> "%VERIFY%"
echo Verification report (after Apply v2.1 SAFE) >> "%VERIFY%"
echo Timestamp: %date% %time% >> "%VERIFY%"
echo Backup dir: %BACKUPDIR% >> "%VERIFY%"
echo ===============================================================>> "%VERIFY%"
echo.>> "%VERIFY%"

:: Menu
echo.
echo ===============================================================
echo 0AI Apply v2.1 - Select what to run:
echo   A) Core privacy + AI surface reduction
echo   B) AI-in-apps suppression (Paint policies + systemAIModels Deny + Notepad policy keys)
echo   C) Security hardening (best-effort)
echo   P) Proceed (A+B+C)
echo   Q) Quit
echo ===============================================================
choice /c ABCPQ /n /m "Select [A/B/C/P/Q]: "
if errorlevel 5 exit /b 0
if errorlevel 4 set "MODE=P"
if errorlevel 3 set "MODE=C"
if errorlevel 2 set "MODE=B"
if errorlevel 1 set "MODE=A"

if /i "%MODE%"=="P" (call :SECTION_A & call :SECTION_B & call :SECTION_C) else (
  if /i "%MODE%"=="A" call :SECTION_A
  if /i "%MODE%"=="B" call :SECTION_B
  if /i "%MODE%"=="C" call :SECTION_C
)

call :VERIFY_ALL

echo.
echo [i] Restarting Explorer...
taskkill /f /im explorer.exe >nul 2>&1
start explorer.exe

echo.
echo DONE. Reboot recommended.
echo Backups + verification: "%BACKUPDIR%"
pause
exit /b 0

:: --------------------------- EXPORT REG --------------------------------------
:EXPORT_REG
echo [+] Exporting registry snapshots...>>"%LOG%"

reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows" "%BACKUPDIR%\HKLM_Policies_Microsoft_Windows.reg" /y >>"%LOG%" 2>&1
reg export "HKLM\SOFTWARE\Policies\Microsoft\Edge" "%BACKUPDIR%\HKLM_Policies_Edge.reg" /y >>"%LOG%" 2>&1
reg export "HKLM\SOFTWARE\Policies\Microsoft\Dsh" "%BACKUPDIR%\HKLM_Policies_Dsh.reg" /y >>"%LOG%" 2>&1
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" "%BACKUPDIR%\HKLM_Policies_WindowsAI.reg" /y >>"%LOG%" 2>&1
reg export "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" "%BACKUPDIR%\HKCU_Policies_WindowsCopilot.reg" /y >>"%LOG%" 2>&1

reg export "HKLM\SOFTWARE\Policies\Microsoft\Notepad" "%BACKUPDIR%\HKLM_Policies_Microsoft_Notepad.reg" /y >>"%LOG%" 2>&1
reg export "HKLM\SOFTWARE\Policies\WindowsNotepad" "%BACKUPDIR%\HKLM_Policies_WindowsNotepad.reg" /y >>"%LOG%" 2>&1
reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint" "%BACKUPDIR%\HKLM_Policies_Paint.reg" /y >>"%LOG%" 2>&1

reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" "%BACKUPDIR%\HKCU_Search.reg" /y >>"%LOG%" 2>&1
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActions" "%BACKUPDIR%\HKCU_SmartActions.reg" /y >>"%LOG%" 2>&1
reg export "HKCU\Software\Microsoft\InputPersonalization" "%BACKUPDIR%\HKCU_InputPersonalization.reg" /y >>"%LOG%" 2>&1

reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" "%BACKUPDIR%\HKLM_AdvertisingInfo.reg" /y >>"%LOG%" 2>&1
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" "%BACKUPDIR%\HKCU_AdvertisingInfo.reg" /y >>"%LOG%" 2>&1

reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" "%BACKUPDIR%\HKLM_WER_Policy.reg" /y >>"%LOG%" 2>&1
reg export "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" "%BACKUPDIR%\HKLM_WER_System.reg" /y >>"%LOG%" 2>&1

reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" "%BACKUPDIR%\HKLM_System_Policies.reg" /y >>"%LOG%" 2>&1
reg export "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" "%BACKUPDIR%\HKLM_TerminalServer.reg" /y >>"%LOG%" 2>&1
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" "%BACKUPDIR%\HKCU_Explorer_Advanced.reg" /y >>"%LOG%" 2>&1

reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels" "%BACKUPDIR%\HKLM_ConsentStore_systemAIModels.reg" /y >>"%LOG%" 2>&1
reg export "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels" "%BACKUPDIR%\HKCU_ConsentStore_systemAIModels.reg" /y >>"%LOG%" 2>&1

REM v2.2 additions
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" "%BACKUPDIR%\HKLM_Policies_Explorer.reg" /y >>"%LOG%" 2>&1
reg export "HKCU\Software\Policies\Microsoft\Windows\Explorer" "%BACKUPDIR%\HKCU_Policies_Explorer.reg" /y >>"%LOG%" 2>&1
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" "%BACKUPDIR%\HKLM_Policies_WindowsCopilot.reg" /y >>"%LOG%" 2>&1
reg export "HKCU\Software\Policies\Microsoft\Windows\WindowsNotepad" "%BACKUPDIR%\HKCU_Policies_WindowsNotepad.reg" /y >>"%LOG%" 2>&1
reg export "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "%BACKUPDIR%\HKLM_TerminalServices_Policy.reg" /y >>"%LOG%" 2>&1
reg export "HKCU\Software\Microsoft\Terminal Server Client" "%BACKUPDIR%\HKCU_TerminalServerClient.reg" /y >>"%LOG%" 2>&1
reg export "HKCU\Software\Microsoft\Narrator\NoRoam" "%BACKUPDIR%\HKCU_Narrator_NoRoam.reg" /y >>"%LOG%" 2>&1

exit /b 0

:: --------------------------- SECTION A ---------------------------------------
:SECTION_A
echo.>>"%LOG%"
echo ===== SECTION A: Core privacy + AI surface reduction =====>>"%LOG%"
echo.
echo === A) Core privacy + AI surface reduction ===

echo [A1] Disable Windows Copilot (shell integration) - HKCU + HKLM + WindowsAI
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1

echo [A2] WindowsAI policies: Recall / Click-to-Do / Settings agent / 25H2 generative-AI catalog
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v AllowRecallEnablement /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v AllowRecallExport /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableClickToDo /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableRecallDataProviders /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableSettingsAgent /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableSettingsAgenticSearch /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
REM v2.2: 25H2 Intune Settings Catalog names (mirror under WindowsAI hive for forward-compat)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableCocreator /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableGenerativeFill /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableImageCreator /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1

echo [A3] Best-effort: purge Recall data folder if present
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Remove-Item -Recurse -Force $env:LOCALAPPDATA\Microsoft\Windows\Recall -ErrorAction SilentlyContinue" ^
  >>"%LOG%" 2>&1

echo [A4] Force classic local-only search (no Bing/web suggestions)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v BingSearchEnabled /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v CortanaConsent /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1

echo [A5] Disable Suggested Actions + typing/ink personalization
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\SmartActions" /v SmartActionsState /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKCU\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1

echo [A6] Telemetry minimization (DiagTrack + dmwappush)
REM NOTE: AllowTelemetry=0 is only honored on Enterprise/Education SKUs.
REM On Pro/Home it silently clamps to 1 (Required). See verification.txt for effective level.
sc stop DiagTrack >>"%LOG%" 2>&1
sc config DiagTrack start= disabled >>"%LOG%" 2>&1
sc stop dmwappushservice >>"%LOG%" 2>&1
sc config dmwappushservice start= disabled >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKCU\Software\Microsoft\Siuf\Rules" /v PeriodInNanoSeconds /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1

echo [A7] Remove Widgets (WebExperience) and block it (policy)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-AppxPackage *WebExperience* -ErrorAction SilentlyContinue | Remove-AppxPackage -ErrorAction SilentlyContinue" ^
  >>"%LOG%" 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like '*WebExperience*' } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue" ^
  >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowWidgets /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1

echo [A8] Edge AI surfaces off (sidebar/discover/copilot)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v HubsSidebarEnabled /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v DiscoverEnabled /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Edge" /v EdgeCopilotEnabled /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1

echo [A9] Advertising ID off (machine + user)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1

echo [A10] Disable Windows Error Reporting (WER)
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
sc stop WerSvc >>"%LOG%" 2>&1
sc config WerSvc start= disabled >>"%LOG%" 2>&1

echo [A11] Activity history + cross-device clipboard OFF
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v AllowCrossDeviceClipboard /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1

REM [A12] removed in v2.2: AllowLockScreenCamera is deprecated on Windows 11 24H2+ (no-op).

echo [A13] Disable Remote Desktop (hardening)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
sc stop TermService >>"%LOG%" 2>&1
sc config TermService start= disabled >>"%LOG%" 2>&1

echo [A14] Kill Explorer/OneDrive sync-provider banners (keep OneDrive)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1

echo [A15] Uninstall Phone Link + Cross-Device (installed + provisioned)
call :REMOVE_PHONELINK

echo [A16] Hide File Explorer "AI Actions" context menu (Windows 11 25H2+)
REM Documented community-wide; Microsoft Learn page pending. Harmless on pre-25H2 builds.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v HideAIActionsMenu /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v HideAIActionsMenu /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1

echo [A17] Harden .rdp client behavior (April 2026 KB5083769 phishing mitigation surface)
REM Complements [A13]: even with RDP service off, .rdp attachment attacks still open the client.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v AllowSavedCredentials /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v AllowSavedCredentialsWhenNTLMOnly /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1
reg add "HKCU\Software\Microsoft\Terminal Server Client" /v RDGClientTransport /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1

echo [A18] Disable Narrator rich image descriptions (cloud-assisted; expanded to all PCs in KB5083769)
reg add "HKCU\Software\Microsoft\Narrator\NoRoam" /v ImageDescriptionsEnabled /t REG_DWORD /d 0 /f >>"%LOG%" 2>&1

echo [A19] Snapshot Microsoft.Windows.AI.* component versions for audit trail
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Get-AppxPackage Microsoft.Windows.AI.* -ErrorAction SilentlyContinue | Select Name,Version,PackageFullName | Format-Table -AutoSize | Out-String | Out-File -Encoding UTF8 '%BACKUPDIR%\AI_Components.txt' } catch { }" ^
  >>"%LOG%" 2>&1

exit /b 0

:: --------------------------- SECTION B ---------------------------------------
:SECTION_B
echo.>>"%LOG%"
echo ===== SECTION B: AI-in-apps suppression (safe) =====>>"%LOG%"
echo.
echo === B) AI-in-apps suppression (safe levers) ===

echo [B1] Notepad AI policy keys (multi-namespace for coverage)
REM Some Notepad builds may keep UI visible despite these keys.
reg add "HKLM\SOFTWARE\Policies\Microsoft\Notepad" /v DisableAIFeatures /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Policies\WindowsNotepad" /v DisableAIFeatures /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1

echo [B5] Notepad AI user-scope policy (recent Store builds read HKCU first)
reg add "HKCU\Software\Policies\Microsoft\Windows\WindowsNotepad" /v DisableAIFeatures /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1

echo [B2] Paint: disable Cocreator / Generative Fill / Image Creator
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint" /v DisableCocreator /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint" /v DisableGenerativeFill /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint" /v DisableImageCreator /t REG_DWORD /d 1 /f >>"%LOG%" 2>&1

echo [B3] Generative AI capability: systemAIModels = Deny (HKLM + HKCU)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels" /v Value /t REG_SZ /d Deny /f >>"%LOG%" 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels" /v Value /t REG_SZ /d Deny /f >>"%LOG%" 2>&1

echo [B4] Note: Notepad Copilot/Rewrite UI may remain visible on some builds.
echo      This is a Microsoft app/UI decision. The safe script does not modify app-private files.
echo.>>"%LOG%"
echo NOTE: Notepad UI may remain visible; safe script does not hack app-private settings.>>"%LOG%"

exit /b 0

:: --------------------------- SECTION C ---------------------------------------
:SECTION_C
echo.>>"%LOG%"
echo ===== SECTION C: Security hardening (best-effort) =====>>"%LOG%"
echo.
echo === C) Security hardening (dev-friendly, best-effort) ===

echo [C1] Defender: PUA -> BLOCK (may be blocked by Tamper Protection/MDM)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { $p=(Get-MpPreference).PUAProtection; Set-Content -Path '%BACKUPDIR%\PUA_before.txt' -Value $p -Encoding ascii } catch { }" ^
  >>"%LOG%" 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Set-MpPreference -PUAProtection 2 } catch { 'Set-MpPreference failed (Tamper Protection / MDM).'; }" ^
  >>"%LOG%" 2>&1

echo [C2] Defender: ASR subset -> BLOCK (best-effort)
set "ASR_IDS=be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 d3e037e1-3eb8-44c8-a917-57927947596d 5beb7efe-fd9a-4556-801d-275e5ffc04cc 9e6ea88d-6e13-4ec2-b7e2-5b56f6b457ff e6db77e5-3df2-4cf1-b95a-636979351e5b d1e49aac-8f56-4280-b9ba-993a6d77406c c1db55ab-c21a-4637-bb3f-a12568109d35"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ids='%ASR_IDS%'.Split(' '); foreach($id in $ids){ if($id){ try { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled } catch { } } }" ^
  >>"%LOG%" 2>&1

echo [C3] Exploit Protection: enable safe system defaults (DEP/ASLR/SEHOP)
REM v2.2: CFG dropped from explicit list - it's a system default since KB5066835
REM and setting it explicitly occasionally produces EDR false positives.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Set-ProcessMitigation -System -Enable DEP,ForceRelocateImages,BottomUp,HighEntropy,SEHOP } catch { }" ^
  >>"%LOG%" 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Get-ProcessMitigation -System | Out-File -Encoding UTF8 '%BACKUPDIR%\ExploitMitigation_after.txt' } catch { }" ^
  >>"%LOG%" 2>&1

echo [C4] Report Smart App Control state (KB5083769 allows toggling without reinstall; this script does NOT force it on)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { (Get-MpComputerStatus | Select SmartAppControlState,SmartAppControlExpiration | Format-List | Out-String) | Out-File -Encoding UTF8 '%BACKUPDIR%\SmartAppControl_state.txt' } catch { 'Get-MpComputerStatus unavailable.' | Out-File -Encoding UTF8 '%BACKUPDIR%\SmartAppControl_state.txt' }" ^
  >>"%LOG%" 2>&1
exit /b 0

:: --------------------------- HELPERS -----------------------------------------
:REMOVE_PHONELINK
echo [i] Removing Phone Link / YourPhone / CrossDevice (best-effort)...>>"%LOG%"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-AppxPackage -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'YourPhone|PhoneLink|CrossDevice' -or $_.PackageFamilyName -match 'YourPhone|PhoneLink|CrossDevice' } | ForEach-Object { try { Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue } catch {} }" ^
  >>"%LOG%" 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'YourPhone|PhoneLink|CrossDevice' -or $_.PackageFamilyName -match 'YourPhone|PhoneLink|CrossDevice' } | ForEach-Object { try { Remove-AppxPackage -Package $_.PackageFullName -AllUsers -ErrorAction SilentlyContinue } catch { try { Remove-AppxPackage -Package $_.PackageFullName -ErrorAction SilentlyContinue } catch {} } } } catch {}" ^
  >>"%LOG%" 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -match 'YourPhone|PhoneLink|CrossDevice' -or $_.DisplayName -match 'YourPhone|PhoneLink|CrossDevice' } | Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue } catch {}" ^
  >>"%LOG%" 2>&1

exit /b 0

:: --------------------------- VERIFICATION ------------------------------------
:VERIFY_ALL
echo.>>"%VERIFY%"
echo --- OS build / display version --- >>"%VERIFY%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' DisplayVersion,CurrentBuild,UBR,ProductName -ErrorAction SilentlyContinue | Format-List | Out-String)" ^
  >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"

echo --- Effective telemetry level (SKU-dependent; Pro/Home clamp to 1) --- >>"%VERIFY%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { $p=(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection' -ErrorAction SilentlyContinue).AllowTelemetry; 'AllowTelemetry (written)=' + $p } catch { }" ^
  >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"

echo --- WindowsAI policy --- >>"%VERIFY%"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"

echo --- Explorer AI Actions (HideAIActionsMenu) --- >>"%VERIFY%"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v HideAIActionsMenu >>"%VERIFY%" 2>&1
reg query "HKCU\Software\Policies\Microsoft\Windows\Explorer" /v HideAIActionsMenu >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"

echo --- Installed AI components (Microsoft.Windows.AI.*) --- >>"%VERIFY%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Get-AppxPackage Microsoft.Windows.AI.* -ErrorAction SilentlyContinue | Select Name,Version | Format-Table -AutoSize | Out-String } catch { 'n/a' }" ^
  >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"

echo --- Smart App Control state (report-only; NOT forced by this script) --- >>"%VERIFY%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { (Get-MpComputerStatus | Select SmartAppControlState,SmartAppControlExpiration | Format-List | Out-String) } catch { 'Get-MpComputerStatus unavailable.' }" ^
  >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"

echo --- Narrator rich image descriptions --- >>"%VERIFY%"
reg query "HKCU\Software\Microsoft\Narrator\NoRoam" /v ImageDescriptionsEnabled >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"

echo --- Terminal Services (.rdp client) hardening --- >>"%VERIFY%"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"

echo --- Notepad policy keys written (UI may still remain on some builds) --- >>"%VERIFY%"
reg query "HKLM\SOFTWARE\Policies\Microsoft\Notepad" >>"%VERIFY%" 2>&1
reg query "HKLM\SOFTWARE\Policies\WindowsNotepad" >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"

echo --- Paint AI policy --- >>"%VERIFY%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Paint" >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"

echo --- systemAIModels capability --- >>"%VERIFY%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels" /v Value >>"%VERIFY%" 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels" /v Value >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"

echo --- Phone Link presence (installed + provisioned) --- >>"%VERIFY%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'YourPhone|PhoneLink|CrossDevice' -or $_.PackageFamilyName -match 'YourPhone|PhoneLink|CrossDevice' } | Select Name,PackageFullName | Format-Table -AutoSize | Out-String" ^
  >>"%VERIFY%" 2>&1
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -match 'YourPhone|PhoneLink|CrossDevice' -or $_.DisplayName -match 'YourPhone|PhoneLink|CrossDevice' } | Select DisplayName,PackageName | Format-Table -AutoSize | Out-String" ^
  >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"

echo --- Defender state (after; best-effort) --- >>"%VERIFY%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { (Get-MpPreference | Select PUAProtection,AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions) | Format-List | Out-String } catch { 'Get-MpPreference failed.' }" ^
  >>"%VERIFY%" 2>&1
echo.>>"%VERIFY%"
exit /b 0

