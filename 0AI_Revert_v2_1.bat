@echo off
setlocal EnableExtensions EnableDelayedExpansion
title 0AI - Privacy ^& Security Kit (Revert v2.1)

REM =============================================================================
REM 0AI_Revert_v2_1.bat
REM - Uses the newest folder in %USERPROFILE%\0AI_Backups
REM - Imports registry exports where available (best-effort)
REM - Restores systemAIModels to Prompt and tries to undo Defender/mitigation changes
REM - Does NOT reinstall apps (by design)
REM =============================================================================

net session >nul 2>&1 || (echo [!] Run this script as Administrator. & pause & exit /b 1)

set "ROOT=%USERPROFILE%\0AI_Backups"
if not exist "%ROOT%" (
  echo [!] No backup folder found at "%ROOT%".
  pause
  exit /b 1
)

set "LATEST="
for /f "delims=" %%D in ('dir "%ROOT%" /b /ad /o-d 2^>nul') do (set "LATEST=%%D" & goto :GOT)
:GOT
if not defined LATEST (
  echo [!] No backup subfolders found.
  pause
  exit /b 1
)

set "BACKUPDIR=%ROOT%\%LATEST%"
set "LOG=%BACKUPDIR%\revert.log"

echo [+] Using backup folder: "%BACKUPDIR%"
echo.>"%LOG%"

echo [+] Creating best-effort restore point (before revert)...>>"%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Checkpoint-Computer -Description '0AI_Revert_v2_1' -RestorePointType 'MODIFY_SETTINGS' | Out-Null } catch { }" ^
  >>"%LOG%" 2>&1

echo [+] Importing registry exports (best-effort)...>>"%LOG%"
for %%F in (
  "%BACKUPDIR%\HKLM_Policies_Microsoft_Windows.reg"
  "%BACKUPDIR%\HKLM_Policies_Edge.reg"
  "%BACKUPDIR%\HKLM_Policies_Dsh.reg"
  "%BACKUPDIR%\HKLM_Policies_WindowsAI.reg"
  "%BACKUPDIR%\HKCU_Policies_WindowsCopilot.reg"
  "%BACKUPDIR%\HKLM_Policies_Microsoft_Notepad.reg"
  "%BACKUPDIR%\HKLM_Policies_WindowsNotepad.reg"
  "%BACKUPDIR%\HKLM_Policies_Paint.reg"
  "%BACKUPDIR%\HKCU_Search.reg"
  "%BACKUPDIR%\HKCU_SmartActions.reg"
  "%BACKUPDIR%\HKCU_InputPersonalization.reg"
  "%BACKUPDIR%\HKLM_AdvertisingInfo.reg"
  "%BACKUPDIR%\HKCU_AdvertisingInfo.reg"
  "%BACKUPDIR%\HKLM_WER_Policy.reg"
  "%BACKUPDIR%\HKLM_WER_System.reg"
  "%BACKUPDIR%\HKLM_System_Policies.reg"
  "%BACKUPDIR%\HKLM_TerminalServer.reg"
  "%BACKUPDIR%\HKCU_Explorer_Advanced.reg"
  "%BACKUPDIR%\HKLM_ConsentStore_systemAIModels.reg"
  "%BACKUPDIR%\HKCU_ConsentStore_systemAIModels.reg"
) do (
  if exist "%%~fF" reg import "%%~fF" >>"%LOG%" 2>&1
)

echo [+] Restore systemAIModels to Prompt (typical default)...>>"%LOG%"
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels" /v Value /t REG_SZ /d Prompt /f >>"%LOG%" 2>&1
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\systemAIModels" /v Value /t REG_SZ /d Prompt /f >>"%LOG%" 2>&1

echo [+] Reverting Defender hardening (best-effort; may be blocked by Tamper Protection)...>>"%LOG%"
set "PUA=0"
if exist "%BACKUPDIR%\PUA_before.txt" (
  for /f "usebackq delims=" %%p in ("%BACKUPDIR%\PUA_before.txt") do set "PUA=%%p"
)
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Set-MpPreference -PUAProtection %PUA% } catch { }" ^
  >>"%LOG%" 2>&1

set "ASR_IDS=be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 d3e037e1-3eb8-44c8-a917-57927947596d 5beb7efe-fd9a-4556-801d-275e5ffc04cc 9e6ea88d-6e13-4ec2-b7e2-5b56f6b457ff e6db77e5-3df2-4cf1-b95a-636979351e5b d1e49aac-8f56-4280-b9ba-993a6d77406c c1db55ab-c21a-4637-bb3f-a12568109d35"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ids='%ASR_IDS%'.Split(' '); foreach($id in $ids){ if($id){ try { Remove-MpPreference -AttackSurfaceReductionRules_Ids $id } catch { } } }" ^
  >>"%LOG%" 2>&1

echo [+] Attempting to undo exploit mitigations we enabled (best-effort)...>>"%LOG%"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Set-ProcessMitigation -System -Disable DEP,ForceRelocateImages,BottomUp,HighEntropy,SEHOP,CFG } catch { }" ^
  >>"%LOG%" 2>&1

echo.
echo [i] Restarting Explorer...
taskkill /f /im explorer.exe >nul 2>&1
start explorer.exe

echo.
echo DONE. Reboot recommended.
echo Log: "%LOG%"
pause
exit /b 0

