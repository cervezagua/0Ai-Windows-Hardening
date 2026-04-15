@echo off
setlocal EnableExtensions
title 0AI v2.3 - Apply

net session >nul 2>&1
if %errorlevel% NEQ 0 (
  echo [i] Elevating...
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0' -ArgumentList '%*'"
  exit /b
)

REM Force UTF-8 so the dashboard launcher's box-drawing characters render
REM correctly on default conhost. Harmless on any Win10/11 build.
chcp 65001 >nul

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Apply.ps1" %*
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
