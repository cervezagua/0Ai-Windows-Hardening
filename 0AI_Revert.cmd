@echo off
setlocal EnableExtensions
title 0AI v2.3 - Revert

net session >nul 2>&1
if %errorlevel% NEQ 0 (
  echo [i] Elevating...
  powershell -NoProfile -Command "Start-Process -Verb RunAs -FilePath '%~f0' -ArgumentList '%*'"
  exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Revert.ps1" %*
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
