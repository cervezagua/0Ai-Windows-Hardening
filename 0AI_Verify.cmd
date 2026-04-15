@echo off
setlocal EnableExtensions
title 0AI v2.3 - Verify

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Verify.ps1" %*
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
