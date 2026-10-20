@echo off
setlocal EnableExtensions
title 0AI - Verify

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0src\Verify.ps1" %*
set "RC=%ERRORLEVEL%"
echo.
pause
exit /b %RC%
