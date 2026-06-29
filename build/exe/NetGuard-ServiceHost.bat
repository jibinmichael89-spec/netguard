@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-NetGuard-Services.ps1" -InstallDir "%~dp0."
exit /b %ERRORLEVEL%
