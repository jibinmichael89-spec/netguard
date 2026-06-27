@echo off
setlocal
cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Start-NetGuard-Services.ps1" -InstallDir "%~dp0"

set "DASHBOARD_URL=http://127.0.0.1:8000"
set /a tries=0

:wait_for_server
set /a tries+=1
if %tries% GTR 40 goto open_browser
powershell -NoProfile -WindowStyle Hidden -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri '%DASHBOARD_URL%/health' -TimeoutSec 2).StatusCode -eq 200 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    ping 127.0.0.1 -n 2 >nul
    goto wait_for_server
)

:open_browser
start "" "%DASHBOARD_URL%"
exit /b 0
