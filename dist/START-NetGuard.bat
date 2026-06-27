@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set "DASHBOARD_URL=http://127.0.0.1:8000"

rem Ensure all engines and API are running
call "%~dp0NetGuard-ServiceHost.bat"

rem If API already responding, open dashboard
powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri '%DASHBOARD_URL%/health' -TimeoutSec 2).StatusCode -eq 200 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    start "" "%DASHBOARD_URL%"
    exit /b 0
)

rem Wait for API (up to ~30 seconds)
set /a tries=0
:wait_for_server
set /a tries+=1
if %tries% GTR 30 goto open_browser
powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri '%DASHBOARD_URL%/health' -TimeoutSec 1).StatusCode -eq 200 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    ping 127.0.0.1 -n 2 >nul
    goto wait_for_server
)

:open_browser
start "" "%DASHBOARD_URL%"
exit /b 0
