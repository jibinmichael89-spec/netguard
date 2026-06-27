@echo off
setlocal
cd /d "%~dp0"

set "DASHBOARD_URL=http://127.0.0.1:8000"

rem Start v1.2 background daemons if not already running.
for %%E in (
    arp-scanner.exe
    arp-spoof-detector.exe
    risk-scorer.exe
    dns-monitor.exe
    rogue-dhcp-detector.exe
    inbound-connection-detector.exe
    policy-engine.exe
) do (
    tasklist /FI "IMAGENAME eq %%E" 2>nul | find /I "%%E" >nul
    if errorlevel 1 (
        start "NetGuard %%E" /MIN "%~dp0%%E"
    )
)

rem Run threat intel update once if executable present (non-blocking).
if exist "%~dp0threat-intel.exe" (
    tasklist /FI "IMAGENAME eq threat-intel.exe" 2>nul | find /I "threat-intel.exe" >nul
    if errorlevel 1 (
        start "NetGuard Threat Intel" /MIN "%~dp0threat-intel.exe"
    )
)

rem If the API is already running, just open the dashboard.
tasklist /FI "IMAGENAME eq NetGuard-API.exe" 2>nul | find /I "NetGuard-API.exe" >nul
if not errorlevel 1 (
    start "" "%DASHBOARD_URL%"
    exit /b 0
)

rem Start the API server in a minimized window.
start "NetGuard Server" /MIN "%~dp0NetGuard-API.exe"

rem Wait for the server to respond (up to ~20 seconds).
set /a tries=0
:wait_for_server
set /a tries+=1
if %tries% GTR 20 goto open_browser
powershell -NoProfile -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri '%DASHBOARD_URL%/health' -TimeoutSec 1).StatusCode -eq 200 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    ping 127.0.0.1 -n 2 >nul
    goto wait_for_server
)

:open_browser
start "" "%DASHBOARD_URL%"
exit /b 0
