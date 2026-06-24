@echo off
setlocal
cd /d "%~dp0"

set "DASHBOARD_URL=http://127.0.0.1:8000"

rem Start background scanner if not already running (devices, ports, DNS).
tasklist /FI "IMAGENAME eq arp-scanner.exe" 2>nul | find /I "arp-scanner.exe" >nul
if errorlevel 1 (
    start "NetGuard Scanner" /MIN "%~dp0arp-scanner.exe"
)

rem Start ARP spoof detector if not already running.
tasklist /FI "IMAGENAME eq arp-spoof-detector.exe" 2>nul | find /I "arp-spoof-detector.exe" >nul
if errorlevel 1 (
    start "NetGuard ARP Spoof Guard" /MIN "%~dp0arp-spoof-detector.exe"
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
