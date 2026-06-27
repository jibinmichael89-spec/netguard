@echo off
setlocal
cd /d "%~dp0"

rem Start all engines hidden (ServiceHost requests Administrator if needed).
powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ^
    "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','\"\"%~dp0NetGuard-ServiceHost.bat\"\"' -WorkingDirectory '%~dp0' -WindowStyle Hidden"

set "DASHBOARD_URL=http://127.0.0.1:8000"
set /a tries=0

:wait_for_server
set /a tries+=1
if %tries% GTR 30 goto open_browser
powershell -NoProfile -WindowStyle Hidden -Command ^
    "try { (Invoke-WebRequest -UseBasicParsing -Uri '%DASHBOARD_URL%/health' -TimeoutSec 2).StatusCode -eq 200 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    ping 127.0.0.1 -n 2 >nul
    goto wait_for_server
)

:open_browser
start "" "%DASHBOARD_URL%"
exit /b 0
