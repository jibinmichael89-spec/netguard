@echo off
setlocal
cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0Start-NetGuard-Services.ps1" -InstallDir "%~dp0."
if errorlevel 1 (
    echo.
    echo ====================================================
    echo   NetGuard could not start the API server
    echo ====================================================
    echo.
    echo Check the log: %ProgramData%\NetGuard\logs\servicehost.log
    echo.
    echo Try running this shortcut as Administrator.
    echo.
    pause
    exit /b 1
)

set "DASHBOARD_URL=http://127.0.0.1:8000"
set /a tries=0

:wait_for_server
set /a tries+=1
if %tries% GTR 40 goto api_unreachable
powershell -NoProfile -WindowStyle Hidden -Command "try { (Invoke-WebRequest -UseBasicParsing -Uri '%DASHBOARD_URL%/health' -TimeoutSec 2).StatusCode -eq 200 } catch { exit 1 }" >nul 2>&1
if errorlevel 1 (
    ping 127.0.0.1 -n 2 >nul
    goto wait_for_server
)

start "" "%DASHBOARD_URL%"
exit /b 0

:api_unreachable
echo.
echo ====================================================
echo   NetGuard API is not responding on port 8000
echo ====================================================
echo.
echo The dashboard was not opened because the API is offline.
echo Check: %ProgramData%\NetGuard\logs\servicehost.log
echo.
pause
exit /b 1
