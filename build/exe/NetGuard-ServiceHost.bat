@echo off
setlocal
cd /d "%~dp0"

rem Packet-capture engines need Administrator. Re-launch this script elevated once.
net session >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command ^
        "Start-Process -FilePath '%~f0' -WorkingDirectory '%~dp0' -Verb RunAs -WindowStyle Hidden"
    exit /b 0
)

if not defined NETGUARD_DB_PATH (
    set "NETGUARD_DB_PATH=%ProgramData%\NetGuard\netguard.db"
)

set "ENGINE_SCRIPT=%~dp0Start-NetGuard-Engine.ps1"
if not exist "%ENGINE_SCRIPT%" (
    set "ENGINE_SCRIPT=%~dp0..\..\scripts\Start-NetGuard-Engine.ps1"
)

for %%E in (
    arp-scanner.exe
    arp-spoof-detector.exe
    risk-scorer.exe
    dns-monitor.exe
    rogue-dhcp-detector.exe
    inbound-connection-detector.exe
    policy-engine.exe
    NetGuard-API.exe
) do (
    tasklist /FI "IMAGENAME eq %%E" 2>nul | find /I "%%E" >nul
    if errorlevel 1 (
        if exist "%ENGINE_SCRIPT%" (
            powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "%ENGINE_SCRIPT%" -InstallDir "%~dp0" -Engine "%%E"
        ) else (
            powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-Process -LiteralPath '%~dp0%%E' -WorkingDirectory '%~dp0' -WindowStyle Hidden"
        )
        ping 127.0.0.1 -n 2 >nul
    )
)

exit /b 0
