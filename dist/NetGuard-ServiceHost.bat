@echo off
rem NetGuard background engines + API — no browser (boot scheduled task)
setlocal
cd /d "%~dp0"

if not defined NETGUARD_DB_PATH (
    set "NETGUARD_DB_PATH=%ProgramData%\NetGuard\netguard.db"
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
        start "NetGuard %%E" /MIN "%~dp0%%E"
        ping 127.0.0.1 -n 1 >nul
    )
)

exit /b 0
