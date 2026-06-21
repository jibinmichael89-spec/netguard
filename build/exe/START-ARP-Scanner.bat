@echo off
setlocal
cd /d "%~dp0"
title NetGuard ARP Scanner

echo.
echo ====================================================
echo   NetGuard ARP Scanner
echo ====================================================
echo.
echo Leave this window OPEN while using NetGuard.
echo Devices appear in the dashboard after the first scan.
echo.
echo Tip: right-click this shortcut and choose "Run as administrator"
echo      if no devices are found.
echo.

"%~dp0arp-scanner.exe"

echo.
echo Scanner stopped.
pause
