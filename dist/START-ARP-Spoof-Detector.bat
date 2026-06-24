@echo off
setlocal
cd /d "%~dp0"
title NetGuard ARP Spoof Detector

echo.
echo ====================================================
echo   NetGuard ARP Spoof Detector
echo ====================================================
echo.
echo Leave this window OPEN while using NetGuard.
echo Watches for unexpected MAC address changes on your LAN.
echo.

"%~dp0arp-spoof-detector.exe"

echo.
echo ARP spoof detector stopped.
pause
