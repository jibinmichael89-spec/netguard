# Restart NetGuard-API on Windows (invoked from the dashboard Settings page).
param(
    [string]$InstallDir = ""
)

$ErrorActionPreference = "SilentlyContinue"

if (-not $InstallDir) {
    $InstallDir = $PSScriptRoot
}

$ApiExe = Join-Path $InstallDir "NetGuard-API.exe"
if (-not (Test-Path $ApiExe)) {
    $ApiExe = Join-Path ${env:ProgramFiles} "NetGuard\NetGuard-API.exe"
    $InstallDir = Split-Path -Parent $ApiExe
}

if (-not (Test-Path $ApiExe)) {
    exit 1
}

Start-Sleep -Seconds 2
Get-Process -Name "NetGuard-API" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
Start-Process -FilePath $ApiExe -WorkingDirectory $InstallDir -WindowStyle Hidden
exit 0
