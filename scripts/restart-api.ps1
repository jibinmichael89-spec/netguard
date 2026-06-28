# Restart NetGuard-API on Windows (invoked from the dashboard Settings page).
param(
    [string]$InstallDir = ""
)

$ErrorActionPreference = "SilentlyContinue"

if (-not $InstallDir) {
    $InstallDir = $PSScriptRoot
}

$envFile = Join-Path $env:ProgramData "NetGuard\netguard.env"
if (-not (Test-Path $envFile)) {
    $envFile = Join-Path $InstallDir "netguard.env"
}
if (Test-Path $envFile) {
    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#") -or $line -notmatch "=") { return }
        $parts = $line -split "=", 2
        $key = $parts[0].Trim()
        $value = $parts[1].Trim()
        if ($key -and -not (Test-Path "Env:$key")) {
            Set-Item -Path "Env:$key" -Value $value
        }
    }
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
