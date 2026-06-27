#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install NetGuard Windows Home profile with auto-start scheduled tasks.
#>
param(
    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"
$ProfileDir = $PSScriptRoot
$RepoRoot = Resolve-Path (Join-Path $ProfileDir "..\..\..")

if (-not $InstallDir) {
    $InstallDir = Join-Path $RepoRoot "build\exe"
}
if (-not (Test-Path $InstallDir)) {
    $InstallDir = "${env:ProgramFiles}\NetGuard"
}

$DataDir = Join-Path $env:ProgramData "NetGuard"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
Copy-Item (Join-Path $ProfileDir "netguard.env") (Join-Path $DataDir "netguard.env") -Force
Copy-Item (Join-Path $ProfileDir "netguard.env") (Join-Path $InstallDir "netguard.env") -Force -ErrorAction SilentlyContinue

$Register = Join-Path $InstallDir "Register-NetGuard-AutoStart.ps1"
if (-not (Test-Path $Register)) {
    $Register = Join-Path $RepoRoot "build\windows\Register-NetGuard-AutoStart.ps1"
}
$RestartApi = Join-Path $RepoRoot "scripts\restart-api.ps1"
if (Test-Path $RestartApi) {
    Copy-Item $RestartApi (Join-Path $InstallDir "restart-api.ps1") -Force
}
& $Register -InstallDir $InstallDir -Profile home

Write-Host "[*] Windows Home profile installed with auto-start"
Write-Host "    Dashboard: http://localhost:8000"
Write-Host "    Run: $InstallDir\START-NetGuard.bat"
