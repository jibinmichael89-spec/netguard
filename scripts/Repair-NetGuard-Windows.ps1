#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Repair a broken NetGuard Windows install (permissions, legacy DB, restart).
.EXAMPLE
  .\scripts\Repair-NetGuard-Windows.ps1
#>
param(
    [string]$InstallDir = (Join-Path ${env:ProgramFiles} "NetGuard"),
    [string]$RepoRoot = ""
)

$ErrorActionPreference = "Stop"
if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

$DataDir = Join-Path $env:ProgramData "NetGuard"
$dbPath = Join-Path $DataDir "netguard.db"

Write-Host "[*] Stopping NetGuard processes ..."
$names = @(
    "NetGuard-API", "arp-scanner", "risk-scorer", "policy-engine",
    "arp-spoof-detector", "dns-monitor", "rogue-dhcp-detector", "inbound-connection-detector"
)
foreach ($n in $names) {
    Get-Process -Name $n -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

Write-Host "[*] Fixing data folder permissions ..."
New-Item -ItemType Directory -Force -Path $DataDir, (Join-Path $DataDir "logs") | Out-Null
icacls $DataDir /grant "Users:(OI)(CI)M" /T | Out-Null
if (Test-Path $dbPath) { attrib -R $dbPath 2>$null | Out-Null }

$legacyDb = Join-Path $InstallDir "netguard.db"
if (Test-Path $legacyDb) {
    Write-Host "[*] Removing legacy database from $InstallDir ..."
    Remove-Item $legacyDb -Force
}

[Environment]::SetEnvironmentVariable("NETGUARD_DB_PATH", $dbPath, "Machine")

Write-Host "[*] Reinstalling from latest build ..."
& (Join-Path $RepoRoot "install\profiles\windows-home\install.ps1") -InstallDir $InstallDir

Write-Host "[*] Waiting for NetGuard API (install registers and starts services) ..."
$healthy = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    Start-Sleep -Seconds 2
    try {
        $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 4
        if ($health.status -eq "ok") {
            $healthy = $true
            break
        }
    } catch {
        # API still starting
    }
}

if (-not $healthy) {
    Write-Host "[*] API not responding yet - running START-NetGuard.bat ..."
    $launcher = Join-Path $InstallDir "START-NetGuard.bat"
    if (Test-Path $launcher) {
        & $launcher
    }
    Start-Sleep -Seconds 8
}

& (Join-Path $RepoRoot "scripts\Verify-NetGuard-Windows.ps1") -InstallDir $InstallDir
