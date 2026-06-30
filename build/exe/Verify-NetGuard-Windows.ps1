# Verify NetGuard Windows install: processes, API health, database path.
# Run as Administrator for full checks (optional).
param(
    [string]$InstallDir = (Join-Path ${env:ProgramFiles} "NetGuard")
)

$ErrorActionPreference = "Stop"
$failures = @()

function Test-Condition {
    param([string]$Name, [bool]$Ok, [string]$Detail = "")
    if ($Ok) {
        Write-Host "[OK]   $Name" -ForegroundColor Green
        if ($Detail) { Write-Host "       $Detail" -ForegroundColor DarkGray }
    } else {
        Write-Host "[FAIL] $Name" -ForegroundColor Red
        if ($Detail) { Write-Host "       $Detail" -ForegroundColor Yellow }
        $script:failures += $Name
    }
}

function Test-NpcapInstalled {
    if (Test-Path "$env:ProgramFiles\Npcap\wpcap.dll") { return $true }
    if (Test-Path "${env:ProgramFiles(x86)}\Npcap\wpcap.dll") { return $true }
    return ($null -ne (Get-Service -Name "npcap" -ErrorAction SilentlyContinue))
}

Write-Host ""
Write-Host "NetGuard Windows verification" -ForegroundColor Cyan
Write-Host "Install dir: $InstallDir"
Write-Host ""

$expectedDb = Join-Path $env:ProgramData "NetGuard\netguard.db"
$legacyDb = Join-Path $InstallDir "netguard.db"
$logFile = Join-Path $env:ProgramData "NetGuard\logs\servicehost.log"

Test-Condition "NetGuard-API.exe exists" (Test-Path (Join-Path $InstallDir "NetGuard-API.exe"))
Test-Condition "START-NetGuard.bat exists" (Test-Path (Join-Path $InstallDir "START-NetGuard.bat"))
Test-Condition "No legacy DB in Program Files" (-not (Test-Path $legacyDb)) $legacyDb
Test-Condition "Machine NETGUARD_DB_PATH set" ([bool]([Environment]::GetEnvironmentVariable("NETGUARD_DB_PATH", "Machine"))) ([Environment]::GetEnvironmentVariable("NETGUARD_DB_PATH", "Machine"))

$npcapOk = Test-NpcapInstalled
Test-Condition "Npcap installed (packet capture)" $npcapOk $(if ($npcapOk) { "Required for DNS/DHCP/inbound monitors" } else { "Install from https://npcap.com then re-run START-NetGuard.bat as Admin" })

$captureNames = @("dns-monitor", "rogue-dhcp-detector", "inbound-connection-detector", "arp-spoof-detector")
$captureRunning = @($captureNames | Where-Object { Get-Process -Name $_ -ErrorAction SilentlyContinue }).Count
if ($npcapOk) {
    Test-Condition "Capture engines running" ($captureRunning -ge 1) "$captureRunning/$($captureNames.Count) optional detectors"
}

$apiProc = Get-Process -Name "NetGuard-API" -ErrorAction SilentlyContinue
Test-Condition "NetGuard-API process running" ($null -ne $apiProc) $(if ($apiProc) { "pid $($apiProc.Id)" } else { "Run START-NetGuard.bat as Administrator" })

try {
    $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 5
    Test-Condition "API /health responds" ($health.status -eq "ok") ($health | ConvertTo-Json -Compress)
} catch {
    Test-Condition "API /health responds" $false $_.Exception.Message
}

try {
    $monitoring = Invoke-RestMethod -Uri "http://127.0.0.1:8000/monitoring/status" -TimeoutSec 5
    $core = @($monitoring.detectors | Where-Object { -not $_.optional })
    $healthy = @($core | Where-Object { $_.status -in @("active", "idle") }).Count
    Test-Condition "Monitoring status reachable" $true "overall=$($monitoring.overall_status) core=$healthy/$($core.Count)"
} catch {
    Test-Condition "Monitoring status reachable" $false $_.Exception.Message
}

if (Test-Path $expectedDb) {
    Test-Condition "Writable database in ProgramData" $true $expectedDb
} else {
    Test-Condition "Writable database in ProgramData" $false "Expected $expectedDb (created on first scan)"
}

if (Test-Path $logFile) {
    Write-Host ""
    Write-Host "Last 5 log lines ($logFile):" -ForegroundColor DarkGray
    Get-Content $logFile -Tail 5 | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
}

Write-Host ""
if ($failures.Count -eq 0) {
    Write-Host "All checks passed." -ForegroundColor Green
    exit 0
}

Write-Host "$($failures.Count) check(s) failed." -ForegroundColor Red
exit 1
