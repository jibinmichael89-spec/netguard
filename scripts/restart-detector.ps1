# Restart a single NetGuard detector on Windows (invoked from the dashboard).
param(
    [Parameter(Mandatory = $true)]
    [string]$DetectorId,

    [string]$InstallDir = ""
)

$ErrorActionPreference = "Stop"

$DetectorExeMap = @{
    arp_scanner   = "arp-scanner.exe"
    risk_scorer   = "risk-scorer.exe"
    arp_spoof     = "arp-spoof-detector.exe"
    dns_monitor   = "dns-monitor.exe"
    rogue_dhcp    = "rogue-dhcp-detector.exe"
    inbound       = "inbound-connection-detector.exe"
    policy_engine = "policy-engine.exe"
}

$CaptureEngines = @(
    "arp-spoof-detector.exe",
    "dns-monitor.exe",
    "rogue-dhcp-detector.exe",
    "inbound-connection-detector.exe"
)

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Import-NetGuardEnv {
    param([string]$BaseDir)

    $envFile = Join-Path $env:ProgramData "NetGuard\netguard.env"
    if (-not (Test-Path $envFile)) {
        $envFile = Join-Path $BaseDir "netguard.env"
    }
    if (-not (Test-Path $envFile)) {
        return
    }

    Get-Content $envFile | ForEach-Object {
        $line = $_.Trim()
        if (-not $line -or $line.StartsWith("#") -or $line -notmatch "=") { return }
        $parts = $line -split "=", 2
        $key = $parts[0].Trim()
        $value = $parts[1].Trim()
        if ($key) {
            Set-Item -Path "Env:$key" -Value $value
        }
    }
}

if (-not $InstallDir) {
    $InstallDir = $PSScriptRoot
}

if (-not $DetectorExeMap.ContainsKey($DetectorId)) {
    Write-Error "Unknown detector: $DetectorId"
    exit 1
}

$engine = $DetectorExeMap[$DetectorId]
$exe = Join-Path $InstallDir $engine
if (-not (Test-Path $exe)) {
    $fallbackDir = Join-Path ${env:ProgramFiles} "NetGuard"
    $fallbackExe = Join-Path $fallbackDir $engine
    if (Test-Path $fallbackExe) {
        $exe = $fallbackExe
        $InstallDir = $fallbackDir
    } else {
        Write-Error "Executable not found: $engine"
        exit 1
    }
}

if ($CaptureEngines -contains $engine -and -not (Test-IsAdmin)) {
    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-WindowStyle", "Hidden",
        "-File", $PSCommandPath,
        "-DetectorId", $DetectorId,
        "-InstallDir", $InstallDir
    )
    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs -WindowStyle Hidden
    exit 0
}

Import-NetGuardEnv -BaseDir $InstallDir

$processName = [System.IO.Path]::GetFileNameWithoutExtension($engine)
Get-Process -Name $processName -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
Start-Process -FilePath $exe -WorkingDirectory $InstallDir -WindowStyle Hidden
exit 0
