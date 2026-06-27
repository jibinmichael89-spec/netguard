param(
    [string]$InstallDir = $PSScriptRoot,
    [switch]$CaptureOnly
)

$ErrorActionPreference = "Stop"

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-ServiceLog {
    param([string]$Message)
    $logDir = Join-Path $env:ProgramData "NetGuard\logs"
    New-Item -ItemType Directory -Force -Path $logDir | Out-Null
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path (Join-Path $logDir "servicehost.log") -Value $line
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
    Write-ServiceLog "Loaded env from $envFile"
}

function Start-Engine {
    param(
        [string]$BaseDir,
        [string]$Engine
    )

    $exe = Join-Path $BaseDir $Engine
    if (-not (Test-Path $exe)) {
        Write-ServiceLog "MISSING $Engine"
        return $false
    }

    $processName = [System.IO.Path]::GetFileNameWithoutExtension($Engine)
    if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
        Write-ServiceLog "ALREADY RUNNING $Engine"
        return $true
    }

    try {
        Start-Process -FilePath $exe -WorkingDirectory $BaseDir -WindowStyle Hidden
        Start-Sleep -Milliseconds 750
        if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
            Write-ServiceLog "STARTED $Engine"
            return $true
        }
        Write-ServiceLog "FAILED $Engine (process exited immediately)"
        return $false
    } catch {
        Write-ServiceLog "FAILED $Engine : $($_.Exception.Message)"
        return $false
    }
}

$InstallDir = (Resolve-Path $InstallDir).Path
Import-NetGuardEnv -BaseDir $InstallDir

if (-not $env:NETGUARD_DB_PATH) {
    $env:NETGUARD_DB_PATH = Join-Path $env:ProgramData "NetGuard\netguard.db"
}
New-Item -ItemType Directory -Force -Path (Split-Path $env:NETGUARD_DB_PATH -Parent) | Out-Null

$coreEngines = @(
    "arp-scanner.exe",
    "risk-scorer.exe",
    "policy-engine.exe",
    "NetGuard-API.exe"
)

$captureEngines = @(
    "arp-spoof-detector.exe",
    "dns-monitor.exe",
    "rogue-dhcp-detector.exe",
    "inbound-connection-detector.exe"
)

if ($CaptureOnly) {
    if (-not (Test-IsAdmin)) {
        Write-ServiceLog "Capture engines require Administrator privileges"
        exit 1
    }

    Write-ServiceLog "Starting capture engines (elevated) from $InstallDir"
    $count = 0
    foreach ($engine in $captureEngines) {
        if (Start-Engine -BaseDir $InstallDir -Engine $engine) { $count++ }
    }
    Write-ServiceLog "Capture engines running: $count/$($captureEngines.Count)"
    exit 0
}

Write-ServiceLog "Starting core NetGuard services from $InstallDir"
$coreStarted = 0
foreach ($engine in $coreEngines) {
    if (Start-Engine -BaseDir $InstallDir -Engine $engine) { $coreStarted++ }
}
Write-ServiceLog "Core services running: $coreStarted/$($coreEngines.Count)"

if (Test-IsAdmin) {
    $captureStarted = 0
    foreach ($engine in $captureEngines) {
        if (Start-Engine -BaseDir $InstallDir -Engine $engine) { $captureStarted++ }
    }
    Write-ServiceLog "Capture services running: $captureStarted/$($captureEngines.Count)"
} else {
    Write-ServiceLog "Requesting Administrator elevation for packet-capture engines ..."
    $args = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath,
        "-InstallDir", $InstallDir,
        "-CaptureOnly"
    )
    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs -WindowStyle Hidden
}

exit 0
