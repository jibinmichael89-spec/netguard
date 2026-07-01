param(
    [string]$InstallDir = $PSScriptRoot,
    [switch]$CaptureOnly
)

$ErrorActionPreference = "Stop"

function Test-NpcapInstalled {
    if (Test-Path "$env:ProgramFiles\Npcap\wpcap.dll") { return $true }
    if (Test-Path "${env:ProgramFiles(x86)}\Npcap\wpcap.dll") { return $true }
    $svc = Get-Service -Name "npcap" -ErrorAction SilentlyContinue
    return ($null -ne $svc)
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Write-ServiceLog {
    param([string]$Message)
    try {
        $logDir = Join-Path $env:ProgramData "NetGuard\logs"
        New-Item -ItemType Directory -Force -Path $logDir | Out-Null
        $logFile = Join-Path $logDir "servicehost.log"
        $line = "{0} {1}{2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message, [Environment]::NewLine
        for ($attempt = 0; $attempt -lt 6; $attempt++) {
            try {
                $stream = [System.IO.File]::Open(
                    $logFile,
                    [System.IO.FileMode]::Append,
                    [System.IO.FileAccess]::Write,
                    [System.IO.FileShare]::ReadWrite
                )
                try {
                    $writer = New-Object System.IO.StreamWriter($stream)
                    $writer.Write($line)
                    $writer.Flush()
                    $writer.Close()
                } finally {
                    $stream.Close()
                }
                return
            } catch {
                Start-Sleep -Milliseconds (150 * ($attempt + 1))
            }
        }
    } catch {
        # Never block service startup because logging failed.
    }
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

function Initialize-NetGuardDataDir {
    $dataDir = Join-Path $env:ProgramData "NetGuard"
    $dbPath = Join-Path $dataDir "netguard.db"
    $logDir = Join-Path $dataDir "logs"

    New-Item -ItemType Directory -Force -Path $dataDir, $logDir | Out-Null
    Ensure-NetGuardDataPermissions -DataDir $dataDir

    # Always use writable ProgramData - never Program Files
    $env:NETGUARD_DB_PATH = $dbPath
    if (Test-IsAdmin) {
        [Environment]::SetEnvironmentVariable("NETGUARD_DB_PATH", $dbPath, "Machine")
    }

    $legacyDb = Join-Path $InstallDir "netguard.db"
    if (Test-Path $legacyDb) {
        Write-ServiceLog "Removing legacy read-only database from install folder"
        Remove-Item $legacyDb -Force -ErrorAction SilentlyContinue
    }

    if (Test-Path $dbPath) {
        attrib -R $dbPath 2>$null | Out-Null
    }

    return $dbPath
}

function Ensure-NetGuardDataPermissions {
    param([string]$DataDir)

    try {
        icacls $DataDir /grant "Users:(OI)(CI)M" /T | Out-Null
        Write-ServiceLog "Ensured Users can write to $DataDir"
    } catch {
        Write-ServiceLog "WARNING: could not set data folder permissions: $($_.Exception.Message)"
    }
}

function Test-PortInUse {
    param([int]$Port)
    $conn = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $conn) { return $null }
    return Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
}

function Ensure-ApiPortAvailable {
    $owner = Test-PortInUse -Port 8000
    if (-not $owner) { return }

    if ($owner.ProcessName -eq "NetGuard-API") {
        Write-ServiceLog "Port 8000 already served by NetGuard-API (pid $($owner.Id))"
        return
    }

    Write-ServiceLog "WARNING: port 8000 is in use by $($owner.ProcessName) (pid $($owner.Id))"
    try {
        Stop-Process -Id $owner.Id -Force -ErrorAction Stop
        Start-Sleep -Seconds 2
        Write-ServiceLog "Stopped $($owner.ProcessName) to free port 8000 for NetGuard-API"
    } catch {
        Write-ServiceLog "ERROR: could not free port 8000: $($_.Exception.Message)"
        throw "Port 8000 is in use by $($owner.ProcessName). Stop it and retry."
    }
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
    $running = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if ($running) {
        if ($Engine -eq "NetGuard-API.exe") {
            try {
                $health = Invoke-RestMethod -Uri "http://127.0.0.1:8000/health" -TimeoutSec 3
                if ($health.status -eq "ok") {
                    Write-ServiceLog "ALREADY RUNNING $Engine (healthy on port 8000)"
                    return $true
                }
            } catch {
                Write-ServiceLog "Stale $Engine process detected - restarting"
                $running | Stop-Process -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            }
        } else {
            Write-ServiceLog "ALREADY RUNNING $Engine (pid $($running.Id -join ','))"
            return $true
        }
    }

    try {
        if ($Engine -eq "NetGuard-API.exe") {
            Get-Process -Name $processName -ErrorAction SilentlyContinue |
                Stop-Process -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 1
        }

        Start-Process -FilePath $exe -WorkingDirectory $BaseDir -WindowStyle Hidden
        Start-Sleep -Milliseconds 1000
        if (Get-Process -Name $processName -ErrorAction SilentlyContinue) {
            Write-ServiceLog "STARTED $Engine (db=$($env:NETGUARD_DB_PATH))"
            return $true
        }
        Write-ServiceLog "FAILED $Engine (process exited immediately)"
        return $false
    } catch {
        Write-ServiceLog "FAILED $Engine : $($_.Exception.Message)"
        return $false
    }
}

$InstallDir = $InstallDir.Trim().Trim('"').TrimEnd('\')
if (-not $InstallDir) {
    $InstallDir = $PSScriptRoot
}
$InstallDir = (Resolve-Path -LiteralPath $InstallDir).Path

Import-NetGuardEnv -BaseDir $InstallDir
$dbPath = Initialize-NetGuardDataDir
Write-ServiceLog "Using database: $dbPath"

$coreEngines = @(
    "arp-scanner.exe",
    "risk-scorer.exe",
    "policy-engine.exe",
    "syslog-export.exe",
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

    if (-not (Test-NpcapInstalled)) {
        Write-ServiceLog "ERROR: Npcap is not installed - DNS/DHCP/inbound capture cannot start"
        Write-ServiceLog "Install Npcap from https://npcap.com (default options) and restart NetGuard"
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
Ensure-ApiPortAvailable
$coreStarted = 0
$apiStarted = $false
foreach ($engine in $coreEngines) {
    if (Start-Engine -BaseDir $InstallDir -Engine $engine) {
        $coreStarted++
        if ($engine -eq "NetGuard-API.exe") {
            $apiStarted = $true
        }
    }
}
Write-ServiceLog "Core services running: $coreStarted/$($coreEngines.Count)"

if (-not $apiStarted) {
    $logFile = Join-Path $env:ProgramData "NetGuard\logs\servicehost.log"
    Write-ServiceLog "ERROR: NetGuard-API.exe did not start - dashboard will show Scanner Offline"
    Write-Error "NetGuard-API.exe failed to start. Check $logFile"
    exit 1
}

if (Test-IsAdmin) {
    if (-not (Test-NpcapInstalled)) {
        Write-ServiceLog "WARNING: Npcap not installed - packet capture engines will not run"
        Write-ServiceLog "Install from https://npcap.com then run Repair-NetGuard-Windows.ps1 as Administrator"
    } else {
        $captureStarted = 0
        foreach ($engine in $captureEngines) {
            if (Start-Engine -BaseDir $InstallDir -Engine $engine) { $captureStarted++ }
        }
        Write-ServiceLog "Capture services running: $captureStarted/$($captureEngines.Count)"
    }
} else {
    Write-ServiceLog "Requesting Administrator elevation for packet-capture engines ..."
    $elevatedArgs = @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $PSCommandPath,
        "-InstallDir", $InstallDir,
        "-CaptureOnly"
    )
    try {
        Start-Process -FilePath "powershell.exe" -ArgumentList $elevatedArgs -Verb RunAs -WindowStyle Hidden -ErrorAction Stop
    } catch {
        Write-ServiceLog "Capture engine elevation skipped: $($_.Exception.Message)"
    }
}

exit 0
