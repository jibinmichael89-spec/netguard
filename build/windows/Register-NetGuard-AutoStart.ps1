#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Register NetGuard Windows scheduled tasks for automatic startup of all engines.
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [string]$Profile = "home"
)

$ErrorActionPreference = "Stop"
$InstallDir = $InstallDir.TrimEnd('\')
$DataDir = Join-Path $env:ProgramData "NetGuard"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
icacls $DataDir /grant "Users:(OI)(CI)M" /T | Out-Null

$LegacyDb = Join-Path $InstallDir "netguard.db"
if (Test-Path $LegacyDb) {
    Remove-Item $LegacyDb -Force -ErrorAction SilentlyContinue
}

function Remove-ScheduledTaskIfExists([string]$TaskName) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}

$EnvFile = Join-Path $DataDir "netguard.env"
if (-not (Test-Path $EnvFile)) {
    $Template = Join-Path $InstallDir "netguard.env"
    if (Test-Path $Template) {
        Copy-Item $Template $EnvFile -Force
    }
}

$DbPath = Join-Path $DataDir "netguard.db"
[Environment]::SetEnvironmentVariable("NETGUARD_DB_PATH", $DbPath, "Machine")
[Environment]::SetEnvironmentVariable("NETGUARD_PROFILE", $Profile, "Machine")

function Read-EnvValue([string]$Key) {
    if (-not (Test-Path $EnvFile)) { return "" }
    foreach ($line in Get-Content $EnvFile) {
        if ($line -match "^\s*#") { continue }
        if ($line -match "^\s*$Key=(.*)$") { return $Matches[1].Trim() }
    }
    return ""
}

$ServicesScript = Join-Path $InstallDir "Start-NetGuard-Services.ps1"
if (-not (Test-Path $ServicesScript)) {
    throw "Start-NetGuard-Services.ps1 not found in $InstallDir"
}

$PowerShellArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ServicesScript`" -InstallDir `"$InstallDir`""
$CaptureArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$ServicesScript`" -InstallDir `"$InstallDir`" -CaptureOnly"

# Remove old tasks before re-registering
$TaskNames = @(
    "NetGuard Services",
    "NetGuard Capture Engines",
    "NetGuard Threat Intel",
    "NetGuard MSP Heartbeat"
)
foreach ($Name in $TaskNames) {
    Remove-ScheduledTaskIfExists -TaskName $Name
}

$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

# Boot: core scanners + API (hidden PowerShell — no visible CMD window)
$BootAction = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument $PowerShellArgs `
    -WorkingDirectory $InstallDir
$BootTrigger = New-ScheduledTaskTrigger -AtStartup
$BootTrigger.Delay = "PT2M"
Register-ScheduledTask `
    -TaskName "NetGuard Services" `
    -Action $BootAction `
    -Trigger $BootTrigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description "Starts NetGuard core engines and API at Windows boot" `
    -Force | Out-Null

# Boot: packet-capture engines (SYSTEM + admin; needs Npcap on the host)
$CaptureAction = New-ScheduledTaskAction `
    -Execute "powershell.exe" `
    -Argument $CaptureArgs `
    -WorkingDirectory $InstallDir
$CaptureTrigger = New-ScheduledTaskTrigger -AtStartup
$CaptureTrigger.Delay = "PT3M"
Register-ScheduledTask `
    -TaskName "NetGuard Capture Engines" `
    -Action $CaptureAction `
    -Trigger $CaptureTrigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description "Starts DNS/DHCP/inbound packet capture engines (requires Npcap)" `
    -Force | Out-Null

# Weekly threat intel feed update
$ThreatExe = Join-Path $InstallDir "threat-intel.exe"
if (Test-Path $ThreatExe) {
    $ThreatAction = New-ScheduledTaskAction -Execute $ThreatExe -WorkingDirectory $InstallDir
    $ThreatTrigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Sunday -At 3am
    Register-ScheduledTask `
        -TaskName "NetGuard Threat Intel" `
        -Action $ThreatAction `
        -Trigger $ThreatTrigger `
        -Principal $Principal `
        -Settings $Settings `
        -Description "Weekly threat intelligence feed update" `
        -Force | Out-Null
}

# MSP heartbeat (only when collector URL configured)
$Collector = Read-EnvValue "NETGUARD_MSP_COLLECTOR_URL"
$SiteToken = Read-EnvValue "NETGUARD_SITE_TOKEN"
$SiteId = Read-EnvValue "NETGUARD_SITE_ID"
if ($Profile -eq "msp" -and $Collector -and $SiteToken) {
    $MspExe = Join-Path $InstallDir "msp-agent.exe"
    if (Test-Path $MspExe) {
        $MspAction = New-ScheduledTaskAction -Execute $MspExe -WorkingDirectory $InstallDir
        $MspTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5) -RepetitionDuration ([TimeSpan]::MaxValue)
        Register-ScheduledTask `
            -TaskName "NetGuard MSP Heartbeat" `
            -Action $MspAction `
            -Trigger $MspTrigger `
            -Principal $Principal `
            -Settings $Settings `
            -Description "Reports site status to MSP collector" `
            -Force | Out-Null
        [Environment]::SetEnvironmentVariable("NETGUARD_MSP_COLLECTOR_URL", $Collector, "Machine")
        [Environment]::SetEnvironmentVariable("NETGUARD_SITE_TOKEN", $SiteToken, "Machine")
        if ($SiteId) {
            [Environment]::SetEnvironmentVariable("NETGUARD_SITE_ID", $SiteId, "Machine")
        }
    }
}

# Start once now (scheduled task only — avoid duplicate CMD windows)
Start-ScheduledTask -TaskName "NetGuard Services" -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Start-ScheduledTask -TaskName "NetGuard Capture Engines" -ErrorAction SilentlyContinue

Write-Host "[*] NetGuard auto-start registered"
Write-Host "    Boot task:     NetGuard Services (2 min after startup)"
Write-Host "    Capture task:  NetGuard Capture Engines (3 min after startup, needs Npcap)"
Write-Host "    Database:      $DbPath"
Write-Host "    Install dir:   $InstallDir"
