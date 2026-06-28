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
    $ServicesScript = Join-Path $RepoRoot "scripts\Start-NetGuard-Services.ps1"
    if (Test-Path $ServicesScript) {
        Copy-Item $ServicesScript (Join-Path $InstallDir "Start-NetGuard-Services.ps1") -Force
    }
}

$HostBat = Join-Path $InstallDir "NetGuard-ServiceHost.bat"
if (-not (Test-Path $HostBat)) {
    throw "NetGuard-ServiceHost.bat not found in $InstallDir"
}

# Remove old tasks before re-registering
$TaskNames = @(
    "NetGuard Services",
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

# Boot: all scanners + API
$BootAction = New-ScheduledTaskAction -Execute $HostBat -WorkingDirectory $InstallDir
$BootTrigger = New-ScheduledTaskTrigger -AtStartup
$BootTrigger.Delay = "PT2M"
Register-ScheduledTask `
    -TaskName "NetGuard Services" `
    -Action $BootAction `
    -Trigger $BootTrigger `
    -Principal $Principal `
    -Settings $Settings `
    -Description "Starts all NetGuard security engines and API at Windows boot" `
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

# Start everything now (don't wait)
Start-ScheduledTask -TaskName "NetGuard Services" -ErrorAction SilentlyContinue
Start-Process -FilePath $HostBat -WorkingDirectory $InstallDir -WindowStyle Hidden

Write-Host "[*] NetGuard auto-start registered"
Write-Host "    Boot task:     NetGuard Services (2 min after startup)"
Write-Host "    Database:      $DbPath"
Write-Host "    Install dir:   $InstallDir"
