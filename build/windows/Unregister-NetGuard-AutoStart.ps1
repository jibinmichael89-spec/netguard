#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Remove NetGuard scheduled tasks on uninstall.
#>
$ErrorActionPreference = "Stop"

function Remove-ScheduledTaskIfExists([string]$TaskName) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    }
}

$TaskNames = @(
    "NetGuard Services",
    "NetGuard Capture Engines",
    "NetGuard Threat Intel",
    "NetGuard MSP Heartbeat"
)
foreach ($Name in $TaskNames) {
    Remove-ScheduledTaskIfExists -TaskName $Name
}
[Environment]::SetEnvironmentVariable("NETGUARD_DB_PATH", $null, "Machine")
[Environment]::SetEnvironmentVariable("NETGUARD_PROFILE", $null, "Machine")
[Environment]::SetEnvironmentVariable("NETGUARD_MSP_COLLECTOR_URL", $null, "Machine")
[Environment]::SetEnvironmentVariable("NETGUARD_SITE_TOKEN", $null, "Machine")
[Environment]::SetEnvironmentVariable("NETGUARD_SITE_ID", $null, "Machine")
