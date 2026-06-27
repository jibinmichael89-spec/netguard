#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Remove NetGuard scheduled tasks on uninstall.
#>
$TaskNames = @(
    "NetGuard Services",
    "NetGuard Threat Intel",
    "NetGuard MSP Heartbeat"
)
foreach ($Name in $TaskNames) {
    schtasks /Delete /TN $Name /F 2>$null | Out-Null
}
[Environment]::SetEnvironmentVariable("NETGUARD_DB_PATH", $null, "Machine")
[Environment]::SetEnvironmentVariable("NETGUARD_PROFILE", $null, "Machine")
[Environment]::SetEnvironmentVariable("NETGUARD_MSP_COLLECTOR_URL", $null, "Machine")
[Environment]::SetEnvironmentVariable("NETGUARD_SITE_TOKEN", $null, "Machine")
[Environment]::SetEnvironmentVariable("NETGUARD_SITE_ID", $null, "Machine")
