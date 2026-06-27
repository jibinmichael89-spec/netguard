#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install NetGuard Windows MSP profile with auto-start and MSP heartbeat.
.EXAMPLE
  .\install\profiles\windows-msp\install.ps1
.EXAMPLE
  .\install\profiles\windows-msp\install.ps1 -InstallDir "C:\Program Files\NetGuard"
#>
param(
    [string]$InstallDir = "",
    [string]$SourceDir = ""
)

$ErrorActionPreference = "Stop"
$ProfileDir = $PSScriptRoot
$RepoRoot = (Resolve-Path (Join-Path $ProfileDir "..\..\..")).Path

. (Join-Path (Split-Path $ProfileDir -Parent) "Install-WindowsProfile.ps1")

Install-NetGuardWindowsProfile `
    -Profile msp `
    -ProfileDir $ProfileDir `
    -RepoRoot $RepoRoot `
    -InstallDir $InstallDir `
    -SourceDir $SourceDir
