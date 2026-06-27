#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Install NetGuard Windows Home profile with auto-start scheduled tasks.
.EXAMPLE
  .\install\profiles\windows-home\install.ps1
.EXAMPLE
  .\install\profiles\windows-home\install.ps1 -InstallDir "C:\Program Files\NetGuard"
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
    -Profile home `
    -ProfileDir $ProfileDir `
    -RepoRoot $RepoRoot `
    -InstallDir $InstallDir `
    -SourceDir $SourceDir
