# Install Npcap if missing. Used by NetGuard-Setup.exe and repair scripts.
param(
    [string]$PrereqDir = "",
    [switch]$SilentOnly
)

$ErrorActionPreference = "Stop"

function Test-NpcapInstalled {
    if (Test-Path "$env:ProgramFiles\Npcap\NPFInstall.exe") { return $true }
    if (Test-Path "$env:ProgramFiles\Npcap\wpcap.dll") { return $true }
    if (Test-Path "${env:ProgramFiles(x86)}\Npcap\wpcap.dll") { return $true }
    return ($null -ne (Get-Service -Name "npcap" -ErrorAction SilentlyContinue))
}

function Find-NpcapInstaller {
    param([string]$SearchDir)

    if (-not $SearchDir -or -not (Test-Path $SearchDir)) {
        return $null
    }

    $oem = Get-ChildItem -Path $SearchDir -Filter "npcap-oem.exe" -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($oem) {
        return @{
            Path = $oem.FullName
            Silent = $true
            Args = "/S /winpcap_mode=yes /loopback_support=no /admin_only=no /dot11_support=no"
        }
    }

    $named = Join-Path $SearchDir "npcap-installer.exe"
    if (Test-Path $named) {
        return @{
            Path = $named
            Silent = $false
            Args = "/winpcap_mode=enforced /loopback_support=disabled /admin_only=no /dot11_support=disabled"
        }
    }

    $free = Get-ChildItem -Path $SearchDir -Filter "npcap-*.exe" -File -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notmatch "-oem" } |
        Sort-Object Name -Descending |
        Select-Object -First 1
    if ($free) {
        return @{
            Path = $free.FullName
            Silent = $false
            Args = "/winpcap_mode=enforced /loopback_support=disabled /admin_only=no /dot11_support=disabled"
        }
    }

    return $null
}

if (Test-NpcapInstalled) {
    Write-Host "[OK] Npcap already installed"
    exit 0
}

$searchDirs = @()
if ($PrereqDir) { $searchDirs += $PrereqDir }
$searchDirs += $PSScriptRoot
$searchDirs += (Join-Path $env:ProgramFiles "NetGuard")

$installer = $null
foreach ($dir in $searchDirs) {
    $installer = Find-NpcapInstaller -SearchDir $dir
    if ($installer) { break }
}

if (-not $installer) {
    if ($SilentOnly) {
        Write-Error "Npcap OEM installer not found for silent install"
        exit 1
    }
    Write-Error @"
Npcap installer not bundled. DNS/DHCP/inbound monitoring requires Npcap.
Rebuild NetGuard-Setup.exe on a machine with internet access, or install Npcap
from https://npcap.com then run Repair-NetGuard-Windows.ps1
"@
    exit 1
}

if ($SilentOnly -and -not $installer.Silent) {
    Write-Error "Only Npcap OEM supports fully silent install (npcap-oem.exe)"
    exit 1
}

Write-Host "[*] Installing Npcap from $($installer.Path) ..."
$windowStyle = if ($installer.Silent) { "Hidden" } else { "Normal" }
$process = Start-Process `
    -FilePath $installer.Path `
    -ArgumentList $installer.Args `
    -Wait `
    -PassThru `
    -WindowStyle $windowStyle

$exitCode = $process.ExitCode
if ($exitCode -notin 0, 3010) {
    if (-not (Test-NpcapInstalled)) {
        Write-Error "Npcap installer exited with code $exitCode and Npcap is still missing"
        exit [Math]::Max($exitCode, 1)
    }
}

if (Test-NpcapInstalled) {
    Write-Host "[OK] Npcap installed"
    if ($exitCode -eq 3010) {
        Write-Host "[!] Reboot recommended for Npcap (will work after restart)"
    }
    exit 0
}

Write-Error "Npcap installation did not complete"
exit 1
