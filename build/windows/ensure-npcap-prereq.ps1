# Download or locate the Npcap installer for bundling into NetGuard-Setup.exe.
# For commercial silent installs, place your licensed npcap-*-oem.exe in build/prerequisites/
# as npcap-oem.exe (see build/prerequisites/README.md).
param(
    [string]$RepoRoot = "",
    [string]$NpcapVersion = "1.83"
)

$ErrorActionPreference = "Stop"
if (-not $RepoRoot) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

$PrereqDir = Join-Path $RepoRoot "build\prerequisites"
New-Item -ItemType Directory -Force -Path $PrereqDir | Out-Null

$oemPath = Join-Path $PrereqDir "npcap-oem.exe"
if (Test-Path $oemPath) {
    Write-Host "[*] Npcap OEM installer found: $oemPath (silent install enabled)"
    exit 0
}

$bundledPath = Join-Path $PrereqDir "npcap-installer.exe"
if (Test-Path $bundledPath) {
    Write-Host "[*] Npcap installer already present: $bundledPath"
    exit 0
}

$url = "https://npcap.com/dist/npcap-$NpcapVersion.exe"
Write-Host "[*] Downloading Npcap $NpcapVersion for bundling ..."
Write-Host "    $url"
try {
    Invoke-WebRequest -Uri $url -OutFile $bundledPath -UseBasicParsing
} catch {
    throw @"
Could not download Npcap installer.
Download manually from https://npcap.com/#download
Save as: $bundledPath

For commercial distribution (silent, unlimited installs), purchase Npcap OEM
redistribution and place npcap-oem.exe in build\prerequisites\
See build\prerequisites\README.md
"@
}

Write-Host "[*] Saved $bundledPath"
