# Build NetGuard Windows release: dashboard, PyInstaller exes, Inno Setup installer.
# Usage: .\build\windows\build-installer.ps1

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")

Write-Host "[*] Building dashboard ..."
Push-Location (Join-Path $Root "dashboard")
npm install --no-fund --no-audit
npm run build
$StaticDir = Join-Path $Root "api\static"
New-Item -ItemType Directory -Force -Path $StaticDir | Out-Null
Copy-Item -Path "dist\*" -Destination $StaticDir -Recurse -Force
Pop-Location

$ExeDir = Join-Path $Root "build\exe"
New-Item -ItemType Directory -Force -Path $ExeDir | Out-Null

Write-Host "[*] Stopping running NetGuard processes (so exes can be rebuilt) ..."
$ProcessNames = @(
    "NetGuard-API", "arp-scanner", "risk-scorer", "policy-engine",
    "arp-spoof-detector", "dns-monitor", "rogue-dhcp-detector",
    "inbound-connection-detector", "threat-intel", "msp-agent"
)
foreach ($Name in $ProcessNames) {
    Get-Process -Name $Name -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

Write-Host "[*] Building PyInstaller executables ..."
Push-Location $Root
$Specs = @(
    "api.spec",
    "arp_scanner.spec",
    "arp_spoof_detector.spec",
    "risk_scorer.spec",
    "dns_monitor.spec",
    "rogue_dhcp_detector.spec",
    "inbound_connection_detector.spec",
    "policy_engine.spec",
    "threat_intel.spec",
    "msp_agent.spec"
)
foreach ($Spec in $Specs) {
    Write-Host "  -> $Spec"
    python -m PyInstaller --noconfirm --distpath $ExeDir --workpath (Join-Path $Root "build\temp") $Spec
}
Pop-Location

Write-Host "[*] Copying launcher scripts ..."
Copy-Item (Join-Path $Root "dist\START-NetGuard.bat") $ExeDir -Force
Copy-Item (Join-Path $Root "dist\NetGuard-ServiceHost.bat") $ExeDir -Force
Copy-Item (Join-Path $Root "dist\START-ARP-Scanner.bat") $ExeDir -Force
Copy-Item (Join-Path $Root "dist\START-ARP-Spoof-Detector.bat") $ExeDir -Force
Copy-Item (Join-Path $Root "build\windows\Register-NetGuard-AutoStart.ps1") $ExeDir -Force
Copy-Item (Join-Path $Root "build\windows\Unregister-NetGuard-AutoStart.ps1") $ExeDir -Force
Copy-Item (Join-Path $Root "scripts\restart-api.ps1") $ExeDir -Force
Copy-Item (Join-Path $Root "scripts\restart-detector.ps1") $ExeDir -Force
Copy-Item (Join-Path $Root "scripts\Start-NetGuard-Services.ps1") $ExeDir -Force
Copy-Item (Join-Path $Root "scripts\Start-NetGuard-Engine.ps1") $ExeDir -Force
Copy-Item (Join-Path $Root "scripts\Verify-NetGuard-Windows.ps1") $ExeDir -Force
Copy-Item (Join-Path $Root "scripts\Repair-NetGuard-Windows.ps1") $ExeDir -Force
Copy-Item (Join-Path $Root "build\windows\Install-Npcap.ps1") $ExeDir -Force
Copy-Item (Join-Path $Root "install\profiles\windows-home\netguard.env") $ExeDir -Force

Write-Host "[*] Ensuring Npcap installer is bundled ..."
& (Join-Path $Root "build\windows\ensure-npcap-prereq.ps1") -RepoRoot $Root

# Never ship a database inside the install folder
Get-ChildItem -Path $ExeDir -Filter "*.db" -File -ErrorAction SilentlyContinue | Remove-Item -Force

if (-not (Test-Path (Join-Path $Root "build\prerequisites\npcap-installer.exe")) -and
    -not (Test-Path (Join-Path $Root "build\prerequisites\npcap-oem.exe"))) {
    Write-Warning "[!] No Npcap installer in build\prerequisites - NetGuard-Setup.exe will not bundle packet capture"
}

$Iscc = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $Iscc) {
    Write-Warning '[!] Inno Setup not found - executables are in build/exe'
    exit 0
}

Write-Host "[*] Building installer with Inno Setup ..."
& $Iscc (Join-Path $Root "NetGuard-Setup.iss")
& $Iscc (Join-Path $Root "NetGuard-Uninstall.iss")
Write-Host '[*] Done: build/installer/NetGuard-Setup.exe'
