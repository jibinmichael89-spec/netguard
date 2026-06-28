function Install-NetGuardWindowsProfile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("home", "msp")]
        [string]$Profile,

        [Parameter(Mandatory = $true)]
        [string]$ProfileDir,

        [Parameter(Mandatory = $true)]
        [string]$RepoRoot,

        [string]$InstallDir = "",
        [string]$SourceDir = ""
    )

    $ErrorActionPreference = "Stop"

    if (-not $InstallDir) {
        $InstallDir = Join-Path ${env:ProgramFiles} "NetGuard"
    }
    if (-not $SourceDir) {
        $SourceDir = Join-Path $RepoRoot "build\exe"
    }

    $ApiExe = Join-Path $SourceDir "NetGuard-API.exe"
    if (-not (Test-Path $ApiExe)) {
        throw @"
Built executables not found in $SourceDir.
Run this first (Administrator PowerShell, repo root):

  .\build\windows\build-installer.ps1
"@
    }

    $DataDir = Join-Path $env:ProgramData "NetGuard"
    New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null

    Write-Host "[*] Copying NetGuard executables and launchers to $InstallDir ..."
    Get-ChildItem -Path $SourceDir -File | ForEach-Object {
        Copy-Item $_.FullName (Join-Path $InstallDir $_.Name) -Force
    }

    $RestartApi = Join-Path $RepoRoot "scripts\restart-api.ps1"
    if (Test-Path $RestartApi) {
        Copy-Item $RestartApi (Join-Path $InstallDir "restart-api.ps1") -Force
    }

    $ServicesScript = Join-Path $RepoRoot "scripts\Start-NetGuard-Services.ps1"
    if (Test-Path $ServicesScript) {
        Copy-Item $ServicesScript (Join-Path $InstallDir "Start-NetGuard-Services.ps1") -Force
    }

    $EngineScript = Join-Path $RepoRoot "scripts\Start-NetGuard-Engine.ps1"
    if (Test-Path $EngineScript) {
        Copy-Item $EngineScript (Join-Path $InstallDir "Start-NetGuard-Engine.ps1") -Force
    }

    $ServiceHost = Join-Path $SourceDir "NetGuard-ServiceHost.bat"
    if (Test-Path $ServiceHost) {
        Copy-Item $ServiceHost (Join-Path $InstallDir "NetGuard-ServiceHost.bat") -Force
    } else {
        $ServiceHost = Join-Path $RepoRoot "dist\NetGuard-ServiceHost.bat"
        if (Test-Path $ServiceHost) {
            Copy-Item $ServiceHost (Join-Path $InstallDir "NetGuard-ServiceHost.bat") -Force
        }
    }

    $Register = Join-Path $RepoRoot "build\windows\Register-NetGuard-AutoStart.ps1"
    Copy-Item $Register (Join-Path $InstallDir "Register-NetGuard-AutoStart.ps1") -Force

    $Unregister = Join-Path $RepoRoot "build\windows\Unregister-NetGuard-AutoStart.ps1"
    Copy-Item $Unregister (Join-Path $InstallDir "Unregister-NetGuard-AutoStart.ps1") -Force

    $ProfileEnv = Join-Path $ProfileDir "netguard.env"
    Copy-Item $ProfileEnv (Join-Path $DataDir "netguard.env") -Force
    Copy-Item $ProfileEnv (Join-Path $InstallDir "netguard.env") -Force

    Write-Host "[*] Registering auto-start scheduled tasks (profile: $Profile) ..."
    & $Register -InstallDir $InstallDir -Profile $Profile

    Write-Host ""
    Write-Host "[*] Windows $Profile profile installed"
    Write-Host "    Install dir:  $InstallDir"
    Write-Host "    Database:     $(Join-Path $DataDir 'netguard.db')"
    Write-Host "    Config:       $(Join-Path $DataDir 'netguard.env')"
    Write-Host "    Dashboard:    http://localhost:8000"
    Write-Host "    Router setup: Settings -> Router (save in dashboard, then Save & restart API)"
    Write-Host "    Launcher:     $(Join-Path $InstallDir 'START-NetGuard.bat')"
    if ($Profile -eq "msp") {
        Write-Host "    MSP config:   edit $(Join-Path $DataDir 'netguard.env') (collector URL + site token)"
    }
}
