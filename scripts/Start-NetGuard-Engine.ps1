param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,

    [Parameter(Mandatory = $true)]
    [string]$Engine
)

$ErrorActionPreference = "Stop"
$exe = Join-Path $InstallDir $Engine
if (-not (Test-Path $exe)) {
    exit 1
}

$logDir = Join-Path $env:ProgramData "NetGuard\logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$base = [System.IO.Path]::GetFileNameWithoutExtension($Engine)
$outLog = Join-Path $logDir "$base.log"
$errLog = Join-Path $logDir "$base.err.log"

Start-Process `
    -FilePath $exe `
    -WorkingDirectory $InstallDir `
    -WindowStyle Hidden `
    -RedirectStandardOutput $outLog `
    -RedirectStandardError $errLog
