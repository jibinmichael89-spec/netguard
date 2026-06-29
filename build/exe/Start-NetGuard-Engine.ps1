param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,

    [Parameter(Mandatory = $true)]
    [string]$Engine
)

$InstallDir = $InstallDir.Trim().Trim('"').TrimEnd('\')
if (-not $InstallDir) {
    $InstallDir = $PSScriptRoot
}
if (Test-Path -LiteralPath $InstallDir) {
    $InstallDir = (Resolve-Path -LiteralPath $InstallDir).Path
}

$exe = Join-Path $InstallDir $Engine
if (-not (Test-Path $exe)) {
    exit 1
}

# Windowless PyInstaller exes (runw.exe) cannot use stdout/stderr redirection.
Start-Process `
    -FilePath $exe `
    -WorkingDirectory $InstallDir `
    -WindowStyle Hidden | Out-Null

exit 0
