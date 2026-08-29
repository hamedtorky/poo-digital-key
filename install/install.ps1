[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ($env:POO_INSTALL_DIR) {
    $InstallDir = $env:POO_INSTALL_DIR
} else {
    $InstallDir = Join-Path $env:LOCALAPPDATA "PooDigitalKey"
}
if ($env:POO_BIN_DIR) {
    $BinDir = $env:POO_BIN_DIR
} else {
    $BinDir = Join-Path $env:LOCALAPPDATA "Programs\PooDigitalKey\bin"
}
$VenvDir = Join-Path $InstallDir "venv"

$PyLauncher = Get-Command py -ErrorAction SilentlyContinue
$PythonCommand = Get-Command python -ErrorAction SilentlyContinue
if ($PyLauncher) {
    & $PyLauncher.Source -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
    if ($LASTEXITCODE -ne 0) { throw "Python 3.10 or newer is required." }
    New-Item -ItemType Directory -Force -Path $InstallDir, $BinDir | Out-Null
    & $PyLauncher.Source -3 -m venv $VenvDir
} elseif ($PythonCommand) {
    & $PythonCommand.Source -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
    if ($LASTEXITCODE -ne 0) { throw "Python 3.10 or newer is required." }
    New-Item -ItemType Directory -Force -Path $InstallDir, $BinDir | Out-Null
    & $PythonCommand.Source -m venv $VenvDir
} else {
    throw "Python 3.10 or newer was not found. Install it from https://python.org first."
}

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
if (!(Test-Path $VenvPython)) { throw "Failed to create the Python environment." }

Write-Host "Installing poo into $InstallDir"
& $VenvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "Failed to update pip." }
& $VenvPython -m pip install --upgrade $ProjectDir
if ($LASTEXITCODE -ne 0) { throw "Failed to install poo." }

$Wrapper = Join-Path $BinDir "poo.cmd"
$WrapperText = "@echo off`r`n`"$VenvPython`" -m digital_key.cli %*`r`n"
Set-Content -Path $Wrapper -Value $WrapperText -Encoding ASCII

$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
$PathEntries = @()
if ($UserPath) { $PathEntries = $UserPath.Split(';') }
if ($PathEntries -notcontains $BinDir) {
    $NewPath = if ($UserPath) { "$UserPath;$BinDir" } else { $BinDir }
    [Environment]::SetEnvironmentVariable("Path", $NewPath, "User")
}
if (($env:Path.Split(';')) -notcontains $BinDir) {
    $env:Path = "$BinDir;$env:Path"
}

Write-Host ""
Write-Host "Installation complete."
Write-Host "Open a new terminal, connect the dongle, and run: poo status"
