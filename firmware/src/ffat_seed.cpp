#include <Arduino.h>
#include <FS.h>
#include <FFat.h>

static const char README_TXT[] =
"Open a terminal and run: sh ./install/install.sh\n";

static const char INSTALL_SH[] = "#!/bin/sh\n"
"set -eu\n\n"
"PROJECT_DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")/..\" && pwd)\n"
"INSTALL_DIR=${POO_INSTALL_DIR:-\"$HOME/.local/share/poo-digital-key\"}\n"
"BIN_DIR=${POO_BIN_DIR:-\"$HOME/.local/bin\"}\n"
"PYTHON=${PYTHON:-python3}\n\n"
"if ! command -v \"$PYTHON\" >/dev/null 2>&1; then\n"
"  printf 'Error: Python 3.10 or newer is required.\\n' >&2\n"
"  exit 1\n"
"fi\n\n"
"if ! \"$PYTHON\" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then\n"
"  printf 'Error: Python 3.10 or newer is required.\\n' >&2\n"
"  exit 1\n"
"fi\n\n"
"printf 'Installing poo into %s\\n' \"$INSTALL_DIR\"\n"
"mkdir -p \"$INSTALL_DIR\" \"$BIN_DIR\"\n"
"\"$PYTHON\" -m venv \"$INSTALL_DIR/venv\"\n"
"\"$INSTALL_DIR/venv/bin/python\" -m pip install --upgrade pip\n"
"\"$INSTALL_DIR/venv/bin/python\" -m pip install --upgrade \"$PROJECT_DIR\"\n"
"ln -sfn \"$INSTALL_DIR/venv/bin/poo\" \"$BIN_DIR/poo\"\n\n"
"printf '\\nInstallation complete.\\n'\n"
"printf 'Command: %s/poo\\n' \"$BIN_DIR\"\n"
"case \":$PATH:\" in\n"
"  *\":$BIN_DIR:\"*) ;;\n"
"  *)\n"
"    printf '\\nAdd this line to ~/.zshrc or ~/.bashrc, then open a new terminal:\\n'\n"
"    printf '  export PATH=\"$HOME/.local/bin:$PATH\"\\n'\n"
"    ;;\n"
"esac\n"
"printf '\\nConnect the dongle and run: poo status\\n'\n";

static const char INSTALL_PS1[] =
"[CmdletBinding()]\n"
"param()\n\n"
"$ErrorActionPreference = \"Stop\"\n"
"$ProjectDir = (Resolve-Path (Join-Path $PSScriptRoot \"..\")).Path\n\n"
"if ($env:POO_INSTALL_DIR) {\n"
"    $InstallDir = $env:POO_INSTALL_DIR\n"
"} else {\n"
"    $InstallDir = Join-Path $env:LOCALAPPDATA \"PooDigitalKey\"\n"
"}\n"
"if ($env:POO_BIN_DIR) {\n"
"    $BinDir = $env:POO_BIN_DIR\n"
"} else {\n"
"    $BinDir = Join-Path $env:LOCALAPPDATA \"Programs\\PooDigitalKey\\bin\"\n"
"}\n"
"$VenvDir = Join-Path $InstallDir \"venv\"\n\n"
"$PyLauncher = Get-Command py -ErrorAction SilentlyContinue\n"
"$PythonCommand = Get-Command python -ErrorAction SilentlyContinue\n"
"if ($PyLauncher) {\n"
"    & $PyLauncher.Source -3 -c \"import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)\"\n"
"    if ($LASTEXITCODE -ne 0) { throw \"Python 3.10 or newer is required.\" }\n"
"    New-Item -ItemType Directory -Force -Path $InstallDir, $BinDir | Out-Null\n"
"    & $PyLauncher.Source -3 -m venv $VenvDir\n"
"} elseif ($PythonCommand) {\n"
"    & $PythonCommand.Source -c \"import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)\"\n"
"    if ($LASTEXITCODE -ne 0) { throw \"Python 3.10 or newer is required.\" }\n"
"    New-Item -ItemType Directory -Force -Path $InstallDir, $BinDir | Out-Null\n"
"    & $PythonCommand.Source -m venv $VenvDir\n"
"} else {\n"
"    throw \"Python 3.10 or newer was not found. Install it from https://python.org first.\"\n"
"}\n\n"
"$VenvPython = Join-Path $VenvDir \"Scripts\\python.exe\"\n"
"if (!(Test-Path $VenvPython)) { throw \"Failed to create the Python environment.\" }\n\n"
"Write-Host \"Installing poo into $InstallDir\"\n"
"& $VenvPython -m pip install --upgrade pip\n"
"if ($LASTEXITCODE -ne 0) { throw \"Failed to update pip.\" }\n"
"& $VenvPython -m pip install --upgrade $ProjectDir\n"
"if ($LASTEXITCODE -ne 0) { throw \"Failed to install poo.\" }\n\n"
"$Wrapper = Join-Path $BinDir \"poo.cmd\"\n"
"$WrapperText = \"@echo off`r`n`\"$VenvPython`\" -m digital_key.cli %*`r`n\"\n"
"Set-Content -Path $Wrapper -Value $WrapperText -Encoding ASCII\n\n"
"$UserPath = [Environment]::GetEnvironmentVariable(\"Path\", \"User\")\n"
"$PathEntries = @()\n"
"if ($UserPath) { $PathEntries = $UserPath.Split(';') }\n"
"if ($PathEntries -notcontains $BinDir) {\n"
"    $NewPath = if ($UserPath) { \"$UserPath;$BinDir\" } else { $BinDir }\n"
"    [Environment]::SetEnvironmentVariable(\"Path\", $NewPath, \"User\")\n"
"}\n"
"if (($env:Path.Split(';')) -notcontains $BinDir) {\n"
"    $env:Path = \"$BinDir;$env:Path\"\n"
"}\n\n"
"Write-Host \"\"\n"
"Write-Host \"Installation complete.\"\n"
"Write-Host \"Open a new terminal, connect the dongle, and run: poo status\"\n";

static const char INSTALL_CMD[] =
"@echo off\r\n"
"powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%~dp0install.ps1\"\r\n"
"if errorlevel 1 (\r\n"
"  echo Installation failed.\r\n"
"  exit /b 1\r\n"
")\r\n";

static bool write_file_if_missing(const char* path, const char* data, size_t len, bool make_exec=false) {
  File f = FFat.open(path, FILE_READ);
  if (f) { f.close(); return true; }
  f = FFat.open(path, FILE_WRITE);
  if (!f) return false;
  size_t w = f.write((const uint8_t*)data, len);
  f.close();
  // exec bit is not applicable on FFat (no POSIX perms), ignored
  return w == len;
}

void ensure_ffat_seed() {
  if (!FFat.begin(false)) {
    // format if mount fails
    if (!FFat.begin(true)) {
      return;
    }
  }
  FFat.mkdir("/install");
  write_file_if_missing("/README.txt", README_TXT, strlen(README_TXT));
  write_file_if_missing("/install/install.sh", INSTALL_SH, strlen(INSTALL_SH), true);
  write_file_if_missing("/install/install.ps1", INSTALL_PS1, strlen(INSTALL_PS1));
  write_file_if_missing("/install/install-windows.cmd", INSTALL_CMD, strlen(INSTALL_CMD));
}
