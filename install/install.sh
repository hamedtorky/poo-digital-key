#!/bin/sh
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
INSTALL_DIR=${POO_INSTALL_DIR:-"$HOME/.local/share/poo-digital-key"}
BIN_DIR=${POO_BIN_DIR:-"$HOME/.local/bin"}
PYTHON=${PYTHON:-python3}

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  printf 'Error: Python 3.10 or newer is required.\n' >&2
  exit 1
fi

if ! "$PYTHON" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
  printf 'Error: Python 3.10 or newer is required.\n' >&2
  exit 1
fi

printf 'Installing poo into %s\n' "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR" "$BIN_DIR"
"$PYTHON" -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/python" -m pip install --upgrade pip
"$INSTALL_DIR/venv/bin/python" -m pip install --upgrade "$PROJECT_DIR"
ln -sfn "$INSTALL_DIR/venv/bin/poo" "$BIN_DIR/poo"

printf '\nInstallation complete.\n'
printf 'Command: %s/poo\n' "$BIN_DIR"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    printf '\nAdd this line to ~/.zshrc or ~/.bashrc, then open a new terminal:\n'
    printf '  export PATH="$HOME/.local/bin:$PATH"\n'
    ;;
esac
printf '\nConnect the dongle and run: poo status\n'
