#!/usr/bin/env bash
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "[*] Installing ShadowRecon..."

python3 -m venv "$PROJECT_DIR/.venv"

source "$PROJECT_DIR/.venv/bin/activate"

python -m pip install --upgrade pip
python -m pip install -r "$PROJECT_DIR/requirements.txt"
python -m pip install -e "$PROJECT_DIR"

echo
echo "[+] ShadowRecon installed successfully."
echo "[+] Run it with:"
echo
echo "    $PROJECT_DIR/.venv/bin/shadowrecon"
echo
echo "[+] Or activate the environment:"
echo
echo "    source $PROJECT_DIR/.venv/bin/activate"
echo "    shadowrecon"
