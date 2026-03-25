#!/usr/bin/env bash
# BugScanner Web GUI — Linux/Mac launcher
# Usage: ./run_web.sh [--port 5000] [--host 0.0.0.0]
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

# Activate venv if it exists
if [ -f "$HOME/.bugscanner/venv/bin/activate" ]; then
    source "$HOME/.bugscanner/venv/bin/activate"
elif [ -f "$DIR/venv/bin/activate" ]; then
    source "$DIR/venv/bin/activate"
fi

echo ""
echo -e "\033[0;32m  🌐 BugScanner Web GUI starting...\033[0m"
echo -e "\033[0;36m  Open: http://localhost:5000\033[0m"
echo -e "\033[2m  Ctrl+C to stop\033[0m"
echo ""

python web_gui.py "$@"
