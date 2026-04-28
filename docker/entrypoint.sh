#!/usr/bin/env bash
set -euo pipefail

cd /app

mkdir -p reports logs config

if [[ "${UPDATE_NUCLEI_TEMPLATES:-0}" == "1" ]] && command -v nuclei >/dev/null 2>&1; then
    echo "[*] Updating nuclei templates..."
    nuclei -ut || true
fi

if [[ $# -eq 0 || "$1" == "app" ]]; then
    shift || true
    echo "[+] Starting OmniScan dashboard on 0.0.0.0:5000"
    exec python3 app.py "$@"
fi

if [[ "$1" == "scanner" ]]; then
    shift
    exec python3 scanner.py "$@"
fi

exec "$@"
