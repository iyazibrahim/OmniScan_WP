#!/bin/bash
# wp-tester.sh - Auto-launch script for WP Tester
# Safely manages the virtual environment to prevent "externally-managed-environment" errors.

# Ensure we are in the script's directory
cd "$(dirname "$0")"

# Validate Python 3 existence
if ! command -v python3 &> /dev/null; then
    echo "[-] Error: Python 3 could not be found. Please install Python 3.10+"
    exit 1
fi

# Ensure python3-venv is installed on apt-based systems (Ubuntu/Debian)
if ! python3 -m venv -h &> /dev/null; then
    if command -v apt-get &> /dev/null; then
        echo "[*] Missing 'python3-venv'. Attempting to install via apt-get..."
        sudo apt-get update && sudo apt-get install -y python3-venv
    else
        echo "[-] Error: 'python3-venv' module is missing. Please install it using your system package manager."
        exit 1
    fi
fi

# Automatically create the virtual environment if missing
if [ ! -d "venv" ]; then
    echo "[*] Creating new Python virtual environment in 'venv/'..."
    python3 -m venv venv
    
    echo "[*] Activating virtual environment..."
    source venv/bin/activate
    
    echo "[*] Installing Python requirements..."
    pip install --upgrade pip
    pip install -r requirements.txt
    echo "[+] Virtual environment setup complete!"
else
    # Seamlessly activate the existing venv
    source venv/bin/activate
fi

# Route the execution
if [ "$1" == "app" ]; then
    shift # Remove 'app' from args so downstream doesn't misinterpret
    echo "[+] Starting WP Tester Web Dashboard on http://0.0.0.0:5000 ..."
    python app.py "$@"
else
    # By default, pass all arguments straight to the CLI scanner wrapper
    python scanner.py "$@"
fi
