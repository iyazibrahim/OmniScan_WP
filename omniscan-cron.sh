#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# OmniScan - Cron Wrapper Script
# ──────────────────────────────────────────────────────────────────────────────
#
# This script is designed to be called by cron for automated scanning.
# It sets up the environment, runs the scanner, and logs output.
#
# Setup:
#   1. Make executable:  chmod +x run-scan.sh
#   2. Edit variables below
#   3. Add to crontab:   crontab -e
#      Daily at 10:00 AM:  0 10 * * * /path/to/WP-Tester/run-scan.sh
#      Weekly Monday 8AM:  0 8 * * 1 /path/to/WP-Tester/run-scan.sh
#
# ──────────────────────────────────────────────────────────────────────────────

# ── Configuration (edit these) ──────────────────────────────────────────────
TARGET_URL="https://digitalpenang.my"
SCAN_MODE="full"   # passive | active | full

# Email settings (optional — or set in config/email-config.json)
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_SENDER="iyazbrhm@gmail.com"          # your-email@gmail.com
export SMTP_PASSWORD="kdac lgno rjkk ywqb"        # Gmail App Password
export SMTP_RECIPIENTS="iyaz@digitalpenang.my"      # recipient1@email.com,recipient2@email.com

# API tokens (optional — or set in config/tokens.json)
export WPSCAN_API_TOKEN=""
export ZAP_API_KEY=""

# ── Paths ───────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_DIR="${SCRIPT_DIR}/logs"
LOG_FILE="${LOG_DIR}/scan_$(date +%Y%m%d_%H%M%S).log"
PYTHON="python3"

# ── Setup ───────────────────────────────────────────────────────────────────
export CI=true
mkdir -p "${LOG_DIR}"

echo "========================================" | tee -a "${LOG_FILE}"
echo "WP Scan started at $(date)" | tee -a "${LOG_FILE}"
echo "Target: ${TARGET_URL}" | tee -a "${LOG_FILE}"
echo "Mode:   ${SCAN_MODE}" | tee -a "${LOG_FILE}"
echo "========================================" | tee -a "${LOG_FILE}"

# ── Run scanner ─────────────────────────────────────────────────────────────
cd "${SCRIPT_DIR}" || exit 1

# Determine email flag
EMAIL_FLAG=""
if [ -n "${SMTP_SENDER}" ] && [ -n "${SMTP_PASSWORD}" ] && [ -n "${SMTP_RECIPIENTS}" ]; then
    EMAIL_FLAG="--email"
fi

${PYTHON} scanner.py \
    --target "${TARGET_URL}" \
    --mode "${SCAN_MODE}" \
    --ci \
    ${EMAIL_FLAG} \
    2>&1 | tee -a "${LOG_FILE}"

EXIT_CODE=${PIPESTATUS[0]}

echo "" | tee -a "${LOG_FILE}"
echo "Scan finished at $(date) (exit code: ${EXIT_CODE})" | tee -a "${LOG_FILE}"

# ── Cleanup old logs (keep last 30 days) ────────────────────────────────────
find "${LOG_DIR}" -name "scan_*.log" -mtime +30 -delete 2>/dev/null

exit ${EXIT_CODE}
