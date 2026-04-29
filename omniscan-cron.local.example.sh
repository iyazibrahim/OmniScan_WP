#!/usr/bin/env bash
# Local-only cron wrapper example for OmniScan.
# Copy to omniscan-cron.local.sh and customize for your environment.
# Do NOT commit the local file.

TARGET_URL="https://example.com"
SCAN_MODE="full"

# Optional email configuration
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_SENDER="your-email@example.com"
export SMTP_PASSWORD="replace-with-app-password"
export SMTP_RECIPIENTS="recipient1@example.com,recipient2@example.com"

# Optional API tokens
export WPSCAN_API_TOKEN=""
export ZAP_API_KEY=""

# Run project script using your local env vars
exec "$(cd "$(dirname "$0")" && pwd)/omniscan-cron.sh"
