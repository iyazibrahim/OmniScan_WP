# WordPress Vulnerability Scanner

Automated multi-tool security testing pipeline for WordPress websites.

## Features

- **9 open-source tools** — Nuclei, WPScan, Nikto, OWASP ZAP, SQLMap, SSLyze, WhatWeb, httpx, CMSMap
- **Multi-URL targets** — save and manage multiple WordPress sites
- **3 scan modes** — Passive (safe recon), Active (deep testing), or Full (both)
- **Auto-detection & Installation** — detects missing tools and can auto-install them across Windows & Linux
- **Rich reports** — HTML (dark-themed, filterable), Markdown, and JSON output
- **Remediation guidance** — each finding includes step-by-step fix instructions
- **CI/CD & Automation** — headless modes with email notifications for cron jobs
- **Demo mode** — generate a sample report without any tools installed

## Installation

### Prerequisites
- **Python 3.10+**

### 1. Setup Environment
```bash
git clone <repository_url>
cd wp-vuln-scanner
pip install -r requirements.txt
```

### 2. Install Security Tools
You can install the required security tools automatically using the built-in installer:
```bash
python scanner.py --install
```
*Note: The installer supports both Windows and Linux (Kali/Debian).*

Only **Nuclei** is strictly required. Install more tools for broader coverage.

## Quick Start

```bash
# Run the interactive menu
python scanner.py

# Check which tools are installed
python scanner.py --check-tools

# Generate a demo report (no scanning needed)
python scanner.py --demo
```

## CLI Usage

```bash
# Scan a specific URL (passive mode by default)
python scanner.py --target https://example.com

# Run an active (deep) scan
python scanner.py --target https://example.com --mode active
```

## Automation & CI/CD

Headless scanning allows integration with CI pipelines and cron jobs.

```bash
# Headless scan (no prompts, exits with code 1 on critical findings)
python scanner.py --target https://example.com --ci

# Headless scan with email notifications and custom output directory
python scanner.py --target https://example.com --ci --email --output-dir /var/reports/
```

### Scheduling with Linux Cron

To run a weekly scan every Monday at 6 AM:
```bash
# Edit crontab
crontab -e

# Add the following entry
0 6 * * 1 cd /path/to/wp-vuln-scanner && /usr/bin/python3 scanner.py --target https://example.com --ci --email
```

### Scheduling with Windows Task Scheduler

```powershell
# Create a scheduled task to run weekly passive scans
$action = New-ScheduledTaskAction -Execute "python.exe" -Argument "C:\path\to\wp-vuln-scanner\scanner.py --target https://example.com --ci"
$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 6am
Register-ScheduledTask -TaskName "WP-VulnScan" -Action $action -Trigger $trigger
```

## Configuration

| File | Purpose |
|------|---------|
| `config/targets.json` | Saved target URLs (managed via menu) |
| `config/tokens.json` | API tokens — optional, gitignored |
| `config/scan-config.json` | Default scan settings for all tools |
| `fixes/remediation-db.json` | Vulnerability → fix mapping |

### API Tokens (Optional)

Use menu option **Configure API Tokens** or edit `config/tokens.json`:

```json
{
  "wpscan_api_token": "your-token-from-wpscan.com",
  "zap_api_key": ""
}
```

Free WPScan token: [wpscan.com/api](https://wpscan.com/api) (25 calls/day).

## Scan Phases

| Phase | Mode | Tools |
|-------|------|-------|
| 1. Recon | Passive | httpx → WhatWeb → SSLyze |
| 2. WordPress | Both | Nuclei → WPScan → CMSMap |
| 3. Deep Scan | Active | Nikto → SQLMap |
| 4. Report | Always | Normalize → Enrich → Generate |

## Report Output

Reports are saved to `reports/<target>_<timestamp>/`:
- `report.html` — Interactive dark-themed report with filtering
- `report.md` — Markdown for sharing/documentation
- `findings.json` — Raw findings for integration

## Legal Notice

⚠️ **Only scan websites you own or have written authorization to test.** Unauthorized scanning is illegal.
