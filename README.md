# WP Tester

An automated, cross-platform security testing pipeline and interactive SPA dashboard for WordPress websites.

## Why

Security testing a WordPress site often requires juggling multiple separate, command-line tools—each with its own installation method, output format, and dependency chain. **WP Tester** was built to provide a centralized command center that orchestrates all these tools into one continuous pipeline. It normalizes their raw output, automatically correlates findings with a remediation database, and presents everything in an easy-to-digest web dashboard and standard report formats. You no longer have to manually install dependencies like Ruby or Go; simply run our installer and get right to testing.

## Features

- **Centralized Security Pipeline**: Orchestrates 9 open-source tools: Nuclei, WPScan, Nikto, OWASP ZAP, SQLMap, SSLyze, WhatWeb, httpx, and CMSMap.
- **Interactive Web Dashboard**: A responsive Single-Page Application (SPA) dashboard to manage scan targets, configure API tokens, and view interactive HTML reports externally from an Ubuntu server.
- **Cross-Platform Auto-Installer**: An advanced, OS-aware installer that automatically provisions required system dependencies (Git, Ruby, Go, Java, Python) via `apt-get` on Ubuntu/Linux or provides `winget` instructions on Windows before installing the actual tools.
- **3 Scan Modes**: Passive (safe recon), Active (deep testing), or Full (both phases).
- **Rich Reporting**: Automatically generates filterable, dark-themed HTML reports, Markdown summaries, and raw JSON data.
- **Remediation Guidance**: A built-in database that maps detected vulnerabilities directly to step-by-step fix instructions.
- **CI/CD & Automation**: Headless CLI scanning with email notifications for automated cron jobs and pipeline integration.
- **Demo Mode**: Quickly generate a sample report to test the dashboard without any tools installed.

## Installation

### Prerequisites
- **Python 3.10+**

### 1. Setup Environment
Clone the repository and install the initial Python requirements:
```bash
git clone <repository_url> wp-tester
cd wp-tester
pip install -r requirements.txt
```

### 2. Auto-Install Dependencies & Tools
You can install the required system dependencies and security tools using the built-in python installer. It natively supports Ubuntu Server (`apt-get`) and Windows:

```bash
python scanner.py --install
```
*Note: Only **Nuclei** is strictly required to run a scan, but installing more tools provides significantly broader testing coverage.*

## How to Use

### Using the Web Dashboard (Recommended)
You can start the Flask web application to access the interactive dashboard interface. 
```bash
python app.py
```
By default, the server binds to `0.0.0.0:5000`. Navigate to `http://localhost:5000` (or your Ubuntu Server's IP address) in your browser to manage targets, configure API keys, and launch scans graphically.

### Using the Command Line Interface (CLI)
You can also run scans headless or via the interactive terminal menu:

```bash
# Start the interactive CLI menu
python scanner.py

# Run a headless passive scan on a specific URL
python scanner.py --target https://example.com --ci

# Run an active (deep) scan
python scanner.py --target https://example.com --mode active --ci

# Run a headless scan with email notifications
python scanner.py --target https://example.com --mode full --ci --email

# Generate a demo report (no scanning needed)
python scanner.py --demo
```

### Scheduling Scans (Linux Cron)
You can automate weekly headless scans using standard cron jobs:
```bash
# Add to crontab (runs every Monday at 6 AM)
0 6 * * 1 cd /path/to/wp-tester && /usr/bin/python3 scanner.py --target https://example.com --ci --email
```

## Architecture & Process Flow

### Scan Phases
The vulnerability scanner executes through four distinct and orchestrated phases to minimize disruption and maximize discovery:

| Phase | Description | Scan Mode | Primary Tools Used |
|-------|-------------|-----------|--------------------|
| **1. Recon** | Safe, light fingerprinting and technology detection. | Passive | `httpx` → `WhatWeb` → `SSLyze` |
| **2. WordPress**| Targeted WP enumeration (plugins, themes, CVEs). | Passive & Active | `Nuclei` → `WPScan` → `CMSMap` |
| **3. Deep Scan**| Intensive fuzzing and payload injection. | Active Only | `Nikto` → `SQLMap` → `OWASP ZAP` |
| **4. Report** | Deduplication, normalization, and remediation matching. | Always | *(Internal Python Engine)* |

### Performance Profiles
Scans can be tailored for either speed or thoroughness natively from the CLI menu (Option 9) or via `config/scan-config.json`. These profiles dynamically adjust the number of concurrent threads, timeouts, and request rate limits passed to the underlying tools.

### Report Output Generation
When a scan completes, the framework compiles all identified vulnerabilities into a dedicated folder (`reports/<target>_<timestamp>/`). The following artifacts are generated:
- `report.html`: A highly interactive, dark-themed HTML file with severity charts, detailed evidence, and dynamic filtering.
- `report.md`: A Markdown version ideal for copying into ticketing systems (Jira, GitHub Issues) or documentation.
- `findings.json`: The raw, normalized JSON output for ingestion into other SIEMs or CI/CD dashboards.

## Configuration

Configuration files are located in the `config/` directory. These can be managed manually or via the Web Dashboard / CLI menu:

| File | Purpose |
|------|---------|
| `config/targets.json` | Saved target URLs |
| `config/tokens.json` | API tokens (e.g., WPScan APIs, ZAP proxy keys) |
| `config/scan-config.json` | Default tool timeouts and thread settings |
| `fixes/remediation-db.json` | Vulnerability to remediation mapping dictionary |

*(Note: Free WPScan tokens are available at [wpscan.com/api](https://wpscan.com/api) - 25 calls/day).*

---
⚠️ **Legal Notice**: Only scan websites that you own or have explicit written authorization to test. Unauthorized scanning is illegal.
