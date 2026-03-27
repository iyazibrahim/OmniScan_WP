# OmniScan (Universal Security Pipeline)

An automated, cross-platform security testing pipeline and interactive SPA dashboard for web applications, APIs, and CMS platforms (WordPress, Joomla, Drupal).

## Why

Security testing a web app or CMS often requires juggling multiple separate, command-line tools—each with its own installation method, output format, and dependency chain. **OmniScan** was originally built for WordPress but has evolved into a centralized command center that orchestrates these tools into one continuous pipeline. It normalizes their raw output, automatically correlates findings with a remediation database, and presents everything in an easy-to-digest web dashboard and standard report formats. You no longer have to manually install dependencies like Ruby or Go; simply run our auto-installer and get right to testing.

## Features

- **Profile-Aware Targeting**: Dynamically adjusts testing toolchains based on the selected target profile (`WordPress`, `Joomla`, `Drupal`, `Web App`, `Custom API`).
- **Centralized Security Pipeline**: Orchestrates 18 powerful open-source tools including Nuclei, WPScan, ffuf, Dalfox, SQLMap, Wapiti, JoomScan, Droopescan, Commix, Corsy, Subfinder, and more.
- **Environment Context Switching**: Automatically identifies local targets (`localhost`) and adjusts testing configurations (e.g., bypassing TLS checks, omitting external DNS enumerations).
- **Interactive Web Dashboard**: A responsive Single-Page Application (SPA) dashboard to manage scan targets with profile selection, configure API tokens, and view interactive reports.
- **Cross-Platform Auto-Installer**: An advanced, OS-aware installer that automatically provisions required system dependencies (Git, Ruby, Go, Java, Python) and orchestrates binary installations via `go install`, `pip`, or source repository cloning.
- **3 Scan Modes**: Passive (safe recon), Active (deep testing), or Full (both phases).
- **Rich Reporting**: Automatically generates filterable HTML reports, Markdown summaries, and raw JSON data.
- **Remediation Guidance**: A built-in database that maps detected vulnerabilities directly to step-by-step fix instructions.
- **CI/CD & Automation**: Headless CLI scanning with email notifications for automated cron jobs and pipeline integration.

## Installation

### Prerequisites
- **Python 3.10+**

### 1. Setup Environment
Clone the repository and make the auto-launcher script executable:
```bash
git clone <repository_url> omniscan
cd omniscan
chmod +x omniscan.sh
```

### 2. Auto-Install Dependencies & Tools
You can install the required system dependencies and security tools using the built-in installer. We provide a smart launcher script (`omniscan.sh`) that automatically creates a secure Python virtual environment (preventing `externally-managed-environment` errors on Linux) and installs its own requirements:

```bash
./omniscan.sh --install
```
*Note: On Windows, use standard Python commands instead: `python -m venv venv`, `venv\Scripts\activate`, `pip install -r requirements.txt`, `python scanner.py --install`.*

## How to Use

### Using the Web Dashboard (Recommended)
You can start the Flask web application to access the interactive dashboard interface natively through the launcher:
```bash
./omniscan.sh app
```
By default, the server binds to `0.0.0.0:5000`. Navigate to `http://localhost:5000` to manage targets, set target profiles (e.g., Joomla or Generic Web App), configure API keys, and launch scans graphically.

### Using the Command Line Interface (CLI)
You can also run scans headless or via the interactive terminal menu using the launcher:

```bash
# Start the interactive CLI menu
./omniscan.sh

# Run a headless passive scan on a specific URL with a specific profile
./omniscan.sh --target https://example.com --profile webapp --ci

# Run an active (deep) scan on a WordPress site
./omniscan.sh --target https://example.com --mode active --profile wordpress --ci

# Run a headless scan with email notifications
./omniscan.sh --target https://example.com --mode full --profile api --ci --email

# Generate a demo report (no scanning needed)
./omniscan.sh --demo
```

## Architecture & Process Flow

OmniScan orchestrates vulnerabilities scans by intelligently deploying a mix of Reconnaissance and Exploitation tools depending on the configuration provided.

### 1. Passive Reconnaissance (All Profiles)
Before launching aggressive payloads, the system maps the attack surface silently:
- **httpx & WhatWeb**: Identifies the live target, underlying technologies (PHP, Express, Nginx), and basic server headers.
- **Subfinder**: Scrapes public sources to discover adjacent subdomains (skipped on local `localhost` IPs).
- **SSLyze**: Audits the TLS/SSL configuration for weak ciphers or expired certificates.
- **Corsy**: Analyzes CORS (Cross-Origin Resource Sharing) headers for potential bypass vulnerabilities.

### 2. Profile-Based Targeting (Active & Passive)
The vulnerability scanner executes curated phases tailored natively to the target's platform. Depending on the target `profile` selected, specific CMS-auditing tools are unleashed:

| Profile | CMS-Specific Toolchain | Why It's Used |
|---------|------------------------|---------------|
| **WordPress**| `WPScan`, `Nuclei (WP Tags)` | Specializes in enumerating vulnerable WP plugins, outdated themes, and brute-forcing `/wp-login.php`. |
| **Joomla** | `JoomScan`, `CMSMap` | Focuses on known Joomla CVEs, exposed administrator panels, and directory listings. |
| **Drupal** | `Droopescan`, `CMSMap` | Rapidly maps installed Drupal nodes, themes, and version exposures. |
| **Web App**| `ffuf`, `Nuclei (CVE Tags)` | Operates entirely CMS-agnostic. Fuzzes for hidden directories and checks for generic server CVEs. |
| **Custom API**| `Nuclei (API Tags)` | Foregoes web-crawler logic and strictly analyzes JSON/XML endpoint vulnerabilities and misconfigurations. |

### 3. Active Exploitation & Deep Scanning
If `mode=active` or `full` is chosen, the scanner deploys aggressive, noisy penetration tools:
- **SQLMap**: Automatically injects SQL syntax into detected URL parameters and forms. On WP profiles, it strictly targets the login page. On generic Web Apps, it aggressively actively crawls inputs.
- **Dalfox**: An ultra-fast XSS (Cross-Site Scripting) scanner that analyzes DOM reflections and injects polyglot payloads.
- **Commix**: Specifically targets OS Command Injection vectors on input fields, looking for underlying shell access.
- **Wapiti**: A fully-featured web application vulnerability scanner acting as a black-box fuzzer.
- **OWASP ZAP / Nikto**: Traditional heavy-weight web scanners serving as a comprehensive fallback.

### Report Output Generation
When a scan completes, the framework compiles all identified vulnerabilities into a dedicated folder (`reports/<target>_<timestamp>/`). The following artifacts are generated:
- `report.html`: A highly interactive HTML file with severity charts, detailed evidence, and dynamic filtering. Excessively long URLs dynamically wrap boundaries natively to maintain UI format.
- `report.md`: A Markdown version ideal for copying into ticketing systems.
- `findings.json`: The raw, normalized JSON output.

## Configuration

Configuration files are located in the `config/` directory.

| File | Purpose |
|------|---------|
| `config/targets.json` | Saved URLs with their associated `profile` |
| `config/tokens.json` | API tokens (e.g., WPScan APIs) |
| `config/scan-config.json` | Default tool timeouts, rate limits, and thread bounds |
| `fixes/remediation-db.json` | Vulnerability to remediation mapping dictionary |

---
⚠️ **Legal Notice**: Only scan websites that you own or have explicit written authorization to test. Unauthorized scanning is illegal.
