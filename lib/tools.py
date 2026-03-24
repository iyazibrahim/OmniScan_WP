"""Tool execution wrappers for all 9 security scanning tools."""

import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse

from lib import ui

# ── Tool definitions ────────────────────────────────────────────────────────────

TOOLS = [
    {"name": "nuclei",  "label": "Nuclei",    "phase": "passive"},
    {"name": "wpscan",  "label": "WPScan",    "phase": "passive"},
    {"name": "nikto",   "label": "Nikto",     "phase": "passive"},
    {"name": "zap-cli", "label": "OWASP ZAP", "phase": "active"},
    {"name": "sqlmap",  "label": "SQLMap",     "phase": "active"},
    {"name": "sslyze",  "label": "SSLyze",    "phase": "passive"},
    {"name": "whatweb", "label": "WhatWeb",    "phase": "passive"},
    {"name": "httpx",   "label": "httpx",      "phase": "passive"},
    {"name": "cmsmap",  "label": "CMSMap",     "phase": "active"},
]


def is_tool_installed(name: str) -> bool:
    """Check if a CLI tool is available on PATH."""
    return shutil.which(name) is not None


def get_installed_tools() -> dict[str, bool]:
    """Return dict of tool_name -> is_installed."""
    return {t["name"]: is_tool_installed(t["name"]) for t in TOOLS}


def show_tool_status():
    """Print tool availability to the terminal."""
    installed = get_installed_tools()
    total = sum(1 for v in installed.values() if v)

    ui.section("Tool Status")
    for t in TOOLS:
        name = t["name"]
        if installed[name]:
            ui.ok(f"{t['label']}")
        else:
            print(f"  {ui.Fore.RED}[-]{ui.Style.RESET_ALL} {t['label']} (not found: {name})")

    print(f"\n  {total} / {len(TOOLS)} tools available.\n")
    return installed


# ── Tool runners ────────────────────────────────────────────────────────────────

def _run_tool(cmd: list[str], tool_label: str) -> bool:
    """Run a tool command, return True if successful."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # 10-minute timeout per tool
        )
        return result.returncode == 0
    except FileNotFoundError:
        ui.err(f"{tool_label} not found on PATH.")
        return False
    except subprocess.TimeoutExpired:
        ui.warn(f"{tool_label} timed out after 10 minutes.")
        return False
    except Exception as e:
        ui.err(f"{tool_label} failed: {e}")
        return False


def run_nuclei(url: str, config: dict, output_file: Path) -> bool:
    ui.status("Running Nuclei...")
    tags = config.get("nuclei_tags", "wordpress,wp-plugin,wp-theme,cve")
    sev = config.get("nuclei_severity", "critical,high,medium,low")
    rate = config.get("nuclei_rate_limit", 150)

    cmd = [
        "nuclei", "-u", url,
        "-tags", tags, "-severity", sev,
        "-rate-limit", str(rate),
        "-jsonl", "-o", str(output_file),
        "-silent",
    ]
    success = _run_tool(cmd, "Nuclei")
    if success and output_file.exists():
        lines = output_file.read_text(encoding="utf-8", errors="ignore").strip().splitlines()
        ui.ok(f"Nuclei found {len(lines)} result(s).")
    elif success:
        ui.warn("Nuclei completed but produced no output.")
    return success


def run_wpscan(url: str, config: dict, tokens: dict, output_file: Path) -> bool:
    ui.status("Running WPScan...")
    enum = config.get("wpscan_enumerate", "vp,vt,u")
    threads = config.get("wpscan_max_threads", 1)

    cmd = [
        "wpscan", "--url", url,
        "--enumerate", enum,
        "--max-threads", str(threads),
        "--format", "json",
        "--output", str(output_file),
        "--no-banner",
    ]
    token = tokens.get("wpscan_api_token", "")
    if token:
        cmd.extend(["--api-token", token])

    success = _run_tool(cmd, "WPScan")
    if output_file.exists():
        ui.ok("WPScan complete.")
    else:
        ui.warn("WPScan produced no output.")
    return success


def run_nikto(url: str, output_file: Path, config: dict) -> bool:
    ui.status("Running Nikto scan...")
    pause = config.get("nikto_pause_seconds", 1)
    
    cmd = [
        "nikto", "-h", url, 
        "-Format", "json", 
        "-output", str(output_file), 
        "-Pause", str(pause),
        "-nointeractive"
    ]
    success = _run_tool(cmd, "Nikto")
    if output_file.exists():
        ui.ok("Nikto complete.")
    else:
        ui.warn("Nikto produced no output.")
    return success


def run_sslyze(hostname: str, output_file: Path) -> bool:
    ui.status("Running SSLyze TLS audit...")
    cmd = ["sslyze", hostname, f"--json_out={output_file}"]
    success = _run_tool(cmd, "SSLyze")
    if output_file.exists():
        ui.ok("SSLyze complete.")
    else:
        ui.warn("SSLyze produced no output.")
    return success


def run_whatweb(url: str, output_file: Path, config: dict) -> bool:
    ui.status("Running WhatWeb fingerprinting...")
    threads = config.get("whatweb_max_threads", 5)
    
    cmd = [
        "whatweb", url, 
        f"--log-json={output_file}", 
        "--max-threads", str(threads),
        "-q"
    ]
    success = _run_tool(cmd, "WhatWeb")
    if output_file.exists():
        ui.ok("WhatWeb complete.")
    else:
        ui.warn("WhatWeb produced no output.")
    return success


def run_httpx(url: str, output_file: Path, config: dict) -> bool:
    ui.status("Running httpx probe...")
    rate = config.get("httpx_rate_limit", 10)
    
    cmd = [
        "httpx", "-u", url, "-json", "-o", str(output_file),
        "-rate-limit", str(rate),
        "-silent", "-status-code", "-title", "-tech-detect", "-web-server",
    ]
    success = _run_tool(cmd, "httpx")
    if output_file.exists():
        ui.ok("httpx complete.")
    else:
        ui.warn("httpx produced no output.")
    return success


def run_cmsmap(url: str, output_file: Path) -> bool:
    ui.status("Running CMSMap scan...")
    cmd = ["cmsmap", "-t", url, "-o", str(output_file), "-f", "J"]
    success = _run_tool(cmd, "CMSMap")
    if output_file.exists():
        ui.ok("CMSMap complete.")
    else:
        ui.warn("CMSMap produced no output.")
    return success


def run_sqlmap(url: str, output_file: Path) -> bool:
    ui.status("Running SQLMap (login form test)...")
    login_url = f"{url.rstrip('/')}/wp-login.php"
    output_dir = str(output_file.parent)
    cmd = [
        "sqlmap", "-u", login_url,
        "--forms", "--batch",
        "--output-dir", output_dir,
        "--level=1", "--risk=1",
    ]
    success = _run_tool(cmd, "SQLMap")
    if success:
        ui.ok("SQLMap complete.")
    return success


# ── Orchestrator ────────────────────────────────────────────────────────────────

def run_all_tools(url: str, scan_dir: Path, config: dict, tokens: dict, mode: str) -> list[str]:
    """Run all applicable tools for the given mode. Returns list of tool names that ran."""
    installed = get_installed_tools()
    hostname = urlparse(url).hostname or url
    tools_ran = []

    passive_tools = [
        ("nuclei",  lambda: run_nuclei(url, config, scan_dir / "nuclei.jsonl")),
        ("wpscan",  lambda: run_wpscan(url, config, tokens, scan_dir / "wpscan.json")),
        ("nikto",   lambda: run_nikto(url, scan_dir / "nikto.json", config)),
        ("sslyze",  lambda: run_sslyze(hostname, scan_dir / "sslyze.json")),
        ("whatweb", lambda: run_whatweb(url, scan_dir / "whatweb.json", config)),
        ("httpx",   lambda: run_httpx(url, scan_dir / "httpx.json", config)),
    ]

    active_tools = [
        ("cmsmap",  lambda: run_cmsmap(url, scan_dir / "cmsmap.json")),
        ("sqlmap",  lambda: run_sqlmap(url, scan_dir / "sqlmap.json")),
    ]

    tools_to_run = []
    if mode in ("passive", "full"):
        tools_to_run.extend(passive_tools)
    if mode in ("active", "full"):
        tools_to_run.extend(active_tools)

    for tool_name, runner in tools_to_run:
        if installed.get(tool_name):
            runner()
            tools_ran.append(tool_name)
        else:
            ui.warn(f"Skipping {tool_name} (not installed).")

    return tools_ran
