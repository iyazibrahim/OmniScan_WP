"""Tool execution wrappers for all security scanning tools."""

import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlparse
import ipaddress

from lib import ui

# ── Tool definitions ────────────────────────────────────────────────────────────

TOOLS = [
    # Core general tools
    {"name": "nuclei",  "label": "Nuclei",    "phase": "passive"},
    {"name": "nikto",   "label": "Nikto",     "phase": "passive"},
    {"name": "whatweb", "label": "WhatWeb",    "phase": "passive"},
    {"name": "httpx",   "label": "httpx",      "phase": "passive"},
    {"name": "sslyze",  "label": "SSLyze",    "phase": "passive"},
    {"name": "subfinder", "label": "Subfinder", "phase": "passive"},
    {"name": "gitleaks", "label": "Gitleaks", "phase": "passive"},
    {"name": "corsy",   "label": "Corsy",     "phase": "passive"},
    
    # CMS Specific
    {"name": "wpscan",  "label": "WPScan",    "phase": "passive"},
    {"name": "joomscan","label": "JoomScan",  "phase": "passive"},
    {"name": "droopescan","label": "Droopescan","phase": "passive"},
    {"name": "cmsmap",  "label": "CMSMap",     "phase": "active"},

    # Active / Deep Scanners
    {"name": "zap-cli", "label": "OWASP ZAP", "phase": "active"},
    {"name": "sqlmap",  "label": "SQLMap",     "phase": "active"},
    {"name": "ffuf",    "label": "ffuf",       "phase": "active"},
    {"name": "dalfox",  "label": "Dalfox",     "phase": "active"},
    {"name": "commix",  "label": "Commix",     "phase": "active"},
    {"name": "wapiti",  "label": "Wapiti",     "phase": "active"},
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


def is_local(url: str) -> bool:
    hostname = urlparse(url).hostname or ""
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private
    except ValueError:
        return hostname.endswith(".local")


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


def run_nuclei(url: str, config: dict, output_file: Path, profile: str) -> bool:
    ui.status("Running Nuclei...")
    if profile == "wordpress":
        tags = config.get("nuclei_tags", "wordpress,wp-plugin,wp-theme,cve")
    elif profile == "joomla":
        tags = "joomla,cve"
    elif profile == "drupal":
        tags = "drupal,cve"
    else:
        tags = "cve,misconfiguration,vulnerability,exposed-panels"

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


def run_wpscan(url: str, config: dict, tokens: dict, output_file: Path, is_local_target: bool) -> bool:
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
    if is_local_target:
        cmd.append("--disable-tls-checks")
        
    token = tokens.get("wpscan_api_token", "")
    if token:
        cmd.extend(["--api-token", token])

    success = _run_tool(cmd, "WPScan")
    if output_file.exists():
        ui.ok("WPScan complete.")
    return success


def run_joomscan(url: str, output_file: Path) -> bool:
    ui.status("Running JoomScan...")
    cmd = ["joomscan", "--url", url]
    success = _run_tool(cmd, "JoomScan")
    if success: ui.ok("JoomScan complete.")
    return success


def run_droopescan(url: str, output_file: Path) -> bool:
    ui.status("Running Droopescan...")
    cmd = ["droopescan", "scan", "drupal", "-u", url, "-o", "json"]
    try:
        with open(output_file, 'w') as f:
            subprocess.run(cmd, stdout=f, timeout=600)
        ui.ok("Droopescan complete.")
        return True
    except Exception as e:
        ui.err(f"Droopescan failed: {e}")
        return False


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
    if output_file.exists(): ui.ok("Nikto complete.")
    return success


def run_sslyze(hostname: str, output_file: Path) -> bool:
    ui.status("Running SSLyze TLS audit...")
    cmd = ["sslyze", hostname, f"--json_out={output_file}"]
    success = _run_tool(cmd, "SSLyze")
    if output_file.exists(): ui.ok("SSLyze complete.")
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
    if output_file.exists(): ui.ok("WhatWeb complete.")
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
    if output_file.exists(): ui.ok("httpx complete.")
    return success


def run_cmsmap(url: str, output_file: Path) -> bool:
    ui.status("Running CMSMap scan...")
    cmd = ["cmsmap", "-t", url, "-o", str(output_file), "-f", "J"]
    success = _run_tool(cmd, "CMSMap")
    if output_file.exists(): ui.ok("CMSMap complete.")
    return success


def run_sqlmap(url: str, output_file: Path, profile: str) -> bool:
    ui.status("Running SQLMap (login form test)...")
    output_dir = str(output_file.parent)
    cmd = [
        "sqlmap", "--batch", "--output-dir", output_dir, "--level=1", "--risk=1",
    ]
    if profile == "wordpress":
        cmd.extend(["-u", f"{url.rstrip('/')}/wp-login.php", "--forms"])
    elif profile == "joomla":
        cmd.extend(["-u", f"{url.rstrip('/')}/administrator/index.php", "--forms"])
    else:
        cmd.extend(["-u", url, "--crawl=2", "--forms"])
        
    success = _run_tool(cmd, "SQLMap")
    if success: ui.ok("SQLMap complete.")
    return success


def run_subfinder(hostname: str, output_file: Path) -> bool:
    ui.status("Running Subfinder...")
    cmd = ["subfinder", "-d", hostname, "-oJ", "-o", str(output_file), "-silent"]
    success = _run_tool(cmd, "Subfinder")
    if output_file.exists(): ui.ok("Subfinder complete.")
    return success


def run_corsy(url: str, output_file: Path) -> bool:
    ui.status("Running Corsy...")
    cmd = ["corsy", "-u", url]
    try:
        with open(output_file, 'w') as f:
            subprocess.run(cmd, stdout=f, timeout=600)
        ui.ok("Corsy complete.")
        return True
    except Exception:
        return False


def run_ffuf(url: str, output_file: Path) -> bool:
    ui.status("Running ffuf...")
    cmd = ["ffuf", "-u", f"{url.rstrip('/')}/FUZZ", "-w", "/usr/share/wordlists/dirb/common.txt", "-o", str(output_file), "-of", "json", "-s"]
    success = _run_tool(cmd, "ffuf")
    if success: ui.ok("ffuf complete.")
    return success


def run_dalfox(url: str, output_file: Path) -> bool:
    ui.status("Running Dalfox...")
    cmd = ["dalfox", "url", url, "-o", str(output_file), "--format", "json"]
    success = _run_tool(cmd, "Dalfox")
    if success: ui.ok("Dalfox complete.")
    return success


def run_commix(url: str, output_file: Path) -> bool:
    ui.status("Running Commix...")
    cmd = ["commix", "--url", url, "--batch", "--crawl=2"]
    success = _run_tool(cmd, "Commix")
    if success: ui.ok("Commix complete.")
    return success


def run_wapiti(url: str, output_file: Path) -> bool:
    ui.status("Running Wapiti...")
    cmd = ["wapiti", "-u", url, "-f", "json", "-o", str(output_file)]
    success = _run_tool(cmd, "Wapiti")
    if success: ui.ok("Wapiti complete.")
    return success



# ── Orchestrator ────────────────────────────────────────────────────────────────

def run_all_tools(url: str, scan_dir: Path, config: dict, tokens: dict, mode: str, profile: str = "wordpress") -> list[str]:
    """Run all applicable tools for the given mode and profile. Returns list of tools ran."""
    installed = get_installed_tools()
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or url
    is_local_env = is_local(url)
    tools_ran = []

    # Dynamic Tool Loading List (Name, RunnerFunction)
    passive_tools = []
    active_tools = []

    # 1. Nuclei (Always runs, tags adjust to profile)
    passive_tools.append(("nuclei", lambda: run_nuclei(url, config, scan_dir / "nuclei.jsonl", profile)))
    
    # 2. Nikto, WhatWeb, httpx (Always run)
    passive_tools.append(("nikto", lambda: run_nikto(url, scan_dir / "nikto.json", config)))
    passive_tools.append(("whatweb", lambda: run_whatweb(url, scan_dir / "whatweb.json", config)))
    passive_tools.append(("httpx", lambda: run_httpx(url, scan_dir / "httpx.json", config)))
    
    # 3. SSLyze (Only on public https)
    if not is_local_env and parsed_url.scheme == "https":
        passive_tools.append(("sslyze", lambda: run_sslyze(hostname, scan_dir / "sslyze.json")))
    
    # 4. Subfinder (Only on public domains)
    is_private_ip = False
    try:
        is_private_ip = ipaddress.ip_address(hostname).is_private
    except ValueError:
        pass
        
    if not is_local_env and not is_private_ip:
        passive_tools.append(("subfinder", lambda: run_subfinder(hostname, scan_dir / "subfinder.json")))
        
    # 5. Corsy (Run everywhere)
    passive_tools.append(("corsy",  lambda: run_corsy(url, scan_dir / "corsy.json")))

    # CMS-Specific Routing (Passive)
    if profile == "wordpress":
        passive_tools.append(("wpscan", lambda: run_wpscan(url, config, tokens, scan_dir / "wpscan.json", is_local_env)))
    elif profile == "joomla":
        passive_tools.append(("joomscan", lambda: run_joomscan(url, scan_dir / "joomscan.txt")))
    elif profile == "drupal":
        passive_tools.append(("droopescan", lambda: run_droopescan(url, scan_dir / "droopescan.json")))
        
    active_tools.append(("cmsmap", lambda: run_cmsmap(url, scan_dir / "cmsmap.json")))

    # General Web App / API Active Tools
    active_tools.append(("sqlmap", lambda: run_sqlmap(url, scan_dir / "sqlmap.json", profile)))
    active_tools.append(("ffuf",   lambda: run_ffuf(url, scan_dir / "ffuf.json")))
    active_tools.append(("dalfox", lambda: run_dalfox(url, scan_dir / "dalfox.json")))
    active_tools.append(("wapiti", lambda: run_wapiti(url, scan_dir / "wapiti.json")))
    
    if profile in ("webapp", "api"):
        active_tools.append(("commix", lambda: run_commix(url, scan_dir / "commix.json")))

    # Execute
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
            ui.warn(f"Skipping {tool_name} (not installed or missing from PATH).")

    return tools_ran
