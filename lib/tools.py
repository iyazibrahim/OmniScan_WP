"""Tool execution wrappers and orchestration for OmniScan."""

import ipaddress
import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from urllib.parse import urlparse

from lib import ui

TOOLS = [
    {"name": "httpx", "label": "httpx", "phase": "passive", "category": "fingerprint"},
    {"name": "whatweb", "label": "WhatWeb", "phase": "passive", "category": "fingerprint"},
    {"name": "nuclei", "label": "Nuclei", "phase": "passive", "category": "broad"},
    {"name": "nikto", "label": "Nikto", "phase": "passive", "category": "broad"},
    {"name": "sslyze", "label": "SSLyze", "phase": "passive", "category": "tls"},
    {"name": "subfinder", "label": "Subfinder", "phase": "passive", "category": "discovery"},
    {"name": "corsy", "label": "Corsy", "phase": "passive", "category": "headers"},
    {"name": "gau", "label": "gau", "phase": "passive", "category": "discovery"},
    {"name": "katana", "label": "Katana", "phase": "passive", "category": "discovery"},
    {"name": "wpscan", "label": "WPScan", "phase": "passive", "category": "cms"},
    {"name": "joomscan", "label": "JoomScan", "phase": "passive", "category": "cms"},
    {"name": "droopescan", "label": "Droopescan", "phase": "passive", "category": "cms"},
    {"name": "cmsmap", "label": "CMSMap", "phase": "active", "category": "cms"},
    {"name": "sqlmap", "label": "SQLMap", "phase": "active", "category": "validation"},
    {"name": "ffuf", "label": "ffuf", "phase": "active", "category": "content"},
    {"name": "feroxbuster", "label": "Feroxbuster", "phase": "active", "category": "content"},
    {"name": "arjun", "label": "Arjun", "phase": "active", "category": "parameters"},
    {"name": "dalfox", "label": "Dalfox", "phase": "active", "category": "validation"},
    {"name": "commix", "label": "Commix", "phase": "active", "category": "validation"},
    {"name": "wapiti", "label": "Wapiti", "phase": "active", "category": "validation"},
]

WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
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
        if installed[t["name"]]:
            ui.ok(f"{t['label']}")
        else:
            print(f"  {ui.Fore.RED}[-]{ui.Style.RESET_ALL} {t['label']} (not found: {t['name']})")

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


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _result_template(
    tool_name: str,
    tool_label: str,
    phase: str,
    command: list[str],
    status: str,
    note: str = "",
) -> dict:
    return {
        "name": tool_name,
        "label": tool_label,
        "phase": phase,
        "command": command,
        "status": status,
        "returncode": None,
        "duration_seconds": 0.0,
        "stdout_log": "",
        "stderr_log": "",
        "output_files": [],
        "primary_output": "",
        "note": note,
    }


def _missing_tool_result(tool_name: str, tool_label: str, phase: str) -> dict:
    return _result_template(tool_name, tool_label, phase, [], "missing", "Tool not found on PATH.")


def _write_text(path: Path, content: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", errors="ignore")


def _run_tool(
    cmd: list[str],
    tool_name: str,
    tool_label: str,
    phase: str,
    scan_dir: Path,
    output_files: list[Path] | None = None,
    stdout_file: Path | None = None,
    timeout: int = 600,
) -> dict:
    """Run a tool command and capture telemetry and logs."""
    result = _result_template(tool_name, tool_label, phase, cmd, "failed")
    start = time.perf_counter()

    stdout_log = scan_dir / f"{tool_name}.stdout.log"
    stderr_log = scan_dir / f"{tool_name}.stderr.log"

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        duration = time.perf_counter() - start
        _write_text(stdout_log, proc.stdout or "")
        _write_text(stderr_log, proc.stderr or "")
        if stdout_file is not None and proc.stdout:
            _write_text(stdout_file, proc.stdout)

        outputs = [str(p) for p in (output_files or []) if p.exists()]
        if stdout_file is not None and stdout_file.exists():
            outputs.append(str(stdout_file))

        status = "completed" if proc.returncode == 0 else "failed"
        if proc.returncode == 0 and not outputs and not (proc.stdout or "").strip():
            status = "completed_no_output"

        result.update(
            {
                "status": status,
                "returncode": proc.returncode,
                "duration_seconds": round(duration, 2),
                "stdout_log": str(stdout_log),
                "stderr_log": str(stderr_log),
                "output_files": outputs,
                "primary_output": outputs[0] if outputs else "",
                "note": "",
            }
        )
        if proc.returncode != 0 and proc.stderr:
            result["note"] = proc.stderr.strip()[:400]
        return result
    except FileNotFoundError:
        return _missing_tool_result(tool_name, tool_label, phase)
    except subprocess.TimeoutExpired:
        duration = time.perf_counter() - start
        _write_text(stderr_log, f"{tool_label} timed out after {timeout} seconds.")
        result.update(
            {
                "status": "timeout",
                "duration_seconds": round(duration, 2),
                "stdout_log": str(stdout_log),
                "stderr_log": str(stderr_log),
                "note": f"Timed out after {timeout} seconds.",
            }
        )
        return result
    except Exception as exc:
        duration = time.perf_counter() - start
        _write_text(stderr_log, str(exc))
        result.update(
            {
                "status": "failed",
                "duration_seconds": round(duration, 2),
                "stdout_log": str(stdout_log),
                "stderr_log": str(stderr_log),
                "note": str(exc)[:400],
            }
        )
        return result


def _resolve_wordlist(config: dict) -> str | None:
    configured = config.get("content_wordlist")
    if configured and Path(configured).exists():
        return configured
    for candidate in WORDLIST_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


def _extract_detect_text(*paths: Path) -> str:
    return "\n".join(_safe_read_text(path).lower() for path in paths if path.exists())


def detect_profile_from_artifacts(scan_dir: Path, url: str, requested_profile: str) -> dict:
    """Infer the target profile when the user selects auto mode."""
    if requested_profile and requested_profile != "auto":
        return {
            "requested_profile": requested_profile,
            "effective_profile": requested_profile,
            "confidence": "user-selected",
            "scores": {requested_profile: 10},
            "reasons": ["Profile provided explicitly by the operator."],
        }

    scores = {"wordpress": 0, "joomla": 0, "drupal": 0, "api": 0, "webapp": 0}
    reasons: list[str] = []
    detect_text = _extract_detect_text(
        scan_dir / "httpx.json",
        scan_dir / "whatweb.json",
        scan_dir / "whatweb.stdout.log",
        scan_dir / "nuclei.jsonl",
    )
    parsed = urlparse(url)
    path_hint = (parsed.path or "").lower()

    patterns = {
        "wordpress": ["wordpress", "wp-content", "wp-json", "wp-includes", "xmlrpc.php"],
        "joomla": ["joomla", "com_content", "/administrator", "joomscan"],
        "drupal": ["drupal", "/sites/default", "/misc/", "droopescan"],
        "api": ["application/json", "openapi", "swagger", "graphql", "/api/", "rest api"],
    }

    for profile, markers in patterns.items():
        for marker in markers:
            if marker in detect_text or marker in path_hint:
                scores[profile] += 2
                reasons.append(f"Matched {profile} indicator: {marker}")

    if "x-powered-by" in detect_text or "server" in detect_text:
        scores["webapp"] += 1
    if path_hint.startswith("/api") or path_hint.endswith(".json"):
        scores["api"] += 2

    best_profile = max(scores, key=scores.get)
    if scores[best_profile] <= 0:
        best_profile = "api" if path_hint.startswith("/api") else "webapp"
        reasons.append("No strong CMS markers detected; defaulted to generic coverage.")

    confidence = "high" if scores[best_profile] >= 4 else "medium" if scores[best_profile] >= 2 else "low"
    return {
        "requested_profile": "auto",
        "effective_profile": best_profile,
        "confidence": confidence,
        "scores": scores,
        "reasons": reasons[:8],
    }


def run_httpx(url: str, config: dict, scan_dir: Path) -> dict:
    ui.status("Running httpx probe...")
    output_file = scan_dir / "httpx.json"
    rate = str(config.get("httpx_rate_limit", 25))
    cmd = [
        "httpx",
        "-u",
        url,
        "-json",
        "-o",
        str(output_file),
        "-rate-limit",
        rate,
        "-silent",
        "-status-code",
        "-title",
        "-tech-detect",
        "-web-server",
        "-follow-host-redirects",
    ]
    result = _run_tool(cmd, "httpx", "httpx", "passive", scan_dir, output_files=[output_file])
    if result["status"].startswith("completed"):
        ui.ok("httpx complete.")
    return result


def run_whatweb(url: str, config: dict, scan_dir: Path) -> dict:
    ui.status("Running WhatWeb fingerprinting...")
    output_file = scan_dir / "whatweb.json"
    threads = str(config.get("whatweb_max_threads", 10))
    cmd = ["whatweb", url, f"--log-json={output_file}", "--max-threads", threads, "-q"]
    result = _run_tool(cmd, "whatweb", "WhatWeb", "passive", scan_dir, output_files=[output_file])
    if result["status"].startswith("completed"):
        ui.ok("WhatWeb complete.")
    return result


def run_nuclei(url: str, config: dict, scan_dir: Path, profile: str) -> dict:
    ui.status("Running Nuclei...")
    output_file = scan_dir / "nuclei.jsonl"
    if profile == "wordpress":
        tags = config.get("nuclei_tags_wordpress", config.get("nuclei_tags", "wordpress,wp-plugin,wp-theme,cve,misconfig,exposure"))
    elif profile == "joomla":
        tags = config.get("nuclei_tags_joomla", "joomla,cve,misconfig,exposure")
    elif profile == "drupal":
        tags = config.get("nuclei_tags_drupal", "drupal,cve,misconfig,exposure")
    elif profile == "api":
        tags = config.get("nuclei_tags_api", "api,graphql,cve,exposure,misconfig,default-login")
    else:
        tags = config.get(
            "nuclei_tags_broad",
            "cve,rce,lfi,sqli,xss,ssrf,exposure,misconfig,default-login,redirect,takeover,token,credentials",
        )

    severities = config.get("nuclei_severity", "critical,high,medium,low,info")
    rate = str(config.get("nuclei_rate_limit", 25))
    cmd = [
        "nuclei",
        "-u",
        url,
        "-tags",
        tags,
        "-severity",
        severities,
        "-rate-limit",
        rate,
        "-jsonl",
        "-o",
        str(output_file),
        "-silent",
    ]
    result = _run_tool(cmd, "nuclei", "Nuclei", "passive", scan_dir, output_files=[output_file], timeout=900)
    if result["status"].startswith("completed"):
        ui.ok("Nuclei complete.")
    return result


def run_nikto(url: str, config: dict, scan_dir: Path) -> dict:
    ui.status("Running Nikto scan...")
    output_file = scan_dir / "nikto.json"
    pause = str(config.get("nikto_pause_seconds", 1))
    cmd = ["nikto", "-h", url, "-Format", "json", "-output", str(output_file), "-Pause", pause, "-nointeractive"]
    result = _run_tool(cmd, "nikto", "Nikto", "passive", scan_dir, output_files=[output_file], timeout=900)
    if result["status"].startswith("completed"):
        ui.ok("Nikto complete.")
    return result


def run_sslyze(hostname: str, scan_dir: Path) -> dict:
    ui.status("Running SSLyze TLS audit...")
    output_file = scan_dir / "sslyze.json"
    cmd = ["sslyze", hostname, f"--json_out={output_file}"]
    result = _run_tool(cmd, "sslyze", "SSLyze", "passive", scan_dir, output_files=[output_file], timeout=900)
    if result["status"].startswith("completed"):
        ui.ok("SSLyze complete.")
    return result


def run_subfinder(hostname: str, scan_dir: Path) -> dict:
    ui.status("Running Subfinder...")
    output_file = scan_dir / "subfinder.json"
    cmd = ["subfinder", "-d", hostname, "-oJ", "-o", str(output_file), "-silent"]
    result = _run_tool(cmd, "subfinder", "Subfinder", "passive", scan_dir, output_files=[output_file])
    if result["status"].startswith("completed"):
        ui.ok("Subfinder complete.")
    return result


def run_corsy(url: str, scan_dir: Path) -> dict:
    ui.status("Running Corsy...")
    output_file = scan_dir / "corsy.txt"
    cmd = ["corsy", "-u", url]
    result = _run_tool(cmd, "corsy", "Corsy", "passive", scan_dir, output_files=[output_file], stdout_file=output_file)
    if result["status"].startswith("completed"):
        ui.ok("Corsy complete.")
    return result


def run_gau(hostname: str, scan_dir: Path) -> dict:
    ui.status("Running gau...")
    output_file = scan_dir / "gau.txt"
    cmd = ["gau", "--threads", "5", hostname]
    result = _run_tool(cmd, "gau", "gau", "passive", scan_dir, output_files=[output_file], stdout_file=output_file)
    if result["status"].startswith("completed"):
        ui.ok("gau complete.")
    return result


def run_katana(url: str, scan_dir: Path) -> dict:
    ui.status("Running Katana crawler...")
    output_file = scan_dir / "katana.jsonl"
    cmd = ["katana", "-u", url, "-jsonl", "-o", str(output_file), "-silent"]
    result = _run_tool(cmd, "katana", "Katana", "passive", scan_dir, output_files=[output_file], timeout=900)
    if result["status"].startswith("completed"):
        ui.ok("Katana complete.")
    return result


def run_wpscan(url: str, config: dict, tokens: dict, scan_dir: Path, is_local_target: bool) -> dict:
    ui.status("Running WPScan...")
    output_file = scan_dir / "wpscan.json"
    enum = config.get("wpscan_enumerate", "vp,vt,u")
    threads = str(config.get("wpscan_max_threads", 1))
    cmd = ["wpscan", "--url", url, "--enumerate", enum, "--max-threads", threads, "--format", "json", "--output", str(output_file), "--no-banner"]
    if is_local_target:
        cmd.append("--disable-tls-checks")
    token = tokens.get("wpscan_api_token", "")
    if token:
        cmd.extend(["--api-token", token])
    result = _run_tool(cmd, "wpscan", "WPScan", "passive", scan_dir, output_files=[output_file], timeout=900)
    if result["status"].startswith("completed"):
        ui.ok("WPScan complete.")
    return result


def run_joomscan(url: str, scan_dir: Path) -> dict:
    ui.status("Running JoomScan...")
    output_file = scan_dir / "joomscan.txt"
    cmd = ["joomscan", "--url", url]
    result = _run_tool(cmd, "joomscan", "JoomScan", "passive", scan_dir, output_files=[output_file], stdout_file=output_file, timeout=900)
    if result["status"].startswith("completed"):
        ui.ok("JoomScan complete.")
    return result


def run_droopescan(url: str, scan_dir: Path) -> dict:
    ui.status("Running Droopescan...")
    output_file = scan_dir / "droopescan.json"
    cmd = ["droopescan", "scan", "drupal", "-u", url, "-o", "json"]
    result = _run_tool(cmd, "droopescan", "Droopescan", "passive", scan_dir, output_files=[output_file], stdout_file=output_file, timeout=900)
    if result["status"].startswith("completed"):
        ui.ok("Droopescan complete.")
    return result


def run_cmsmap(url: str, scan_dir: Path) -> dict:
    ui.status("Running CMSMap...")
    output_file = scan_dir / "cmsmap.json"
    cmd = ["cmsmap", "-t", url, "-o", str(output_file), "-f", "J"]
    result = _run_tool(cmd, "cmsmap", "CMSMap", "active", scan_dir, output_files=[output_file], timeout=900)
    if result["status"].startswith("completed"):
        ui.ok("CMSMap complete.")
    return result


def run_sqlmap(url: str, scan_dir: Path, profile: str) -> dict:
    ui.status("Running SQLMap...")
    output_dir = scan_dir / "sqlmap-out"
    output_dir.mkdir(parents=True, exist_ok=True)
    cmd = ["sqlmap", "--batch", "--output-dir", str(output_dir), "--level=2", "--risk=2"]
    if profile == "wordpress":
        cmd.extend(["-u", f"{url.rstrip('/')}/wp-login.php", "--forms"])
    elif profile == "joomla":
        cmd.extend(["-u", f"{url.rstrip('/')}/administrator/index.php", "--forms"])
    else:
        cmd.extend(["-u", url, "--crawl=2", "--forms"])
    result = _run_tool(cmd, "sqlmap", "SQLMap", "active", scan_dir, output_files=[output_dir], timeout=1200)
    if result["status"].startswith("completed"):
        ui.ok("SQLMap complete.")
    return result


def run_ffuf(url: str, config: dict, scan_dir: Path) -> dict:
    ui.status("Running ffuf...")
    wordlist = _resolve_wordlist(config)
    if not wordlist:
        return _result_template("ffuf", "ffuf", "active", [], "skipped", "No compatible content-discovery wordlist found.")
    output_file = scan_dir / "ffuf.json"
    cmd = ["ffuf", "-u", f"{url.rstrip('/')}/FUZZ", "-w", wordlist, "-o", str(output_file), "-of", "json", "-s"]
    result = _run_tool(cmd, "ffuf", "ffuf", "active", scan_dir, output_files=[output_file], timeout=1200)
    if result["status"].startswith("completed"):
        ui.ok("ffuf complete.")
    return result


def run_feroxbuster(url: str, config: dict, scan_dir: Path) -> dict:
    ui.status("Running Feroxbuster...")
    wordlist = _resolve_wordlist(config)
    if not wordlist:
        return _result_template("feroxbuster", "Feroxbuster", "active", [], "skipped", "No compatible content-discovery wordlist found.")
    output_file = scan_dir / "feroxbuster.json"
    cmd = ["feroxbuster", "-u", url, "-w", wordlist, "--json", "-o", str(output_file), "-q"]
    result = _run_tool(cmd, "feroxbuster", "Feroxbuster", "active", scan_dir, output_files=[output_file], timeout=1200)
    if result["status"].startswith("completed"):
        ui.ok("Feroxbuster complete.")
    return result


def run_arjun(url: str, scan_dir: Path) -> dict:
    ui.status("Running Arjun parameter discovery...")
    output_file = scan_dir / "arjun.txt"
    cmd = ["arjun", "-u", url, "-oT", str(output_file)]
    result = _run_tool(cmd, "arjun", "Arjun", "active", scan_dir, output_files=[output_file], timeout=900)
    if result["status"].startswith("completed"):
        ui.ok("Arjun complete.")
    return result


def run_dalfox(url: str, scan_dir: Path) -> dict:
    ui.status("Running Dalfox...")
    output_file = scan_dir / "dalfox.json"
    cmd = ["dalfox", "url", url, "--format", "json", "-o", str(output_file), "--no-color"]
    result = _run_tool(cmd, "dalfox", "Dalfox", "active", scan_dir, output_files=[output_file], timeout=1200)
    if result["status"].startswith("completed"):
        ui.ok("Dalfox complete.")
    return result


def run_commix(url: str, scan_dir: Path) -> dict:
    ui.status("Running Commix...")
    output_file = scan_dir / "commix.txt"
    cmd = ["commix", "--url", url, "--batch", "--crawl=2"]
    result = _run_tool(cmd, "commix", "Commix", "active", scan_dir, output_files=[output_file], stdout_file=output_file, timeout=1200)
    if result["status"].startswith("completed"):
        ui.ok("Commix complete.")
    return result


def run_wapiti(url: str, scan_dir: Path) -> dict:
    ui.status("Running Wapiti...")
    output_file = scan_dir / "wapiti.json"
    cmd = ["wapiti", "-u", url, "-f", "json", "-o", str(output_file)]
    result = _run_tool(cmd, "wapiti", "Wapiti", "active", scan_dir, output_files=[output_file], timeout=1200)
    if result["status"].startswith("completed"):
        ui.ok("Wapiti complete.")
    return result


def _run_registered_tool(
    tool_name: str,
    phase: str,
    installed: dict[str, bool],
    runner,
) -> dict:
    tool_meta = next((t for t in TOOLS if t["name"] == tool_name), {"label": tool_name})
    if not installed.get(tool_name):
        ui.warn(f"Skipping {tool_name} (not installed or missing from PATH).")
        return _missing_tool_result(tool_name, tool_meta["label"], phase)
    return runner()


def run_all_tools(url: str, scan_dir: Path, config: dict, tokens: dict, mode: str, profile: str = "auto") -> dict:
    """Run the scan plan and return rich execution metadata."""
    installed = get_installed_tools()
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname or url
    local_target = is_local(url)
    scan_dir.mkdir(parents=True, exist_ok=True)

    tool_runs: list[dict] = []

    if mode in ("passive", "full"):
        generic_passive = [
            ("httpx", lambda: run_httpx(url, config, scan_dir)),
            ("whatweb", lambda: run_whatweb(url, config, scan_dir)),
            ("corsy", lambda: run_corsy(url, scan_dir)),
            ("gau", lambda: run_gau(hostname, scan_dir)),
            ("katana", lambda: run_katana(url, scan_dir)),
        ]
        for tool_name, runner in generic_passive:
            tool_runs.append(_run_registered_tool(tool_name, "passive", installed, runner))

        if not local_target and parsed_url.scheme == "https":
            tool_runs.append(_run_registered_tool("sslyze", "passive", installed, lambda: run_sslyze(hostname, scan_dir)))

        try:
            is_private_ip = ipaddress.ip_address(hostname).is_private
        except ValueError:
            is_private_ip = False
        if not local_target and not is_private_ip:
            tool_runs.append(_run_registered_tool("subfinder", "passive", installed, lambda: run_subfinder(hostname, scan_dir)))

    profile_info = detect_profile_from_artifacts(scan_dir, url, profile)
    effective_profile = profile_info["effective_profile"]

    if mode in ("passive", "full"):
        tool_runs.append(_run_registered_tool("nuclei", "passive", installed, lambda: run_nuclei(url, config, scan_dir, effective_profile)))
        tool_runs.append(_run_registered_tool("nikto", "passive", installed, lambda: run_nikto(url, config, scan_dir)))
        if effective_profile == "wordpress":
            tool_runs.append(_run_registered_tool("wpscan", "passive", installed, lambda: run_wpscan(url, config, tokens, scan_dir, local_target)))
        elif effective_profile == "joomla":
            tool_runs.append(_run_registered_tool("joomscan", "passive", installed, lambda: run_joomscan(url, scan_dir)))
        elif effective_profile == "drupal":
            tool_runs.append(_run_registered_tool("droopescan", "passive", installed, lambda: run_droopescan(url, scan_dir)))

    if mode in ("active", "full"):
        if effective_profile in ("wordpress", "joomla", "drupal"):
            tool_runs.append(_run_registered_tool("cmsmap", "active", installed, lambda: run_cmsmap(url, scan_dir)))
        active_tools = [
            ("sqlmap", lambda: run_sqlmap(url, scan_dir, effective_profile)),
            ("ffuf", lambda: run_ffuf(url, config, scan_dir)),
            ("feroxbuster", lambda: run_feroxbuster(url, config, scan_dir)),
            ("arjun", lambda: run_arjun(url, scan_dir)),
            ("dalfox", lambda: run_dalfox(url, scan_dir)),
            ("wapiti", lambda: run_wapiti(url, scan_dir)),
        ]
        if effective_profile in ("webapp", "api"):
            active_tools.append(("commix", lambda: run_commix(url, scan_dir)))
        for tool_name, runner in active_tools:
            tool_runs.append(_run_registered_tool(tool_name, "active", installed, runner))

    completed = [item["name"] for item in tool_runs if item["status"] in ("completed", "completed_no_output")]
    profile_info["tools_completed"] = completed
    profile_info["tools_attempted"] = [item["name"] for item in tool_runs]

    return {
        "requested_profile": profile,
        "effective_profile": effective_profile,
        "profile_detection": profile_info,
        "tools": tool_runs,
        "tools_used": completed,
    }
