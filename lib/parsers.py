"""Result parsers for security tool JSON outputs."""

import json
from pathlib import Path

from lib import ui


def _safe_load_json(path: Path) -> dict | list | None:
    """Load a JSON file safely, handling JSONL and malformed files."""
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="ignore").strip()
        if not text:
            return None
        return json.loads(text)
    except json.JSONDecodeError:
        # Might be JSONL (one JSON object per line)
        results = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return results if results else None


def _make_finding(title: str, severity: str, tool: str,
                  description: str = "", cve: str = "",
                  evidence: str = "", references: list[str] | None = None) -> dict:
    """Create a normalized finding dict."""
    return {
        "id": "",  # Assigned later
        "title": title,
        "severity": severity.lower(),
        "source_tool": tool,
        "description": description,
        "cve": cve or "",
        "evidence": evidence or "",
        "fix": "",
        "fix_steps": [],
        "references": references or [],
    }


# ── Nuclei Parser ──────────────────────────────────────────────────────────────

def parse_nuclei(results_file: Path) -> list[dict]:
    """Parse Nuclei JSONL output into normalized findings."""
    findings = []
    data = _safe_load_json(results_file)
    if not data:
        return findings

    items = data if isinstance(data, list) else [data]
    for item in items:
        if not isinstance(item, dict):
            continue

        info = item.get("info", {})
        title = info.get("name", item.get("template-id", "Unknown"))
        severity = info.get("severity", "info")
        desc = info.get("description", "")
        matched = item.get("matched-at", "")

        # Extract CVE from classification
        cve = ""
        classification = info.get("classification", {})
        if classification:
            cve_ids = classification.get("cve-id")
            if cve_ids and isinstance(cve_ids, list) and cve_ids:
                cve = cve_ids[0]
            elif isinstance(cve_ids, str):
                cve = cve_ids

        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]

        findings.append(_make_finding(
            title=title,
            severity=severity,
            tool="Nuclei",
            description=desc,
            cve=cve,
            evidence=matched,
            references=refs,
        ))

    return findings


# ── WPScan Parser ──────────────────────────────────────────────────────────────

def parse_wpscan(results_file: Path) -> list[dict]:
    """Parse WPScan JSON output into normalized findings."""
    findings = []
    data = _safe_load_json(results_file)
    if not isinstance(data, dict):
        return findings

    # WordPress version vulnerabilities
    version_info = data.get("version")
    if isinstance(version_info, dict):
        vulns = version_info.get("vulnerabilities", [])
        for v in vulns:
            title = v.get("title", "WordPress Core Vulnerability")
            cve = ""
            refs_data = v.get("references", {})
            cve_list = refs_data.get("cve", [])
            if cve_list:
                cve = f"CVE-{cve_list[0]}" if not str(cve_list[0]).startswith("CVE") else str(cve_list[0])
            ref_urls = refs_data.get("url", [])

            findings.append(_make_finding(
                title=title,
                severity="high",
                tool="WPScan",
                description=f"WordPress core vulnerability: {title}",
                cve=cve,
                evidence=f"Detected version: {version_info.get('number', 'unknown')}",
                references=ref_urls,
            ))

    # Plugin vulnerabilities
    plugins = data.get("plugins", {})
    for plugin_name, plugin_data in plugins.items():
        if not isinstance(plugin_data, dict):
            continue
        for v in plugin_data.get("vulnerabilities", []):
            title = v.get("title", f"Plugin {plugin_name} Vulnerability")
            cve = ""
            refs_data = v.get("references", {})
            cve_list = refs_data.get("cve", [])
            if cve_list:
                cve = f"CVE-{cve_list[0]}" if not str(cve_list[0]).startswith("CVE") else str(cve_list[0])
            ref_urls = refs_data.get("url", [])

            findings.append(_make_finding(
                title=title,
                severity=v.get("severity") or "high",
                tool="WPScan",
                description=f"Plugin vulnerability in {plugin_name}",
                cve=cve,
                evidence=f"Plugin: {plugin_name} v{plugin_data.get('version', {}).get('number', 'unknown')}",
                references=ref_urls,
            ))

    # Theme vulnerabilities
    theme = data.get("main_theme", {})
    if isinstance(theme, dict):
        for v in theme.get("vulnerabilities", []):
            title = v.get("title", "Theme Vulnerability")
            findings.append(_make_finding(
                title=title,
                severity="high",
                tool="WPScan",
                description=f"Theme vulnerability: {title}",
            ))

    return findings


# ── Nikto Parser ───────────────────────────────────────────────────────────────

def parse_nikto(results_file: Path) -> list[dict]:
    """Parse Nikto JSON output into normalized findings."""
    findings = []
    data = _safe_load_json(results_file)
    if not data:
        return findings

    # Nikto outputs an array of host results
    items = data if isinstance(data, list) else [data]
    for host_result in items:
        if not isinstance(host_result, dict):
            continue
        vulns = host_result.get("vulnerabilities", [])
        for v in vulns:
            title = v.get("msg", "Nikto Finding")
            osvdb_id = v.get("OSVDB", "")

            findings.append(_make_finding(
                title=title,
                severity="medium",
                tool="Nikto",
                description=title,
                evidence=f"OSVDB-{osvdb_id}" if osvdb_id else "",
                references=[f"https://vulners.com/osvdb/OSVDB:{osvdb_id}"] if osvdb_id else [],
            ))

    return findings


# ── SSLyze Parser ──────────────────────────────────────────────────────────────

def parse_sslyze(results_file: Path) -> list[dict]:
    """Parse SSLyze JSON output into normalized findings."""
    findings = []
    data = _safe_load_json(results_file)
    if not isinstance(data, dict):
        return findings

    server_results = data.get("server_scan_results", [])
    for server in server_results:
        if not isinstance(server, dict):
            continue
        scan_result = server.get("scan_result", {})

        # Check for TLS 1.0 / 1.1 support
        for old_proto, label in [("tls_1_0_cipher_suites", "TLS 1.0"), ("tls_1_1_cipher_suites", "TLS 1.1")]:
            proto_result = scan_result.get(old_proto, {})
            if isinstance(proto_result, dict):
                accepted = proto_result.get("result", {}).get("accepted_cipher_suites", [])
                if accepted:
                    findings.append(_make_finding(
                        title=f"{label} Supported",
                        severity="high",
                        tool="SSLyze",
                        description=f"Server accepts {label} connections which is deprecated.",
                        evidence=f"{len(accepted)} {label} cipher suites accepted",
                        references=["https://ssl-config.mozilla.org/", "https://www.ssllabs.com/ssltest/"],
                    ))

        # Check for certificate issues
        cert_info = scan_result.get("certificate_info", {})
        if isinstance(cert_info, dict):
            deployments = cert_info.get("result", {}).get("certificate_deployments", [])
            for dep in deployments:
                if isinstance(dep, dict):
                    path_results = dep.get("path_validation_results", [])
                    for pv in path_results:
                        if isinstance(pv, dict) and not pv.get("was_validation_successful"):
                            findings.append(_make_finding(
                                title="SSL Certificate Validation Failed",
                                severity="high",
                                tool="SSLyze",
                                description="The SSL certificate could not be validated.",
                                evidence=str(pv.get("openssl_error_string", "")),
                            ))
                            break  # One finding is enough

    return findings


# ── Master parser ──────────────────────────────────────────────────────────────

def parse_all_results(scan_dir: Path) -> list[dict]:
    """Parse all tool outputs from a scan directory."""
    all_findings = []

    parser_map = {
        "nuclei.jsonl": parse_nuclei,
        "wpscan.json": parse_wpscan,
        "nikto.json": parse_nikto,
        "sslyze.json": parse_sslyze,
    }

    for filename, parser_fn in parser_map.items():
        filepath = scan_dir / filename
        if filepath.exists():
            try:
                results = parser_fn(filepath)
                all_findings.extend(results)
                if results:
                    ui.ok(f"Parsed {len(results)} finding(s) from {filename}")
            except Exception as e:
                ui.warn(f"Error parsing {filename}: {e}")

    return all_findings
