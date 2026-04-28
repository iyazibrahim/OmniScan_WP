"""Result parsers and scan overview extraction for OmniScan."""

import json
import re
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
        results = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results if results else None


def _safe_read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def _normalize_severity(severity: str | None, default: str = "info") -> str:
    sev = (severity or default).strip().lower()
    if sev in {"critical", "high", "medium", "low", "info"}:
        return sev
    if sev in {"warning", "warn"}:
        return "medium"
    if sev in {"error", "severe"}:
        return "high"
    return default


def _make_finding(
    title: str,
    severity: str,
    tool: str,
    description: str = "",
    cve: str = "",
    evidence: str = "",
    references: list[str] | None = None,
) -> dict:
    return {
        "id": "",
        "title": title,
        "severity": _normalize_severity(severity),
        "source_tool": tool,
        "description": description,
        "cve": cve or "",
        "evidence": evidence or "",
        "fix": "",
        "fix_steps": [],
        "references": references or [],
    }


def _dedupe_findings(findings: list[dict]) -> list[dict]:
    seen = set()
    unique = []
    for finding in findings:
        key = (
            finding.get("source_tool", ""),
            finding.get("title", "").strip().lower(),
            finding.get("evidence", "").strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def parse_nuclei(results_file: Path) -> list[dict]:
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

        cve = ""
        classification = info.get("classification", {})
        if isinstance(classification, dict):
            cve_ids = classification.get("cve-id")
            if isinstance(cve_ids, list) and cve_ids:
                cve = cve_ids[0]
            elif isinstance(cve_ids, str):
                cve = cve_ids

        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]

        findings.append(
            _make_finding(
                title=title,
                severity=severity,
                tool="Nuclei",
                description=desc,
                cve=cve,
                evidence=matched,
                references=refs,
            )
        )
    return findings


def parse_wpscan(results_file: Path) -> list[dict]:
    findings = []
    data = _safe_load_json(results_file)
    if not isinstance(data, dict):
        return findings

    version_info = data.get("version")
    if isinstance(version_info, dict):
        for vuln in version_info.get("vulnerabilities", []):
            refs_data = vuln.get("references", {})
            cve_list = refs_data.get("cve", []) if isinstance(refs_data, dict) else []
            cve = ""
            if cve_list:
                raw_cve = str(cve_list[0])
                cve = raw_cve if raw_cve.startswith("CVE") else f"CVE-{raw_cve}"

            findings.append(
                _make_finding(
                    title=vuln.get("title", "WordPress Core Vulnerability"),
                    severity=vuln.get("severity") or "high",
                    tool="WPScan",
                    description=f"WordPress core vulnerability on version {version_info.get('number', 'unknown')}.",
                    cve=cve,
                    evidence=f"Detected version: {version_info.get('number', 'unknown')}",
                    references=refs_data.get("url", []) if isinstance(refs_data, dict) else [],
                )
            )

    plugins = data.get("plugins", {})
    if isinstance(plugins, dict):
        for plugin_name, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict):
                continue
            for vuln in plugin_data.get("vulnerabilities", []):
                refs_data = vuln.get("references", {})
                cve_list = refs_data.get("cve", []) if isinstance(refs_data, dict) else []
                cve = ""
                if cve_list:
                    raw_cve = str(cve_list[0])
                    cve = raw_cve if raw_cve.startswith("CVE") else f"CVE-{raw_cve}"
                findings.append(
                    _make_finding(
                        title=vuln.get("title", f"Plugin {plugin_name} Vulnerability"),
                        severity=vuln.get("severity") or "high",
                        tool="WPScan",
                        description=f"Plugin vulnerability in {plugin_name}.",
                        cve=cve,
                        evidence=f"Plugin: {plugin_name} v{plugin_data.get('version', {}).get('number', 'unknown')}",
                        references=refs_data.get("url", []) if isinstance(refs_data, dict) else [],
                    )
                )

    theme = data.get("main_theme", {})
    if isinstance(theme, dict):
        for vuln in theme.get("vulnerabilities", []):
            findings.append(
                _make_finding(
                    title=vuln.get("title", "Theme Vulnerability"),
                    severity=vuln.get("severity") or "high",
                    tool="WPScan",
                    description="Theme vulnerability detected by WPScan.",
                    evidence=f"Theme: {theme.get('slug', 'unknown')} v{theme.get('version', {}).get('number', 'unknown')}",
                )
            )
    return findings


def parse_nikto(results_file: Path) -> list[dict]:
    findings = []
    data = _safe_load_json(results_file)
    if not data:
        return findings

    items = data if isinstance(data, list) else [data]
    for host_result in items:
        if not isinstance(host_result, dict):
            continue
        for vuln in host_result.get("vulnerabilities", []):
            osvdb_id = vuln.get("OSVDB", "")
            refs = [f"https://vulners.com/osvdb/OSVDB:{osvdb_id}"] if osvdb_id else []
            findings.append(
                _make_finding(
                    title=vuln.get("msg", "Nikto Finding"),
                    severity="medium",
                    tool="Nikto",
                    description=vuln.get("msg", "Nikto Finding"),
                    evidence=f"OSVDB-{osvdb_id}" if osvdb_id else vuln.get("uri", ""),
                    references=refs,
                )
            )
    return findings


def parse_sslyze(results_file: Path) -> list[dict]:
    findings = []
    data = _safe_load_json(results_file)
    if not isinstance(data, dict):
        return findings

    for server in data.get("server_scan_results", []):
        if not isinstance(server, dict):
            continue
        scan_result = server.get("scan_result", {})
        for old_proto, label in [("tls_1_0_cipher_suites", "TLS 1.0"), ("tls_1_1_cipher_suites", "TLS 1.1")]:
            proto_result = scan_result.get(old_proto, {})
            accepted = proto_result.get("result", {}).get("accepted_cipher_suites", []) if isinstance(proto_result, dict) else []
            if accepted:
                findings.append(
                    _make_finding(
                        title=f"{label} Supported",
                        severity="high",
                        tool="SSLyze",
                        description=f"Server accepts {label} connections which are deprecated.",
                        evidence=f"{len(accepted)} accepted cipher suite(s).",
                        references=["https://ssl-config.mozilla.org/", "https://www.ssllabs.com/ssltest/"],
                    )
                )

        cert_info = scan_result.get("certificate_info", {})
        deployments = cert_info.get("result", {}).get("certificate_deployments", []) if isinstance(cert_info, dict) else []
        for deployment in deployments:
            if not isinstance(deployment, dict):
                continue
            for validation in deployment.get("path_validation_results", []):
                if isinstance(validation, dict) and not validation.get("was_validation_successful"):
                    findings.append(
                        _make_finding(
                            title="SSL Certificate Validation Failed",
                            severity="high",
                            tool="SSLyze",
                            description="The SSL certificate could not be validated.",
                            evidence=str(validation.get("openssl_error_string", "")),
                        )
                    )
                    break
    return findings


def parse_corsy(results_file: Path) -> list[dict]:
    findings = []
    text = _safe_read_text(results_file)
    if not text:
        return findings
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    risky_markers = [
        ("access-control-allow-origin: *", "Wildcard CORS Policy", "medium"),
        ("origin reflected", "Origin Reflection in CORS", "high"),
        ("access-control-allow-credentials: true", "Credentialed CORS Enabled", "medium"),
    ]
    for marker, title, severity in risky_markers:
        matching = [line for line in lines if marker in line.lower()]
        if matching:
            findings.append(
                _make_finding(
                    title=title,
                    severity=severity,
                    tool="Corsy",
                    description="Potential CORS misconfiguration identified during header analysis.",
                    evidence="\n".join(matching[:5]),
                )
            )
    return findings


def parse_ffuf(results_file: Path) -> list[dict]:
    findings = []
    data = _safe_load_json(results_file)
    if not isinstance(data, dict):
        return findings
    for item in data.get("results", []):
        if not isinstance(item, dict):
            continue
        status_code = int(item.get("status", 0) or 0)
        if status_code not in {200, 204, 301, 302, 307, 401, 403}:
            continue
        url = item.get("url", "")
        evidence = f"Status {status_code}, words={item.get('words', '?')}, length={item.get('length', '?')}"
        severity = "low" if status_code in {401, 403} else "medium"
        findings.append(
            _make_finding(
                title="Interesting Content Discovery",
                severity=severity,
                tool="ffuf",
                description="Directory or endpoint discovered during content enumeration.",
                evidence=f"{url}\n{evidence}",
            )
        )
    return findings


def parse_feroxbuster(results_file: Path) -> list[dict]:
    findings = []
    data = _safe_load_json(results_file)
    items = data if isinstance(data, list) else [data] if data else []
    for item in items:
        if not isinstance(item, dict):
            continue
        status = int(item.get("status", 0) or 0)
        if status not in {200, 204, 301, 302, 307, 401, 403}:
            continue
        url = item.get("url", "")
        findings.append(
            _make_finding(
                title="Interesting Content Discovery",
                severity="low" if status in {401, 403} else "medium",
                tool="Feroxbuster",
                description="Feroxbuster identified an accessible path or resource.",
                evidence=f"{url}\nStatus {status}",
            )
        )
    return findings


def parse_joomscan(results_file: Path) -> list[dict]:
    findings = []
    text = _safe_read_text(results_file)
    if not text:
        return findings
    for line in text.splitlines():
        clean = line.strip()
        if not clean:
            continue
        lower = clean.lower()
        if "[!]" in clean or "vulnerab" in lower or "exposed" in lower:
            findings.append(
                _make_finding(
                    title="Joomla Exposure or Vulnerability",
                    severity="medium",
                    tool="JoomScan",
                    description="JoomScan reported a potentially actionable exposure.",
                    evidence=clean,
                )
            )
    return findings


def parse_droopescan(results_file: Path) -> list[dict]:
    findings = []
    data = _safe_load_json(results_file)
    items = data if isinstance(data, list) else [data] if data else []
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("version"):
            findings.append(
                _make_finding(
                    title="Drupal Version Identified",
                    severity="info",
                    tool="Droopescan",
                    description="Droopescan identified the Drupal version for the target.",
                    evidence=str(item.get("version")),
                )
            )
        for interesting in item.get("interesting urls", []) if isinstance(item.get("interesting urls"), list) else []:
            findings.append(
                _make_finding(
                    title="Interesting Drupal URL Discovered",
                    severity="low",
                    tool="Droopescan",
                    description="Droopescan discovered a Drupal URL worth reviewing.",
                    evidence=str(interesting),
                )
            )
    return findings


def parse_cmsmap(results_file: Path) -> list[dict]:
    findings = []
    data = _safe_load_json(results_file)
    text = json.dumps(data, ensure_ascii=False) if data is not None else _safe_read_text(results_file)
    for match in re.findall(r"(CVE-\d{4}-\d+)", text, flags=re.IGNORECASE):
        findings.append(
            _make_finding(
                title="CMS Vulnerability Reference",
                severity="high",
                tool="CMSMap",
                description="CMSMap output contains an explicit vulnerability reference.",
                cve=match.upper(),
                evidence=match.upper(),
            )
        )
    if not findings and text:
        for line in text.splitlines():
            lower = line.lower()
            if "vulnerab" in lower or "exposed" in lower:
                findings.append(
                    _make_finding(
                        title="CMS Exposure",
                        severity="medium",
                        tool="CMSMap",
                        description="CMSMap reported a potential exposure or weakness.",
                        evidence=line.strip()[:500],
                    )
                )
    return findings


def parse_dalfox(results_file: Path) -> list[dict]:
    findings = []
    data = _safe_load_json(results_file)
    items = data if isinstance(data, list) else [data] if data else []
    for item in items:
        if not isinstance(item, dict):
            continue
        vuln_type = item.get("type") or item.get("issue") or "XSS Finding"
        evidence_parts = []
        for key in ("url", "param", "payload", "evidence"):
            if item.get(key):
                evidence_parts.append(f"{key}: {item.get(key)}")
        findings.append(
            _make_finding(
                title=str(vuln_type),
                severity="high",
                tool="Dalfox",
                description="Dalfox detected a reflected or DOM-based XSS condition.",
                evidence="\n".join(evidence_parts)[:1000],
            )
        )
    return findings


def parse_wapiti(results_file: Path) -> list[dict]:
    findings = []
    data = _safe_load_json(results_file)
    if not isinstance(data, dict):
        return findings
    vulns = data.get("vulnerabilities", {})
    if not isinstance(vulns, dict):
        return findings
    for vuln_name, entries in vulns.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            evidence = []
            for key in ("path", "method", "parameter", "info", "referer"):
                if entry.get(key):
                    evidence.append(f"{key}: {entry.get(key)}")
            severity = _normalize_severity(entry.get("level"), "medium")
            findings.append(
                _make_finding(
                    title=str(vuln_name),
                    severity=severity,
                    tool="Wapiti",
                    description=entry.get("info", f"Wapiti reported {vuln_name}."),
                    evidence="\n".join(evidence)[:1000],
                    references=entry.get("references", []) if isinstance(entry.get("references"), list) else [],
                )
            )
    return findings


def parse_commix(results_file: Path) -> list[dict]:
    findings = []
    text = _safe_read_text(results_file)
    if not text:
        return findings
    for line in text.splitlines():
        lower = line.lower()
        if "command injection" in lower or "vulnerable" in lower:
            findings.append(
                _make_finding(
                    title="Potential Command Injection",
                    severity="critical",
                    tool="Commix",
                    description="Commix reported a command injection condition.",
                    evidence=line.strip()[:500],
                )
            )
    return findings


def parse_all_results(scan_dir: Path) -> list[dict]:
    all_findings = []
    parser_map = {
        "nuclei.jsonl": parse_nuclei,
        "wpscan.json": parse_wpscan,
        "nikto.json": parse_nikto,
        "sslyze.json": parse_sslyze,
        "corsy.txt": parse_corsy,
        "ffuf.json": parse_ffuf,
        "feroxbuster.json": parse_feroxbuster,
        "joomscan.txt": parse_joomscan,
        "droopescan.json": parse_droopescan,
        "cmsmap.json": parse_cmsmap,
        "dalfox.json": parse_dalfox,
        "wapiti.json": parse_wapiti,
        "commix.txt": parse_commix,
    }

    for filename, parser_fn in parser_map.items():
        filepath = scan_dir / filename
        if not filepath.exists():
            continue
        try:
            results = parser_fn(filepath)
            all_findings.extend(results)
            if results:
                ui.ok(f"Parsed {len(results)} finding(s) from {filename}")
        except Exception as exc:
            ui.warn(f"Error parsing {filename}: {exc}")

    return _dedupe_findings(all_findings)


def _extract_httpx_fingerprint(scan_dir: Path) -> dict:
    data = _safe_load_json(scan_dir / "httpx.json")
    items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    if not items:
        return {}
    item = next((entry for entry in items if isinstance(entry, dict)), {})
    return {
        "url": item.get("url", ""),
        "status_code": item.get("status-code") or item.get("status_code"),
        "title": item.get("title", ""),
        "technologies": item.get("tech", []) if isinstance(item.get("tech"), list) else [],
        "webserver": item.get("webserver") or item.get("web-server") or "",
    }


def _extract_whatweb_plugins(scan_dir: Path) -> list[str]:
    data = _safe_load_json(scan_dir / "whatweb.json")
    items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    plugins = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        plugin_data = item.get("plugins", {})
        if isinstance(plugin_data, dict):
            plugins.update(plugin_data.keys())
    if plugins:
        return sorted(plugins)

    raw = _safe_read_text(scan_dir / "whatweb.stdout.log")
    return sorted(set(re.findall(r"\b[A-Za-z0-9_.+-]{3,}\b", raw)))[:30]


def _collect_sample_urls(scan_dir: Path) -> dict:
    urls = {"gau": [], "katana": [], "ffuf": [], "feroxbuster": []}

    gau_file = scan_dir / "gau.txt"
    if gau_file.exists():
        urls["gau"] = [line.strip() for line in _safe_read_text(gau_file).splitlines() if line.strip()][:20]

    katana_data = _safe_load_json(scan_dir / "katana.jsonl")
    katana_items = katana_data if isinstance(katana_data, list) else [katana_data] if isinstance(katana_data, dict) else []
    for item in katana_items:
        if isinstance(item, dict):
            discovered = item.get("request", {}).get("endpoint") or item.get("url")
            if discovered:
                urls["katana"].append(str(discovered))
    urls["katana"] = urls["katana"][:20]

    for key, file_name in [("ffuf", "ffuf.json"), ("feroxbuster", "feroxbuster.json")]:
        data = _safe_load_json(scan_dir / file_name)
        if isinstance(data, dict):
            results = data.get("results", [])
            if isinstance(results, list):
                urls[key] = [str(item.get("url", "")) for item in results if isinstance(item, dict) and item.get("url")][:20]
        elif isinstance(data, list):
            urls[key] = [str(item.get("url", "")) for item in data if isinstance(item, dict) and item.get("url")][:20]

    return urls


def _collect_subdomains(scan_dir: Path) -> list[str]:
    data = _safe_load_json(scan_dir / "subfinder.json")
    items = data if isinstance(data, list) else [data] if isinstance(data, dict) else []
    results = []
    for item in items:
        if isinstance(item, dict) and item.get("host"):
            results.append(str(item["host"]))
    return results[:50]


def _collect_parameters(scan_dir: Path) -> list[str]:
    text = _safe_read_text(scan_dir / "arjun.txt")
    if not text:
        return []
    params = []
    for line in text.splitlines():
        if "http" in line or "[" not in line:
            continue
        match = re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_-]{1,40}\b", line)
        params.extend(match)
    return sorted(set(params))[:40]


def collect_scan_overview(
    scan_dir: Path,
    target_url: str,
    requested_profile: str,
    effective_profile: str,
    tool_runs: list[dict],
) -> dict:
    fingerprint = _extract_httpx_fingerprint(scan_dir)
    whatweb_plugins = _extract_whatweb_plugins(scan_dir)
    discovered_urls = _collect_sample_urls(scan_dir)
    subdomains = _collect_subdomains(scan_dir)
    parameters = _collect_parameters(scan_dir)

    tools_summary = {
        "completed": sum(1 for run in tool_runs if run.get("status") in {"completed", "completed_no_output"}),
        "failed": sum(1 for run in tool_runs if run.get("status") == "failed"),
        "missing": sum(1 for run in tool_runs if run.get("status") == "missing"),
        "skipped": sum(1 for run in tool_runs if run.get("status") == "skipped"),
        "timeout": sum(1 for run in tool_runs if run.get("status") == "timeout"),
    }

    return {
        "target_url": target_url,
        "requested_profile": requested_profile,
        "effective_profile": effective_profile,
        "fingerprint": {
            "title": fingerprint.get("title", ""),
            "status_code": fingerprint.get("status_code"),
            "technologies": fingerprint.get("technologies", []),
            "webserver": fingerprint.get("webserver", ""),
            "whatweb_plugins": whatweb_plugins,
        },
        "discovery": {
            "subdomains": subdomains,
            "subdomain_count": len(subdomains),
            "parameters": parameters,
            "parameter_count": len(parameters),
            "sample_urls": discovered_urls,
            "gau_count": len(discovered_urls["gau"]),
            "katana_count": len(discovered_urls["katana"]),
            "ffuf_count": len(discovered_urls["ffuf"]),
            "feroxbuster_count": len(discovered_urls["feroxbuster"]),
        },
        "tool_summary": tools_summary,
        "tool_runs": tool_runs,
    }
