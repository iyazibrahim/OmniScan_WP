"""Result parsers and scan overview extraction for DP Security Platform."""

import json
import re
from urllib.parse import parse_qsl, urlparse
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


def _iter_jsonl(path: Path):
    """Yield JSON objects from a JSONL file without loading the whole file."""
    if not path.exists():
        return
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for raw_line in handle:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(item, dict):
                    yield item
    except OSError:
        return


def _katana_discovered_url(item: dict) -> str:
    request = item.get("request", {}) if isinstance(item, dict) else {}
    if isinstance(request, dict):
        for key in ("endpoint", "url", "path"):
            value = request.get(key)
            if value:
                return str(value)
    for key in ("url", "endpoint", "path"):
        value = item.get(key) if isinstance(item, dict) else None
        if value:
            return str(value)
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


def _stringify(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def _query_parameter_from_url(url: str) -> str:
    parsed = urlparse(str(url or ""))
    for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
        if key:
            return key
    return ""


def _compact_evidence(finding: dict) -> str:
    lines: list[str] = []
    for label, key in [
        ("asset", "asset"),
        ("url", "url"),
        ("endpoint", "endpoint"),
        ("path", "path"),
        ("method", "method"),
        ("parameter", "parameter"),
        ("component", "component"),
        ("version", "component_version"),
        ("payload", "payload"),
        ("matched", "matched_evidence"),
        ("request", "request_excerpt"),
        ("response", "response_excerpt"),
        ("verify", "reproduction"),
        ("protect", "protection_target"),
        ("fix_target", "fix_target"),
    ]:
        value = str(finding.get(key, "") or "").strip()
        if value:
            lines.append(f"{label}: {value}")
    if not lines and finding.get("description"):
        lines.append(str(finding["description"]).strip())
    return "\n".join(lines)[:2000]


def _confidence_rank(value: str) -> int:
    return {
        "confirmed": 5,
        "reproduced": 4,
        "detected": 3,
        "weak_signal": 2,
        "informational": 1,
    }.get(str(value or "").strip().lower(), 0)


def _derive_confidence_status(finding: dict) -> tuple[str, str]:
    proof_count = 0
    for key in ("matched_evidence", "payload", "request_excerpt", "response_excerpt"):
        if str(finding.get(key, "") or "").strip():
            proof_count += 1
    if str(finding.get("url", "") or "").strip() or str(finding.get("path", "") or "").strip():
        proof_count += 1
    if str(finding.get("component", "") or "").strip() and str(finding.get("component_version", "") or "").strip():
        proof_count += 1

    kind = str(finding.get("evidence_kind", "") or "").strip().lower()
    if kind in {"injection", "command_injection", "xss"}:
        if proof_count >= 4:
            return "confirmed", "reproduced"
        if proof_count >= 2:
            return "detected", "reproduced"
        return "weak_signal", "detected"
    if kind == "content":
        if proof_count >= 3 and str(finding.get("parameter", "") or "").strip():
            return "detected", "detected"
        return "weak_signal", "detected"
    if kind in {"component", "version", "tls", "headers", "cors", "exposure", "content"}:
        if proof_count >= 2:
            return "detected", "detected"
        return "weak_signal", "detected"
    if str(finding.get("severity", "")).lower() == "info":
        return "informational", "informational"
    if proof_count >= 2:
        return "detected", "detected"
    return "weak_signal", "detected"


def _finalize_finding(finding: dict) -> dict:
    normalized = dict(finding)
    normalized["parameter"] = (
        str(normalized.get("parameter") or "").strip()
        or _query_parameter_from_url(str(normalized.get("url") or normalized.get("endpoint") or ""))
    )

    location_present = any(str(normalized.get(key) or "").strip() for key in ("url", "endpoint", "path", "asset", "component"))
    proof_present = any(str(normalized.get(key) or "").strip() for key in ("matched_evidence", "payload", "component_version", "request_excerpt", "response_excerpt"))
    action_present = any(str(normalized.get(key) or "").strip() for key in ("reproduction", "protection_target", "fix_target"))

    confidence, verification = _derive_confidence_status(normalized)
    explicit_confidence = str(normalized.get("confidence") or "").strip().lower()
    if _confidence_rank(explicit_confidence) > _confidence_rank(confidence):
        confidence = explicit_confidence
    explicit_verification = str(normalized.get("verification_status") or "").strip().lower()
    if explicit_verification:
        verification = explicit_verification

    if not location_present or not proof_present or not action_present:
        if _confidence_rank(confidence) > _confidence_rank("weak_signal"):
            confidence = "weak_signal"
        if not str(normalized.get("protection_target") or "").strip():
            normalized["protection_target"] = "Tool output did not include exact exploit coordinates. Review the raw evidence before remediation."

    normalized["confidence"] = confidence
    normalized["verification_status"] = verification
    normalized["evidence"] = _compact_evidence(normalized)
    return normalized


def _make_finding(
    title: str,
    severity: str,
    tool: str,
    description: str = "",
    cve: str = "",
    evidence: str = "",
    references: list[str] | None = None,
    **extra,
) -> dict:
    finding = {
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
    finding.update(extra)
    if finding.get("evidence"):
        finding.setdefault("matched_evidence", str(finding.get("evidence", "")))
    return _finalize_finding(finding)


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
        evidence_parts = []
        if item.get("matched-at"):
            evidence_parts.append(f"matched_at: {item.get('matched-at')}")
        if item.get("host"):
            evidence_parts.append(f"host: {item.get('host')}")
        if item.get("ip"):
            evidence_parts.append(f"ip: {item.get('ip')}")
        if item.get("template-id"):
            evidence_parts.append(f"template: {item.get('template-id')}")
        if item.get("matcher-name"):
            evidence_parts.append(f"matcher: {item.get('matcher-name')}")
        extracted = item.get("extracted-results")
        if isinstance(extracted, list) and extracted:
            evidence_parts.append(f"extracted: {', '.join(str(x) for x in extracted[:8])}")
        if item.get("curl-command"):
            evidence_parts.append(f"curl: {item.get('curl-command')}")

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
                references=refs,
                asset=item.get("host") or item.get("matched-at") or "",
                url=item.get("matched-at") or item.get("host") or "",
                matched_evidence=", ".join(str(x) for x in extracted[:8]) if isinstance(extracted, list) and extracted else "",
                reproduction=item.get("curl-command") or "",
                protection_target=f"Nuclei template {item.get('template-id')}" if item.get("template-id") else "Matched public-facing endpoint",
                fix_target=item.get("matched-at") or item.get("host") or "",
                evidence_kind="exposure",
                request_excerpt=item.get("curl-command") or "",
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
                    references=refs_data.get("url", []) if isinstance(refs_data, dict) else [],
                    asset=data.get("target_url", "") or "site root",
                    url=data.get("target_url", ""),
                    component="wordpress-core",
                    component_version=version_info.get("number", "unknown"),
                    matched_evidence=f"Detected WordPress core version {version_info.get('number', 'unknown')}",
                    reproduction=f"Check the installed WordPress core version on {data.get('target_url', '') or 'the site root'}",
                    protection_target="WordPress core installation and exposed application routes",
                    fix_target="WordPress core upgrade path",
                    evidence_kind="component",
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
                        references=refs_data.get("url", []) if isinstance(refs_data, dict) else [],
                        asset=data.get("target_url", "") or f"plugin/{plugin_name}",
                        url=data.get("target_url", ""),
                        component=f"plugin/{plugin_name}",
                        component_version=plugin_data.get("version", {}).get("number", "unknown"),
                        path=f"/wp-content/plugins/{plugin_name}/",
                        matched_evidence=f"Detected plugin version {plugin_data.get('version', {}).get('number', 'unknown')}",
                        reproduction=f"Visit /wp-content/plugins/{plugin_name}/ or confirm the installed plugin version in WordPress admin.",
                        protection_target=f"Plugin {plugin_name} and any routes it exposes",
                        fix_target=f"/wp-content/plugins/{plugin_name}/",
                        evidence_kind="component",
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
                    asset=data.get("target_url", "") or f"theme/{theme.get('slug', 'unknown')}",
                    url=data.get("target_url", ""),
                    component=f"theme/{theme.get('slug', 'unknown')}",
                    component_version=theme.get("version", {}).get("number", "unknown"),
                    path=f"/wp-content/themes/{theme.get('slug', 'unknown')}/",
                    matched_evidence=f"Detected theme version {theme.get('version', {}).get('number', 'unknown')}",
                    reproduction=f"Check the installed theme version for {theme.get('slug', 'unknown')} in WordPress admin.",
                    protection_target=f"Theme {theme.get('slug', 'unknown')} templates and asset handlers",
                    fix_target=f"/wp-content/themes/{theme.get('slug', 'unknown')}/",
                    evidence_kind="component",
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
            uri = vuln.get("uri", "")
            method = vuln.get("method", "GET")
            msg = vuln.get("msg", "Nikto Finding")
            evidence_parts = []
            if uri:
                evidence_parts.append(f"url: {uri}")
            if method:
                evidence_parts.append(f"method: {method}")
            if osvdb_id:
                evidence_parts.append(f"osvdb: {osvdb_id}")
            evidence_parts.append(f"message: {msg}")
            findings.append(
                _make_finding(
                    title=msg,
                    severity="medium",
                    tool="Nikto",
                    description=msg,
                    references=refs,
                    url=uri,
                    path=uri,
                    method=method,
                    matched_evidence=msg,
                    reproduction=f"Replay {method} {uri}" if uri else f"Review the Nikto result for message: {msg}",
                    protection_target=uri or "Affected web route or server configuration",
                    fix_target=uri or "Web server or application route handling",
                    evidence_kind="headers" if "header" in msg.lower() else "exposure",
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
                        references=["https://ssl-config.mozilla.org/", "https://www.ssllabs.com/ssltest/"],
                        asset=server.get("server_location", {}).get("hostname", ""),
                        matched_evidence=f"{len(accepted)} accepted cipher suite(s).",
                        reproduction=f"Review {label} support with SSLyze or testssl against {server.get('server_location', {}).get('hostname', 'the server')}.",
                        protection_target="TLS protocol configuration on the public web server",
                        fix_target="Web server TLS settings",
                        evidence_kind="tls",
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
                            asset=server.get("server_location", {}).get("hostname", ""),
                            matched_evidence=str(validation.get("openssl_error_string", "")),
                            reproduction=f"Inspect the deployed certificate chain on {server.get('server_location', {}).get('hostname', 'the server')}.",
                            protection_target="TLS certificate chain and trust configuration",
                            fix_target="Certificate deployment and intermediate chain configuration",
                            evidence_kind="tls",
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
                    matched_evidence="\n".join(matching[:5]),
                    reproduction="Replay the affected request with a custom Origin header and inspect the Access-Control-* response headers.",
                    protection_target="CORS response headers on the affected endpoint",
                    fix_target="Application or reverse-proxy CORS header configuration",
                    evidence_kind="cors",
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
        evidence = (
            f"url: {url}\n"
            f"status: {status_code}\n"
            f"words: {item.get('words', '?')}\n"
            f"length: {item.get('length', '?')}"
        )
        severity = "low" if status_code in {401, 403} else "medium"
        findings.append(
            _make_finding(
                title="Interesting Content Discovery",
                severity=severity,
                tool="ffuf",
                description="Directory or endpoint discovered during content enumeration.",
                url=url,
                path=urlparse(str(url or "")).path,
                matched_evidence=f"status: {status_code}, words: {item.get('words', '?')}, length: {item.get('length', '?')}",
                reproduction=f"Visit {url} and verify whether the content should be public.",
                protection_target="Exposed route, file, or directory discovered during enumeration",
                fix_target=url,
                evidence_kind="content",
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
                url=url,
                path=urlparse(str(url or "")).path,
                matched_evidence=f"status: {status}",
                reproduction=f"Visit {url} and verify whether the resource should be reachable.",
                protection_target="Exposed route, file, or directory discovered during enumeration",
                fix_target=url,
                evidence_kind="content",
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
            location = ""
            url_match = re.search(r"https?://\S+", clean)
            if url_match:
                location = url_match.group(0)
            findings.append(
                _make_finding(
                    title="Joomla Exposure or Vulnerability",
                    severity="medium",
                    tool="JoomScan",
                    description="JoomScan reported a potentially actionable exposure.",
                    url=location,
                    path=urlparse(location).path if location else "",
                    matched_evidence=clean,
                    reproduction=f"Visit {location}" if location else "Review the raw JoomScan finding and confirm the exposed Joomla surface.",
                    protection_target=location or "Affected Joomla route or component",
                    fix_target=location or "Joomla configuration or exposed component",
                    evidence_kind="exposure",
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
                    component="drupal-core",
                    component_version=str(item.get("version")),
                    matched_evidence=str(item.get("version")),
                    reproduction="Confirm the deployed Drupal core version from the application or admin console.",
                    protection_target="Drupal core installation",
                    fix_target="Drupal core upgrade path",
                    evidence_kind="version",
                )
            )
        for interesting in item.get("interesting urls", []) if isinstance(item.get("interesting urls"), list) else []:
            findings.append(
                _make_finding(
                    title="Interesting Drupal URL Discovered",
                    severity="low",
                    tool="Droopescan",
                    description="Droopescan discovered a Drupal URL worth reviewing.",
                    url=str(interesting),
                    path=urlparse(str(interesting)).path,
                    matched_evidence=str(interesting),
                    reproduction=f"Visit {interesting} and verify whether the route should be public.",
                    protection_target="Discovered Drupal route or resource",
                    fix_target=str(interesting),
                    evidence_kind="content",
                )
            )
    return findings


def parse_cmsmap(results_file: Path) -> list[dict]:
    findings = []
    data = _safe_load_json(results_file)
    text = json.dumps(data, ensure_ascii=False) if data is not None else _safe_read_text(results_file)
    for match in re.findall(r"(CVE-\d{4}-\d+)", text, flags=re.IGNORECASE):
        around = ""
        for line in text.splitlines():
            if match.lower() in line.lower():
                around = line.strip()[:350]
                break
        findings.append(
            _make_finding(
                title="CMS Vulnerability Reference",
                severity="high",
                tool="CMSMap",
                description="CMSMap output contains an explicit vulnerability reference.",
                cve=match.upper(),
                matched_evidence=around or match.upper(),
                reproduction=f"Review the affected CMS component tied to {match.upper()} and compare it against the installed version.",
                protection_target="Referenced CMS component or exposed surface in CMSMap output",
                fix_target="CMS component upgrade or configuration review",
                evidence_kind="component",
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
                        matched_evidence=line.strip()[:500],
                        reproduction="Review the CMSMap raw output and confirm the exposed route or component.",
                        protection_target="CMS route or component mentioned in CMSMap output",
                        fix_target="CMS configuration or component review",
                        evidence_kind="exposure",
                    )
                )
    return findings


def parse_dalfox(results_file: Path) -> list[dict]:
    findings = []
    data = _safe_load_json(results_file)

    # Dalfox output varies across versions; flatten likely container keys first.
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        for key in ("results", "issues", "vulnerabilities", "data"):
            maybe = data.get(key)
            if isinstance(maybe, list):
                items = maybe
                break
        else:
            items = [data]
    else:
        items = []

    for item in items:
        if not isinstance(item, dict):
            continue

        vuln_type = (
            item.get("type")
            or item.get("issue")
            or item.get("name")
            or item.get("message")
            or "XSS Finding"
        )
        target_url = (
            item.get("url")
            or item.get("target")
            or item.get("endpoint")
            or item.get("path")
            or ""
        )
        parameter = item.get("param") or item.get("parameter") or _query_parameter_from_url(str(target_url))
        payload = item.get("payload") or item.get("poc") or ""
        matched = item.get("evidence") or item.get("data") or ""
        request_text = _stringify(item.get("request"))
        response_text = _stringify(item.get("response"))
        reproduction = item.get("poc") or (str(target_url) if target_url and payload else "")
        evidence_kind = "xss" if "xss" in str(vuln_type).lower() else "injection"
        protection_target = f"Parameter {parameter} reflected into the response" if parameter else "Reflected or DOM-driven client-side sink"

        findings.append(
            _make_finding(
                title=str(vuln_type),
                severity="high",
                tool="Dalfox",
                description="Dalfox detected a reflected or DOM-based client-side injection condition.",
                url=target_url,
                path=urlparse(str(target_url or "")).path,
                method=item.get("method") or "GET",
                parameter=parameter,
                payload=_stringify(payload),
                matched_evidence=_stringify(matched),
                request_excerpt=request_text,
                response_excerpt=response_text,
                reproduction=_stringify(reproduction) or f"Replay the request against {target_url}",
                protection_target=protection_target,
                fix_target=parameter or target_url or "Affected client-side sink",
                evidence_kind=evidence_kind,
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
                    references=entry.get("references", []) if isinstance(entry.get("references"), list) else [],
                    path=entry.get("path", ""),
                    url=entry.get("path", ""),
                    method=entry.get("method", ""),
                    parameter=entry.get("parameter", ""),
                    matched_evidence=entry.get("info", ""),
                    reproduction=f"Replay {entry.get('method', 'GET')} {entry.get('path', '')}" if entry.get("path") else "Review the affected request in Wapiti output.",
                    protection_target=entry.get("parameter") or entry.get("path") or "Affected request input",
                    fix_target=entry.get("path") or entry.get("parameter") or "Application input handling",
                    evidence_kind="injection",
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
            location = ""
            url_match = re.search(r"https?://\S+", line)
            if url_match:
                location = url_match.group(0)
            findings.append(
                _make_finding(
                    title="Potential Command Injection",
                    severity="critical",
                    tool="Commix",
                    description="Commix reported a command injection condition.",
                    url=location,
                    path=urlparse(location).path if location else "",
                    matched_evidence=line.strip()[:460],
                    reproduction=f"Replay the request to {location} with a benign test payload and confirm server-side command execution is blocked." if location else "Review the raw Commix finding and confirm the affected request input.",
                    protection_target=location or "Potential command-executing request handler",
                    fix_target=location or "Server-side command execution sink",
                    evidence_kind="command_injection",
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

    for item in _iter_jsonl(scan_dir / "katana.jsonl"):
        discovered = _katana_discovered_url(item)
        if not discovered or discovered in urls["katana"]:
            continue
        urls["katana"].append(discovered)
        if len(urls["katana"]) >= 20:
            break

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
        "completed": sum(1 for run in tool_runs if run.get("status") in {"completed", "completed_no_output", "completed_partial"}),
        "failed": sum(1 for run in tool_runs if run.get("status") == "failed"),
        "missing": sum(1 for run in tool_runs if run.get("status") == "missing"),
        "skipped": sum(1 for run in tool_runs if run.get("status") == "skipped"),
        "timeout": sum(1 for run in tool_runs if run.get("status") == "timeout"),
        "partial": sum(1 for run in tool_runs if run.get("status") == "completed_partial"),
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
