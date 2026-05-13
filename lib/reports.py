"""Comprehensive HTML, Markdown, JSON, CSV, and SARIF report generation."""

from __future__ import annotations

import csv
import html
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from lib.config import HTML_TEMPLATE_FILE, REPORTS_DIR, load_json, save_json
from lib.standards import SARIF_LEVEL_MAP

MALAYSIA_TZ = timezone(timedelta(hours=8))
REPORT_INDEX_FILE = REPORTS_DIR / "report-index.json"


def _as_malaysia_time(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(MALAYSIA_TZ)


def _rel_report_path(path: Path) -> str | None:
    try:
        return str(path.resolve().relative_to(REPORTS_DIR.resolve())).replace("\\", "/")
    except Exception:
        return None


def _upsert_report_index(paths: dict[str, Path], payload: dict):
    html_path = paths.get("html")
    if html_path is None or not html_path.exists():
        return

    rel_html = _rel_report_path(html_path)
    if not rel_html:
        return

    entry = {
        "path": rel_html,
        "name": html_path.stem,
        "folder": str(Path(rel_html).parent).replace("\\", "/"),
        "target_url": payload.get("target_url", ""),
        "profile": payload.get("overview", {}).get("effective_profile", ""),
        "assessment_summary": payload.get("assessment", {}).get("summary", {}) if isinstance(payload.get("assessment"), dict) else {},
        "severities": payload.get("summary", {}).get("severity_counts", {}),
        "scan_started_at": payload.get("scan_started_at", ""),
        "scan_started_at_utc": payload.get("scan_started_at_utc", ""),
        "scan_mode": payload.get("scan_mode", ""),
        "size_kb": round(html_path.stat().st_size / 1024, 1),
        "modified": html_path.stat().st_mtime,
        "md_path": _rel_report_path(paths["md"]) if "md" in paths and paths["md"].exists() else None,
        "json_path": _rel_report_path(paths["json"]) if "json" in paths and paths["json"].exists() else None,
        "csv_path": _rel_report_path(paths["csv"]) if "csv" in paths and paths["csv"].exists() else None,
        "sarif_path": _rel_report_path(paths["sarif"]) if "sarif" in paths and paths["sarif"].exists() else None,
    }

    index = load_json(REPORT_INDEX_FILE)
    if not isinstance(index, dict):
        index = {"version": 1, "reports": []}
    reports = index.get("reports")
    if not isinstance(reports, list):
        reports = []

    reports = [item for item in reports if isinstance(item, dict) and item.get("path") != rel_html]
    reports.append(entry)
    reports.sort(key=lambda item: float(item.get("modified", 0) or 0), reverse=True)
    if len(reports) > 5000:
        reports = reports[:5000]

    index["reports"] = reports
    index["version"] = 1
    save_json(REPORT_INDEX_FILE, index)


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = finding.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _tool_status_badge(status: str) -> str:
    cls = {
        "completed": "good",
        "completed_partial": "warn",
        "completed_no_output": "warn",
        "missing": "muted",
        "skipped": "muted",
        "failed": "bad",
        "timeout": "bad",
    }.get(status, "muted")
    return f"<span class='pill {cls}'>{html.escape(status.replace('_', ' '))}</span>"


def _assessment_summary(assessment: dict | None) -> dict:
    if not isinstance(assessment, dict):
        return {}
    return assessment.get("summary", {}) if isinstance(assessment.get("summary"), dict) else {}


def _build_executive_summary(payload: dict) -> list[str]:
    findings = payload.get("findings", [])
    severity_counts = payload.get("summary", {}).get("severity_counts", {})
    overview = payload.get("overview", {})
    tool_summary = overview.get("tool_summary", {})
    assessment_summary = _assessment_summary(payload.get("assessment"))
    case_status = assessment_summary.get("case_status", {})
    verification_status = assessment_summary.get("verification_status", {})

    lines = []
    if severity_counts.get("critical", 0) or severity_counts.get("high", 0):
        lines.append(
            f"{severity_counts.get('critical', 0)} critical and {severity_counts.get('high', 0)} high-severity automated findings require immediate triage."
        )
    elif findings:
        lines.append(f"No critical or high automated findings were parsed, but {len(findings)} lower-severity issues still require review.")
    else:
        lines.append("No automated findings were parsed from the available tool outputs. Review coverage and tool failures before assuming the target is clean.")

    failed = tool_summary.get("failed", 0) + tool_summary.get("timeout", 0) + tool_summary.get("missing", 0)
    if failed:
        lines.append(f"Tool coverage was incomplete: {failed} tool run(s) failed, timed out, or were unavailable.")
    partial = tool_summary.get("partial", 0)
    if partial:
        lines.append(f"{partial} tool run(s) produced partial evidence before exiting or timing out; review telemetry before dismissing those findings.")

    if case_status:
        total_cases = sum(case_status.values())
        not_started = case_status.get("not_started", 0)
        lines.append(f"Guided manual assessment coverage: {total_cases - not_started}/{total_cases} case(s) have at least some analyst activity.")
    if verification_status:
        confirmed = verification_status.get("confirmed", 0) + verification_status.get("reproduced", 0)
        fixed = verification_status.get("fixed", 0)
        lines.append(f"Verification workflow currently records {confirmed} confirmed/reproduced case(s) and {fixed} fixed case(s).")

    if not lines:
        lines.append("Automated and manual assessment data are limited. Continue guided testing before drawing strong conclusions.")
    return lines


def build_report_payload(
    findings: list[dict],
    target_url: str,
    scan_mode: str,
    start_time: datetime,
    scan_overview: dict | None,
    assessment: dict | None = None,
    report_profile: str = "technical",
    include_manual_assessment: bool = True,
) -> dict:
    started_at_malaysia = _as_malaysia_time(start_time)
    duration = datetime.now(timezone.utc) - (start_time if start_time.tzinfo else start_time.replace(tzinfo=timezone.utc))
    duration_seconds = int(duration.total_seconds())
    payload = {
        "report_version": 3,
        "target_url": target_url,
        "scan_mode": scan_mode,
        "scan_started_at": started_at_malaysia.isoformat(),
        "scan_started_at_utc": (start_time if start_time.tzinfo else start_time.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat(),
        "scan_duration_seconds": duration_seconds,
        "summary": {
            "finding_count": len(findings),
            "severity_counts": _severity_counts(findings),
        },
        "overview": scan_overview or {},
        "assessment": assessment or {},
        "report_profile": report_profile,
        "include_manual_assessment": bool(include_manual_assessment),
        "findings": findings,
    }
    payload["summary"]["executive_summary"] = _build_executive_summary(payload)
    return payload


def _render_metric_cards(summary: dict, assessment_summary: dict, overview: dict) -> str:
    severity_counts = summary.get("severity_counts", {})
    tool_summary = overview.get("tool_summary", {})
    note_count = assessment_summary.get("note_count", 0)
    verified = assessment_summary.get("verification_status", {}).get("confirmed", 0) + assessment_summary.get("verification_status", {}).get("reproduced", 0)
    metrics = [
        ("Critical", severity_counts.get("critical", 0), "critical"),
        ("High", severity_counts.get("high", 0), "high"),
        ("Medium", severity_counts.get("medium", 0), "medium"),
        ("Low", severity_counts.get("low", 0), "low"),
        ("Tool Failures", tool_summary.get("failed", 0) + tool_summary.get("timeout", 0) + tool_summary.get("missing", 0), "info"),
        ("Partial Tool Runs", tool_summary.get("partial", 0), "warn"),
        ("Verified Cases", verified, "good"),
        ("Analyst Notes", note_count, "info"),
        ("Total Findings", summary.get("finding_count", 0), "total"),
    ]
    return "".join(
        f"<div class='metric-card {css}'><div class='label'>{html.escape(label)}</div><div class='value'>{value}</div></div>"
        for label, value, css in metrics
    )


def _render_standards_tags(finding: dict) -> str:
    """Render compact framework badge tags for a finding card."""
    parts: list[str] = []

    for item in finding.get("owasp", []):
        parts.append(
            f"<a href='{html.escape(item['url'])}' target='_blank' class='std-tag owasp-tag' "
            f"title='OWASP {html.escape(item['id'])}: {html.escape(item['title'])}'>"
            f"OWASP {html.escape(item['id'])}</a>"
        )
    for item in finding.get("mitre_attack", []):
        parts.append(
            f"<a href='{html.escape(item['url'])}' target='_blank' class='std-tag mitre-tag' "
            f"title='MITRE ATT&amp;CK {html.escape(item['id'])}: {html.escape(item['name'])} ({html.escape(item['tactic'])})'>"
            f"ATT&amp;CK {html.escape(item['id'])}</a>"
        )
    for item in finding.get("cis_controls", []):
        parts.append(
            f"<a href='{html.escape(item['url'])}' target='_blank' class='std-tag cis-tag' "
            f"title='CIS {html.escape(item['id'])}: {html.escape(item['title'])}'>"
            f"{html.escape(item['id'])}</a>"
        )
    for item in finding.get("nist_csf", []):
        parts.append(
            f"<a href='{html.escape(item['url'])}' target='_blank' class='std-tag nist-tag' "
            f"title='NIST CSF {html.escape(item['id'])}: {html.escape(item['category'])} ({html.escape(item['function'])})'>"
            f"NIST {html.escape(item['id'])}</a>"
        )

    if not parts:
        return ""
    return "<div class='standards-row'>" + "".join(parts) + "</div>"


def _render_report_template(template_vars: dict[str, str]) -> str | None:
    """Render the external HTML report template with {{TOKEN}} substitution.

    Returns None if the template file is unavailable, so callers can fall back
    to an inline renderer.
    """
    try:
        if not HTML_TEMPLATE_FILE.exists():
            return None
        template = HTML_TEMPLATE_FILE.read_text(encoding="utf-8")
        for key, value in template_vars.items():
            template = template.replace("{{" + key + "}}", value)
        return template
    except Exception:
        return None


def generate_sarif_report(payload: dict) -> dict:
    """Generate a SARIF 2.1.0 report from a scan payload.

    Compatible with GitHub Code Scanning, VS Code SARIF Viewer,
    and most enterprise security platforms.
    """
    findings = payload.get("findings", [])
    target_url = payload.get("target_url", "unknown")
    scan_mode = payload.get("scan_mode", "unknown")

    # Build de-duplicated rule set from finding titles
    rules: list[dict] = []
    rule_ids_seen: dict[str, str] = {}  # title_key -> ruleId
    for finding in findings:
        title_key = finding.get("title", "Unknown").strip().lower()
        if title_key not in rule_ids_seen:
            rule_id = finding.get("id") or f"RULE-{len(rules) + 1:03d}"
            rule_ids_seen[title_key] = rule_id
            owasp_tags = [f"owasp/{item['id']}" for item in finding.get("owasp", [])]
            mitre_tags = [item["id"] for item in finding.get("mitre_attack", [])]
            cis_tags = [item["id"] for item in finding.get("cis_controls", [])]
            nist_tags = [item["id"] for item in finding.get("nist_csf", [])]
            rules.append({
                "id": rule_id,
                "name": finding.get("title", "Unknown").replace(" ", ""),
                "shortDescription": {"text": finding.get("title", "Unknown")},
                "fullDescription": {"text": finding.get("description", "") or finding.get("title", "")},
                "helpUri": (finding.get("references") or [None])[0],
                "help": {
                    "text": finding.get("fix") or "Review and remediate this finding.",
                    "markdown": (
                        "**Fix:** " + (finding.get("fix") or "Review and remediate this finding.") + "\n\n"
                        + "\n".join(f"- {s}" for s in (finding.get("fix_steps") or []))
                    ),
                },
                "properties": {
                    "tags": ["security"] + owasp_tags + mitre_tags + cis_tags + nist_tags,
                    "precision": "medium",
                    "problem.severity": SARIF_LEVEL_MAP.get(finding.get("severity", "info"), "note"),
                    "security-severity": {
                        "critical": "9.0",
                        "high": "7.5",
                        "medium": "5.0",
                        "low": "2.5",
                        "info": "0.5",
                    }.get(finding.get("severity", "info"), "0.5"),
                },
            })

    # Build results
    results: list[dict] = []
    for finding in findings:
        title_key = finding.get("title", "Unknown").strip().lower()
        rule_id = rule_ids_seen.get(title_key, finding.get("id", "RULE-000"))
        severity = finding.get("severity", "info")
        level = SARIF_LEVEL_MAP.get(severity, "note")

        owasp_ids = ", ".join(item["id"] for item in finding.get("owasp", []))
        mitre_ids = ", ".join(item["id"] for item in finding.get("mitre_attack", []))
        cis_ids = ", ".join(item["id"] for item in finding.get("cis_controls", []))
        nist_ids = ", ".join(item["id"] for item in finding.get("nist_csf", []))

        result: dict = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": (
                    finding.get("description") or finding.get("title", "Security finding detected.")
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target_url,
                            "uriBaseId": "%SRCROOT%",
                        }
                    },
                    "logicalLocations": [
                        {
                            "name": target_url,
                            "kind": "url",
                        }
                    ],
                }
            ],
            "properties": {
                "severity": severity,
                "source_tool": finding.get("source_tool", ""),
                "cve": finding.get("cve", ""),
                "evidence": (finding.get("evidence") or "")[:500],
                "owasp": owasp_ids,
                "mitre_attack": mitre_ids,
                "cis_controls": cis_ids,
                "nist_csf": nist_ids,
            },
        }
        if finding.get("cve"):
            result["relatedLocations"] = [
                {
                    "message": {"text": f"CVE: {finding['cve']}"},
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f"https://nvd.nist.gov/vuln/detail/{finding['cve']}"
                        }
                    },
                }
            ]
        results.append(result)

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "OmniScan",
                        "version": "3.0.0",
                        "informationUri": "https://github.com/omniscan",
                        "rules": rules,
                        "properties": {
                            "frameworkReferences": [
                                "OWASP Top 10 2021",
                                "MITRE ATT&CK for Enterprise v14",
                                "CIS Controls v8",
                                "NIST CSF 2.0",
                            ]
                        },
                    }
                },
                "results": results,
                "properties": {
                    "target_url": target_url,
                    "scan_mode": scan_mode,
                    "scan_started_at": payload.get("scan_started_at", ""),
                    "scan_duration_seconds": payload.get("scan_duration_seconds", 0),
                },
            }
        ],
    }


def generate_csv_report(payload: dict) -> str:
    """Generate a flat CSV report from a scan payload.

    Columns include all security framework identifiers for use in
    ticketing systems, vulnerability management platforms, and SIEM import.
    """
    findings = payload.get("findings", [])
    target_url = payload.get("target_url", "")
    scan_started_at = payload.get("scan_started_at", "")
    scan_mode = payload.get("scan_mode", "")

    fieldnames = [
        "id", "title", "severity", "source_tool", "cve",
        "owasp_ids", "owasp_titles",
        "mitre_attack_ids", "mitre_attack_names", "mitre_tactics",
        "cis_control_ids", "cis_control_titles",
        "nist_csf_ids", "nist_csf_functions", "nist_csf_categories",
        "description", "evidence", "fix_summary", "references",
        "target_url", "scan_mode", "scan_started_at",
    ]

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    for finding in findings:
        owasp = finding.get("owasp", [])
        mitre = finding.get("mitre_attack", [])
        cis = finding.get("cis_controls", [])
        nist = finding.get("nist_csf", [])

        row = {
            "id": finding.get("id", ""),
            "title": finding.get("title", ""),
            "severity": finding.get("severity", ""),
            "source_tool": finding.get("source_tool", ""),
            "cve": finding.get("cve", ""),
            "owasp_ids": "; ".join(item["id"] for item in owasp),
            "owasp_titles": "; ".join(item["title"] for item in owasp),
            "mitre_attack_ids": "; ".join(item["id"] for item in mitre),
            "mitre_attack_names": "; ".join(item["name"] for item in mitre),
            "mitre_tactics": "; ".join(item["tactic"] for item in mitre),
            "cis_control_ids": "; ".join(item["id"] for item in cis),
            "cis_control_titles": "; ".join(item["title"] for item in cis),
            "nist_csf_ids": "; ".join(item["id"] for item in nist),
            "nist_csf_functions": "; ".join(item["function"] for item in nist),
            "nist_csf_categories": "; ".join(item["category"] for item in nist),
            "description": finding.get("description", ""),
            "evidence": (finding.get("evidence") or "")[:500],
            "fix_summary": finding.get("fix", ""),
            "references": "; ".join(finding.get("references", [])),
            "target_url": target_url,
            "scan_mode": scan_mode,
            "scan_started_at": scan_started_at,
        }
        writer.writerow(row)

    return output.getvalue()


def generate_html_report(payload: dict) -> str:
    def _severity_rank(sev: str) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}.get((sev or "info").lower(), 0)

    def _derive_exploitability(finding: dict) -> str:
        val = str(finding.get("exploitability", "")).strip().lower()
        if val in {"high", "medium", "low"}:
            return val
        sev = str(finding.get("severity", "info")).lower()
        text = " ".join([
            str(finding.get("title", "")),
            str(finding.get("description", "")),
            str(finding.get("evidence", "")),
        ]).lower()
        if "rce" in text or "auth bypass" in text or "sql injection" in text:
            return "high"
        if sev in {"critical", "high"}:
            return "high"
        if sev == "medium":
            return "medium"
        return "low"

    def _derive_confidence(finding: dict) -> str:
        val = str(finding.get("confidence", "")).strip().lower()
        if val in {"confirmed", "probable", "possible"}:
            return val
        verification = str(finding.get("verification_status", "")).lower()
        if verification in {"confirmed", "reproduced"}:
            return "confirmed"
        if finding.get("evidence"):
            return "probable"
        return "possible"

    def _derive_status(finding: dict) -> str:
        val = str(finding.get("status", "")).strip().lower()
        if val in {"new", "known", "in_progress", "fixed", "verified", "false_positive"}:
            return val
        verification = str(finding.get("verification_status", "")).lower()
        if verification in {"fixed"}:
            return "fixed"
        if verification in {"confirmed", "reproduced"}:
            return "verified"
        return "new"

    def _derive_owner(finding: dict) -> str:
        return str(finding.get("owner") or finding.get("assignee") or "-")

    def _derive_asset(finding: dict, target_url: str) -> str:
        return str(finding.get("asset") or finding.get("url") or finding.get("endpoint") or target_url or "-")

    def _coverage_metrics(tool_runs: list[dict]) -> tuple[int, int, int, int, int]:
        total = len(tool_runs)
        completed = 0
        failed = 0
        timeout = 0
        missing = 0
        for run in tool_runs:
            status = str(run.get("status", "")).lower()
            if status in {"completed", "completed_no_output", "completed_partial"}:
                completed += 1
            elif status == "failed":
                failed += 1
            elif status == "timeout":
                timeout += 1
            elif status in {"missing", "skipped"}:
                missing += 1
        return total, completed, failed, timeout, missing

    def _overall_risk(summary: dict) -> str:
        sev = summary.get("severity_counts", {})
        if sev.get("critical", 0) > 0:
            return "critical"
        if sev.get("high", 0) > 0:
            return "high"
        if sev.get("medium", 0) > 0:
            return "medium"
        return "low"

    def _compliance_crosswalk_rows(findings: list[dict]) -> list[str]:
        mapping: dict[tuple[str, str], set[str]] = {}
        for f in findings:
            fid = str(f.get("id", "")).strip() or "-"
            for item in f.get("owasp", []):
                key = ("OWASP Top 10", item.get("id", ""))
                mapping.setdefault(key, set()).add(fid)
            for item in f.get("mitre_attack", []):
                key = ("MITRE ATT&CK", item.get("id", ""))
                mapping.setdefault(key, set()).add(fid)
            for item in f.get("cis_controls", []):
                key = ("CIS Controls v8", item.get("id", ""))
                mapping.setdefault(key, set()).add(fid)
            for item in f.get("nist_csf", []):
                key = ("NIST CSF 2.0", item.get("id", ""))
                mapping.setdefault(key, set()).add(fid)
        rows: list[str] = []
        for (framework, control_id), fids in sorted(mapping.items(), key=lambda x: (x[0][0], x[0][1])):
            status = "Not met"
            if len(fids) <= 2:
                status = "Partial"
            if len(fids) == 1:
                status = "Partial"
            rows.append(
                f"<tr><td>{html.escape(framework)}</td><td>{html.escape(control_id)}</td><td>{html.escape(', '.join(sorted(fids)))}</td><td>{status}</td></tr>"
            )
        return rows

    def _build_action_rows(findings: list[dict], bucket: str) -> list[str]:
        rows: list[str] = []
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if bucket == "24h" and sev not in {"critical", "high"}:
                continue
            if bucket == "7d" and sev != "medium":
                continue
            if bucket == "30d" and sev not in {"low", "info"}:
                continue
            owner = _derive_owner(f)
            action = f.get("fix") or "Review and remediate based on validated evidence"
            rows.append(
                f"<tr><td>{html.escape(str(f.get('id', '-')))}</td><td>{html.escape(str(action))}</td><td>{html.escape(owner)}</td></tr>"
            )
            if len(rows) >= 10:
                break
        return rows

    findings = payload.get("findings", [])
    summary = payload.get("summary", {})
    overview = payload.get("overview", {})
    fingerprint = overview.get("fingerprint", {})
    discovery = overview.get("discovery", {})
    tool_runs = overview.get("tool_runs", [])
    include_manual_assessment = bool(payload.get("include_manual_assessment", True))
    report_profile = str(payload.get("report_profile", "technical")).strip().lower()
    if report_profile == "executive":
        include_manual_assessment = False
    assessment = payload.get("assessment", {}) if include_manual_assessment else {}
    workbook = assessment.get("workbook", {}) if isinstance(assessment, dict) else {}
    assessment_summary = _assessment_summary(assessment)
    executive_summary = summary.get("executive_summary", [])

    tools_rows = []
    for run in tool_runs:
        outputs = run.get("output_files", [])
        output_html = "<br>".join(html.escape(Path(path).name) for path in outputs[:4]) or "None"
        command = html.escape(" ".join(run.get("command", []))) or "-"
        tools_rows.append(
            "<tr>"
            f"<td>{html.escape(run.get('label', run.get('name', 'tool')))}</td>"
            f"<td>{html.escape(run.get('phase', ''))}</td>"
            f"<td>{_tool_status_badge(run.get('status', 'unknown'))}</td>"
            f"<td>{run.get('duration_seconds', 0)}</td>"
            f"<td><code>{command}</code></td>"
            f"<td>{output_html}</td>"
            f"<td>{html.escape(run.get('note', '') or '-')}</td>"
            "</tr>"
        )

    discovery_blocks = []
    for label, items in [
        ("Subdomains", discovery.get("subdomains", [])),
        ("Parameters", discovery.get("parameters", [])),
        ("gau URLs", discovery.get("sample_urls", {}).get("gau", [])),
        ("Katana URLs", discovery.get("sample_urls", {}).get("katana", [])),
        ("ffuf Paths", discovery.get("sample_urls", {}).get("ffuf", [])),
        ("Feroxbuster Paths", discovery.get("sample_urls", {}).get("feroxbuster", [])),
    ]:
        if not items:
            continue
        rendered = "".join(f"<li>{html.escape(str(item))}</li>" for item in items[:50])
        count_label = f" <small style='color:var(--muted);font-weight:400'>({len(items)} total)</small>" if len(items) > 50 else f" <small style='color:var(--muted);font-weight:400'>({len(items)})</small>"
        discovery_blocks.append(f"<div class='card disc-card'><h3 style='margin:0 0 10px;font-size:0.95rem'>{html.escape(label)}{count_label}</h3><ul>{rendered}</ul></div>")

    finding_rows = []
    finding_cards = []
    for idx, finding in enumerate(findings, 1):
        severity = finding.get("severity", "info")
        exploitability = _derive_exploitability(finding)
        confidence = _derive_confidence(finding)
        status = _derive_status(finding)
        owner = _derive_owner(finding)
        asset = _derive_asset(finding, payload.get("target_url", ""))
        title = html.escape(finding.get("title", "Finding"))
        evidence = html.escape(finding.get("evidence", ""))
        description = html.escape(finding.get("description", ""))
        cve = html.escape(finding.get("cve", ""))
        refs = finding.get("references", [])
        ref_html = "".join(f"<li><a href='{html.escape(ref)}' target='_blank'>{html.escape(ref)}</a></li>" for ref in refs)
        steps = finding.get("fix_steps", [])
        if steps:
            fix_html = "<ol>" + "".join(f"<li>{html.escape(str(step))}</li>" for step in steps) + "</ol>"
        else:
            fix_html = f"<p>{html.escape(finding.get('fix') or 'Review and remediate based on the evidence above.')}</p>"

        finding_rows.append(
            f"<tr data-severity='{html.escape(str(severity))}' data-exploitability='{html.escape(exploitability)}' data-status='{html.escape(status)}'>"
            f"<td>{idx}</td>"
            f"<td><span class='sev {severity}'>{severity}</span></td>"
            f"<td>{html.escape(exploitability)}</td>"
            f"<td>{html.escape(confidence)}</td>"
            f"<td>{title}</td>"
            f"<td class='url-cell'>{html.escape(asset)}</td>"
            f"<td>{html.escape(finding.get('source_tool', ''))}</td>"
            f"<td>{cve or '-'}</td>"
            f"<td>{html.escape(owner)}</td>"
            f"<td>{html.escape(status.replace('_', ' '))}</td>"
            "</tr>"
        )
        finding_cards.append(
            f"""
            <details class="finding {severity}">
                <summary>
                    <span class="sev {severity}">{severity}</span>
                    <span class="sum-title">{html.escape(finding.get('id', ''))} {title}</span>
                    <span class="url-cell" style="color:var(--muted);font-size:0.8em">{html.escape(finding.get('source_tool', ''))}{' &nbsp;&middot;&nbsp; ' + cve if cve else ''}</span>
                    <svg class="sum-chevron" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg>
                </summary>
                <div class="finding-body">
                    <p class="meta">Source: {html.escape(finding.get('source_tool', ''))}{' | CVE: ' + cve if cve else ''}</p>
                    <p class="meta">Exploitability: {html.escape(exploitability)} | Confidence: {html.escape(confidence)} | Status: {html.escape(status.replace('_', ' '))} | Owner: {html.escape(owner)}</p>
                    <p class="meta">Asset: <span class='url-cell'>{html.escape(asset)}</span></p>
                    {_render_standards_tags(finding)}
                    <p>{description}</p>
                    {'<pre>' + evidence + '</pre>' if evidence else ''}
                    <div class="fix-block">
                        <h4>Recommended Fix</h4>
                        {fix_html}
                    </div>
                    {'<div class="refs"><h4>References</h4><ul>' + ref_html + '</ul></div>' if ref_html else ''}
                </div>
            </details>
            """
        )

    category_rows = []
    workbook_cases = []
    case_rows = []
    notes_html = ""
    verification_html = ""
    if include_manual_assessment:
        for category, data in assessment_summary.get("category_coverage", {}).items():
            category_rows.append(
                f"<tr><td>{html.escape(category)}</td><td>{data.get('total', 0)}</td><td>{data.get('completed', 0)}</td><td>{data.get('confirmed', 0)}</td></tr>"
            )

        workbook_cases = workbook.get("cases", [])
        for case in workbook_cases:
            case_rows.append(
                "<tr>"
                f"<td>{html.escape(case.get('category', ''))}</td>"
                f"<td>{html.escape(case.get('title', ''))}</td>"
                f"<td><span class='pill muted'>{html.escape(case.get('status', 'not_started').replace('_', ' '))}</span></td>"
                f"<td><span class='pill muted'>{html.escape(case.get('verification_status', 'not_verified').replace('_', ' '))}</span></td>"
                f"<td>{html.escape(case.get('owner', '') or '-')}</td>"
                f"<td>{html.escape((case.get('notes', '') or '')[:220] or '-')}</td>"
                "</tr>"
            )

        for note in workbook.get("operator_notes", []):
            notes_html += (
                "<div class='note-card'>"
                f"<div class='note-head'><strong>{html.escape(note.get('title', 'Untitled note'))}</strong><span>{html.escape(note.get('type', 'analysis'))}</span></div>"
                f"<div class='note-meta'>{html.escape(note.get('author', '') or 'Unassigned analyst')} | {html.escape(note.get('updated_at', note.get('created_at', '')))}</div>"
                f"<p>{html.escape(note.get('body', '') or '')}</p>"
                "</div>"
            )

        for run in workbook.get("verification_runs", []):
            verification_html += (
                "<div class='note-card'>"
                f"<div class='note-head'><strong>{html.escape(run.get('title', 'Verification run'))}</strong><span>{html.escape(run.get('outcome', 'pending'))}</span></div>"
                f"<div class='note-meta'>{html.escape(run.get('created_at', ''))}</div>"
                f"<p><strong>Scope:</strong> {html.escape(run.get('scope', '') or '-')}</p>"
                f"<p>{html.escape(run.get('notes', '') or '')}</p>"
                "</div>"
            )

    scan_date = _as_malaysia_time(datetime.fromisoformat(payload["scan_started_at"])).strftime("%Y-%m-%d %H:%M:%S %Z")
    duration_seconds = payload.get("scan_duration_seconds", 0)
    severity_counts = summary.get("severity_counts", {})
    overall_risk = _overall_risk(summary)
    total_tools, completed_tools, failed_tools, timeout_tools, missing_tools = _coverage_metrics(tool_runs)
    coverage_pct = int((completed_tools / total_tools) * 100) if total_tools else 0
    confidence_level = "high" if coverage_pct >= 85 else ("medium" if coverage_pct >= 60 else "low")

    findings_sorted = sorted(
        findings,
        key=lambda f: (
            _severity_rank(str(f.get("severity", "info"))),
            {"high": 3, "medium": 2, "low": 1}.get(_derive_exploitability(f), 0),
            {"confirmed": 3, "probable": 2, "possible": 1}.get(_derive_confidence(f), 0),
        ),
        reverse=True,
    )
    top_risk_rows: list[str] = []
    for f in findings_sorted[:5]:
        top_risk_rows.append(
            "<tr>"
            f"<td>{html.escape(str(f.get('id', '-')))}</td>"
            f"<td>{html.escape(str(f.get('title', 'Finding')))}</td>"
            f"<td><span class='sev {html.escape(str(f.get('severity', 'info')))}'>{html.escape(str(f.get('severity', 'info')))}</span></td>"
            f"<td>{html.escape(_derive_exploitability(f))}</td>"
            f"<td class='url-cell'>{html.escape(_derive_asset(f, payload.get('target_url', '')))}</td>"
            f"<td>{html.escape(_derive_status(f).replace('_', ' '))}</td>"
            "</tr>"
        )

    actions_24h = _build_action_rows(findings_sorted, "24h")
    actions_7d = _build_action_rows(findings_sorted, "7d")
    actions_30d = _build_action_rows(findings_sorted, "30d")
    compliance_rows = _compliance_crosswalk_rows(findings)

    executive_summary_html = html.escape(" ".join(item.strip() for item in executive_summary if str(item).strip()))

    rendered_from_template = _render_report_template(
        {
            "TITLE_TARGET": html.escape(payload.get("target_url", "target")),
            "TARGET_URL": html.escape(payload.get("target_url", "")),
            "SCAN_DATE": scan_date,
            "SCAN_MODE": html.escape(payload.get("scan_mode", "")),
            "REQUESTED_PROFILE": html.escape(overview.get("requested_profile", "")),
            "EFFECTIVE_PROFILE": html.escape(overview.get("effective_profile", "")),
            "SCAN_DURATION_SECONDS": str(duration_seconds),
            "RISK_POSTURE": overall_risk.upper(),
            "DATA_CONFIDENCE": confidence_level.upper(),
            "CRITICAL_HIGH_COUNT": str(severity_counts.get("critical", 0) + severity_counts.get("high", 0)),
            "COVERAGE_COMPLETENESS": str(coverage_pct),
            "METRIC_CARDS": _render_metric_cards(summary, assessment_summary, overview),
            "EXEC_SUMMARY_LIST": executive_summary_html,
            "TOTAL_TOOLS": str(total_tools),
            "COMPLETED_TOOLS": str(completed_tools),
            "FAILED_TOOLS": str(failed_tools),
            "TIMEOUT_TOOLS": str(timeout_tools),
            "MISSING_TOOLS": str(missing_tools),
            "ACTIONS_24H_ROWS": "".join(actions_24h) or "<tr><td colspan='3'>No urgent actions identified.</td></tr>",
            "ACTIONS_7D_ROWS": "".join(actions_7d) or "<tr><td colspan='3'>No medium-priority actions identified.</td></tr>",
            "ACTIONS_30D_ROWS": "".join(actions_30d) or "<tr><td colspan='3'>No deferred actions identified.</td></tr>",
            "TOP_RISK_ROWS": "".join(top_risk_rows) or "<tr><td colspan='6'>No findings available.</td></tr>",
            "FINGERPRINT_TITLE": html.escape(str(fingerprint.get("title", "") or "-")),
            "FINGERPRINT_STATUS_CODE": html.escape(str(fingerprint.get("status_code", "") or "-")),
            "FINGERPRINT_WEBSERVER": html.escape(str(fingerprint.get("webserver", "") or "-")),
            "FINGERPRINT_TECHS": html.escape(", ".join(fingerprint.get("technologies", [])) or "-"),
            "FINGERPRINT_WHATWEB": html.escape(", ".join(fingerprint.get("whatweb_plugins", [])) or "-"),
            "DISCOVERY_SUBDOMAINS": str(discovery.get("subdomain_count", 0)),
            "DISCOVERY_PARAMETERS": str(discovery.get("parameter_count", 0)),
            "DISCOVERY_GAU": str(discovery.get("gau_count", 0)),
            "DISCOVERY_KATANA": str(discovery.get("katana_count", 0)),
            "DISCOVERY_FFUF": str(discovery.get("ffuf_count", 0)),
            "DISCOVERY_FEROX": str(discovery.get("feroxbuster_count", 0)),
            "CATEGORY_COVERAGE_ROWS": "".join(category_rows) or "<tr><td colspan='4'>No category coverage data yet.</td></tr>",
            "TOOLS_ROWS": "".join(tools_rows) or "<tr><td colspan='7'>No tool telemetry captured.</td></tr>",
            "DISCOVERY_BLOCKS": "".join(discovery_blocks) or "<div class='card'>No discovery artifacts captured.</div>",
            "CASE_ROWS": "".join(case_rows) or "<tr><td colspan='6'>No guided cases loaded.</td></tr>",
            "NOTES_HTML": notes_html or "<p>No operator notes recorded.</p>",
            "VERIFICATION_HTML": verification_html or "<p>No verification runs recorded.</p>",
            "FINDING_ROWS": "".join(finding_rows) or "<tr><td colspan='10'>No findings were parsed from the available outputs.</td></tr>",
            "FINDING_CARDS": "".join(finding_cards) or "<div class='card'>No findings available.</div>",
            "COMPLIANCE_ROWS": "".join(compliance_rows) or "<tr><td colspan='4'>No standards mapping data available.</td></tr>",
        }
    )
    if rendered_from_template:
        return rendered_from_template

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OmniScan Assessment Report - {html.escape(payload.get('target_url', 'target'))}</title>
    <style>
        :root {{
            --bg: #08101d;
            --panel: #101826;
            --panel-2: #162133;
            --text: #e6eef8;
            --muted: #91a3c1;
            --border: #283750;
            --accent: #46b7ff;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #60a5fa;
            --info: #94a3b8;
            --good: #22c55e;
            --violet: #8b5cf6;
        }}
        * {{ box-sizing: border-box; }}
        body {{ margin: 0; font-family: Segoe UI, Arial, sans-serif; background: radial-gradient(circle at top left, rgba(70,183,255,0.12), transparent 35%), linear-gradient(180deg, #07101d, #101826 28%); color: var(--text); }}
        .wrap {{ max-width: 1320px; margin: 0 auto; padding: 28px; }}
        .hero {{ background: linear-gradient(135deg, rgba(16,24,38,0.95), rgba(23,37,84,0.92)); border: 1px solid var(--border); border-radius: 22px; padding: 28px; box-shadow: 0 18px 60px rgba(2, 6, 23, 0.35); }}
        .hero h1 {{ margin: 0 0 8px; font-size: 32px; }}
        .hero p {{ margin: 0; color: var(--muted); }}
        .grid {{ display: grid; gap: 16px; }}
        .meta-grid {{ grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-top: 20px; }}
        .metrics {{ grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); margin: 24px 0; }}
        .two {{ grid-template-columns: 1.15fr 1fr; }}
        .three {{ grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }}
        .card, .metric-card {{ background: rgba(16,24,38,0.94); border: 1px solid var(--border); border-radius: 18px; padding: 18px; overflow: hidden; }}
        .metric-card .label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
        .metric-card .value {{ font-size: 34px; font-weight: 800; margin-top: 8px; }}
        .metric-card.critical .value {{ color: var(--critical); }}
        .metric-card.high .value {{ color: var(--high); }}
        .metric-card.medium .value {{ color: var(--medium); }}
        .metric-card.low .value {{ color: var(--low); }}
        .metric-card.info .value {{ color: var(--info); }}
        .metric-card.good .value {{ color: var(--good); }}
        .metric-card.total .value {{ color: var(--accent); }}
        h2 {{ margin: 30px 0 12px; font-size: 22px; }}
        h3 {{ margin-top: 0; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
        th {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
        .sev, .pill {{ display: inline-block; border-radius: 999px; padding: 4px 10px; font-size: 12px; font-weight: 700; text-transform: uppercase; }}
        .sev.critical {{ background: rgba(239,68,68,0.14); color: var(--critical); }}
        .sev.high {{ background: rgba(249,115,22,0.14); color: var(--high); }}
        .sev.medium {{ background: rgba(245,158,11,0.14); color: var(--medium); }}
        .sev.low {{ background: rgba(96,165,250,0.14); color: var(--low); }}
        .sev.info {{ background: rgba(148,163,184,0.14); color: var(--info); }}
        .pill.good {{ background: rgba(34,197,94,0.15); color: #86efac; }}
        .pill.bad {{ background: rgba(239,68,68,0.15); color: #fca5a5; }}
        .pill.warn {{ background: rgba(245,158,11,0.15); color: #fcd34d; }}
        .pill.muted {{ background: rgba(148,163,184,0.15); color: #cbd5e1; }}
        .exec-list {{ margin: 0; padding-left: 20px; }}
        .finding {{ border-left: 4px solid var(--border); margin-bottom: 16px; }}
        .finding.critical {{ border-left-color: var(--critical); }}
        .finding.high {{ border-left-color: var(--high); }}
        .finding.medium {{ border-left-color: var(--medium); }}
        .finding.low {{ border-left-color: var(--low); }}
        .finding.info {{ border-left-color: var(--info); }}
        .finding-head, .note-head {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; }}
        .meta, .note-meta {{ color: var(--muted); font-size: 13px; }}
        pre, code {{ background: #09111f; border: 1px solid var(--border); color: #dbeafe; border-radius: 10px; }}
        pre {{ padding: 12px; white-space: pre-wrap; overflow-x: auto; }}
        code {{ padding: 2px 6px; }}
        ul, ol {{ padding-left: 20px; }}
        a {{ color: #7dd3fc; }}
        .narrative {{ white-space: pre-wrap; line-height: 1.6; }}
        .note-card {{ background: rgba(22,33,51,0.75); border: 1px solid var(--border); border-radius: 14px; padding: 14px; margin-bottom: 12px; }}
        .toc {{ position: sticky; top: 12px; z-index: 10; background: rgba(16,24,38,0.92); border: 1px solid var(--border); border-radius: 12px; padding: 10px 12px; margin: 0 0 14px; backdrop-filter: blur(3px); }}
        .toc a {{ color: var(--muted); text-decoration: none; font-size: 12px; margin-right: 12px; }}
        .toc a:hover {{ color: var(--text); }}
        .risk-banner {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; margin-top: 14px; }}
        .risk-chip {{ border: 1px solid var(--border); border-radius: 12px; padding: 10px 12px; background: rgba(8,16,29,0.65); }}
        .risk-chip .k {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }}
        .risk-chip .v {{ font-size: 20px; font-weight: 700; margin-top: 4px; }}
        .actions-grid {{ grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }}
        .legend {{ color: var(--muted); font-size: 13px; margin-top: 8px; }}
        .appendix-note {{ color: var(--muted); font-size: 13px; margin-bottom: 10px; }}
        @media (max-width: 980px) {{ .two {{ grid-template-columns: 1fr; }} }}
        @media print {{
            .toc, .findings-toolbar, .findings-pages {{ display: none !important; }}
            details.finding > summary .sum-chevron {{ display: none; }}
        }}
        /* ── Text overflow fixes ─────────────────────────────────────────── */
        td, th {{ word-break: break-word; overflow-wrap: anywhere; max-width: 480px; }}
        td code {{ word-break: break-all; white-space: pre-wrap; }}
        pre {{ white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; overflow-x: auto; max-width: 100%; }}
        .url-cell {{ word-break: break-all; font-size: 0.82em; }}
        ul {{ padding-left: 18px; margin: 0; }}
        li {{ word-break: break-all; overflow-wrap: anywhere; font-size: 0.82em; color: var(--muted); margin-bottom: 4px; }}
        .disc-card {{ overflow: hidden; min-width: 0; }}
        .disc-card ul {{ max-height: 280px; overflow-y: auto; }}
        /* ── Findings search / filter / pagination ───────────────────────── */
        .findings-toolbar {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 12px; align-items: center; }}
        .findings-toolbar input {{ flex: 1; min-width: 200px; padding: 8px 12px; background: #0d1929; border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 14px; }}
        .findings-toolbar select {{ padding: 8px 10px; background: #0d1929; border: 1px solid var(--border); border-radius: 8px; color: var(--text); font-size: 14px; }}
        .findings-toolbar .findings-count {{ color: var(--muted); font-size: 13px; white-space: nowrap; }}
        .findings-pages {{ display: flex; gap: 6px; flex-wrap: wrap; margin-top: 10px; align-items: center; }}
        .findings-pages button {{ padding: 5px 11px; background: rgba(255,255,255,0.06); border: 1px solid var(--border); border-radius: 6px; color: var(--text); cursor: pointer; font-size: 13px; }}
        .findings-pages button.active {{ background: var(--accent); color: #000; border-color: var(--accent); }}
        .findings-pages button:hover:not(.active) {{ background: rgba(255,255,255,0.1); }}
        /* ── Collapsible finding cards ───────────────────────────────────── */
        details.finding {{ padding: 0; }}
        details.finding > summary {{ list-style: none; cursor: pointer; padding: 14px 18px; border-radius: 12px; background: rgba(16,24,38,0.94); border: 1px solid var(--border); display: flex; align-items: center; gap: 12px; }}
        details.finding > summary::-webkit-details-marker {{ display: none; }}
        details.finding[open] > summary {{ border-bottom-left-radius: 0; border-bottom-right-radius: 0; border-bottom-color: transparent; }}
        details.finding > summary .sum-chevron {{ margin-left: auto; transition: transform 0.2s; flex-shrink: 0; }}
        details.finding[open] > summary .sum-chevron {{ transform: rotate(180deg); }}
        .finding-body {{ padding: 14px 18px; background: rgba(14,22,36,0.96); border: 1px solid var(--border); border-top: none; border-bottom-left-radius: 12px; border-bottom-right-radius: 12px; }}
        details.finding.critical > summary {{ border-left: 4px solid var(--critical); }}
        details.finding.high    > summary {{ border-left: 4px solid var(--high); }}
        details.finding.medium  > summary {{ border-left: 4px solid var(--medium); }}
        details.finding.low     > summary {{ border-left: 4px solid var(--low); }}
        details.finding.info    > summary {{ border-left: 4px solid var(--info); }}
        .sum-title {{ font-weight: 600; font-size: 0.93rem; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
        #findingsDetailPages {{ display:none; }}
        /* ── Security framework tags ─────────────────────────────────────── */
        .standards-row {{ display: flex; flex-wrap: wrap; gap: 5px; margin: 8px 0 10px; }}
        .std-tag {{ display: inline-block; padding: 2px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; text-decoration: none; cursor: pointer; }}
        .owasp-tag {{ background: rgba(239,68,68,0.12); color: #fca5a5; border: 1px solid rgba(239,68,68,0.25); }}
        .mitre-tag {{ background: rgba(245,158,11,0.12); color: #fcd34d; border: 1px solid rgba(245,158,11,0.25); }}
        .cis-tag {{ background: rgba(70,183,255,0.12); color: #93c5fd; border: 1px solid rgba(70,183,255,0.25); }}
        .nist-tag {{ background: rgba(34,197,94,0.12); color: #86efac; border: 1px solid rgba(34,197,94,0.25); }}
        .std-tag:hover {{ opacity: 0.8; }}
    </style>
</head>
<body>
    <div class="wrap">
        <nav class="toc">
            <a href="#executive-summary">Executive Summary</a>
            <a href="#coverage-limitations">Coverage</a>
            <a href="#immediate-actions">Actions</a>
            <a href="#risk-snapshot">Risk Snapshot</a>
            <a href="#findings-index">Findings</a>
            <a href="#compliance-crosswalk">Crosswalk</a>
            <a href="#appendix">Appendix</a>
        </nav>
        <section class="hero">
            <h1>OmniScan Comprehensive Assessment Report</h1>
            <p>{html.escape(payload.get('target_url', ''))}</p>
            <div class="grid meta-grid">
                <div class="card"><div class="meta">Scan Started</div><div>{scan_date}</div></div>
                <div class="card"><div class="meta">Mode</div><div>{html.escape(payload.get('scan_mode', ''))}</div></div>
                <div class="card"><div class="meta">Requested Profile</div><div>{html.escape(overview.get('requested_profile', ''))}</div></div>
                <div class="card"><div class="meta">Effective Profile</div><div>{html.escape(overview.get('effective_profile', ''))}</div></div>
                <div class="card"><div class="meta">Duration</div><div>{duration_seconds}s</div></div>
            </div>
            <div class="risk-banner">
                <div class="risk-chip"><div class="k">Overall Risk</div><div class="v">{overall_risk.upper()}</div></div>
                <div class="risk-chip"><div class="k">Data Confidence</div><div class="v">{confidence_level.upper()}</div></div>
                <div class="risk-chip"><div class="k">Critical + High</div><div class="v">{severity_counts.get('critical', 0) + severity_counts.get('high', 0)}</div></div>
                <div class="risk-chip"><div class="k">Coverage Completeness</div><div class="v">{coverage_pct}%</div></div>
            </div>
        </section>

        <section class="grid metrics">
            {_render_metric_cards(summary, assessment_summary, overview)}
        </section>

        <h2 id="executive-summary">Executive Summary</h2>
        <div class="card">
            <ul class="exec-list">
                {''.join(f'<li>{html.escape(item)}</li>' for item in executive_summary)}
            </ul>
        </div>

        <h2 id="coverage-limitations">Coverage and Limitations</h2>
        <div class="grid two">
            <div class="card">
                <h3>Coverage Summary</h3>
                <table>
                    <tr><th>Total Tool Runs</th><td>{total_tools}</td></tr>
                    <tr><th>Completed</th><td>{completed_tools}</td></tr>
                    <tr><th>Failed</th><td>{failed_tools}</td></tr>
                    <tr><th>Timed Out</th><td>{timeout_tools}</td></tr>
                    <tr><th>Missing/Skipped</th><td>{missing_tools}</td></tr>
                    <tr><th>Coverage Completeness</th><td>{coverage_pct}%</td></tr>
                </table>
            </div>
            <div class="card">
                <h3>Limitations Statement</h3>
                <p class="narrative">This report aggregates automated and analyst-driven evidence. Areas with failed, timed-out, or skipped tools may contain unseen risk. Treat low finding counts as tentative when coverage completeness is below 85%.</p>
            </div>
        </div>

        <h2 id="immediate-actions">Immediate Actions</h2>
        <div class="grid actions-grid">
            <div class="card">
                <h3>Next 24 Hours</h3>
                <table>
                    <thead><tr><th>Finding ID</th><th>Action</th><th>Owner</th></tr></thead>
                    <tbody>{''.join(actions_24h) or "<tr><td colspan='3'>No urgent actions identified.</td></tr>"}</tbody>
                </table>
            </div>
            <div class="card">
                <h3>Next 7 Days</h3>
                <table>
                    <thead><tr><th>Finding ID</th><th>Action</th><th>Owner</th></tr></thead>
                    <tbody>{''.join(actions_7d) or "<tr><td colspan='3'>No medium-priority actions identified.</td></tr>"}</tbody>
                </table>
            </div>
            <div class="card">
                <h3>Next 30 Days</h3>
                <table>
                    <thead><tr><th>Finding ID</th><th>Action</th><th>Owner</th></tr></thead>
                    <tbody>{''.join(actions_30d) or "<tr><td colspan='3'>No deferred actions identified.</td></tr>"}</tbody>
                </table>
            </div>
        </div>

        <h2 id="risk-snapshot">Risk Snapshot</h2>
        <div class="card">
            <h3>Top 5 Risks</h3>
            <table>
                <thead>
                    <tr><th>ID</th><th>Title</th><th>Severity</th><th>Exploitability</th><th>Affected Area</th><th>Status</th></tr>
                </thead>
                <tbody>
                    {''.join(top_risk_rows) or "<tr><td colspan='6'>No findings available.</td></tr>"}
                </tbody>
            </table>
        </div>

        <h2>Target Overview</h2>
        <div class="grid two">
            <div class="card">
                <h3>Fingerprint</h3>
                <table>
                    <tr><th>Title</th><td>{html.escape(str(fingerprint.get('title', '') or '-'))}</td></tr>
                    <tr><th>Status Code</th><td>{html.escape(str(fingerprint.get('status_code', '') or '-'))}</td></tr>
                    <tr><th>Web Server</th><td>{html.escape(str(fingerprint.get('webserver', '') or '-'))}</td></tr>
                    <tr><th>Technologies</th><td>{html.escape(', '.join(fingerprint.get('technologies', [])) or '-')}</td></tr>
                    <tr><th>WhatWeb Plugins</th><td>{html.escape(', '.join(fingerprint.get('whatweb_plugins', [])) or '-')}</td></tr>
                </table>
            </div>
            <div class="card">
                <h3>Discovery Summary</h3>
                <table>
                    <tr><th>Subdomains</th><td>{discovery.get('subdomain_count', 0)}</td></tr>
                    <tr><th>Parameters</th><td>{discovery.get('parameter_count', 0)}</td></tr>
                    <tr><th>gau URLs</th><td>{discovery.get('gau_count', 0)}</td></tr>
                    <tr><th>Katana URLs</th><td>{discovery.get('katana_count', 0)}</td></tr>
                    <tr><th>ffuf Hits</th><td>{discovery.get('ffuf_count', 0)}</td></tr>
                    <tr><th>Feroxbuster Hits</th><td>{discovery.get('feroxbuster_count', 0)}</td></tr>
                </table>
            </div>
        </div>

        {assessment_narrative_html}
        {manual_analytics_html}
        {category_coverage_html}

        <h2 id="appendix">Appendix: Tool Telemetry</h2>
        <p class="appendix-note">Detailed command telemetry and raw discovery artifacts are provided for analyst traceability.</p>
        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>Tool</th>
                        <th>Phase</th>
                        <th>Status</th>
                        <th>Seconds</th>
                        <th>Command</th>
                        <th>Outputs</th>
                        <th>Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(tools_rows) or "<tr><td colspan='7'>No tool telemetry captured.</td></tr>"}
                </tbody>
            </table>
        </div>

        <h2>Appendix: Discovery Artifacts</h2>
        <div class="grid three">
            {''.join(discovery_blocks) or "<div class='card'>No discovery artifacts captured.</div>"}
        </div>

        <h2>Guided Manual Test Cases</h2>
        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Case</th>
                        <th>Status</th>
                        <th>Verification</th>
                        <th>Owner</th>
                        <th>Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(case_rows) or "<tr><td colspan='6'>No guided cases loaded.</td></tr>"}
                </tbody>
            </table>
        </div>

        <h2>Operator Notes</h2>
        <div class="card">
            {notes_html or "<p>No operator notes recorded.</p>"}
        </div>

        <h2>Verification Runs</h2>
        <div class="card">
            {verification_html or "<p>No verification runs recorded.</p>"}
        </div>

        <h2 id="findings-index">Findings Index</h2>
        <div class="card">
            <div class="findings-toolbar">
                <input id="findingsSearch" type="search" placeholder="Search findings by title, tool, CVE&hellip;">
                <select id="findingsSevFilter">
                    <option value="">All severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                </select>
                <select id="findingsExploitabilityFilter">
                    <option value="">All exploitability</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                </select>
                <select id="findingsStatusFilter">
                    <option value="">All statuses</option>
                    <option value="new">New</option>
                    <option value="known">Known</option>
                    <option value="in_progress">In progress</option>
                    <option value="fixed">Fixed</option>
                    <option value="verified">Verified</option>
                    <option value="false_positive">False positive</option>
                </select>
                <span class="findings-count" id="findingsCount"></span>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Severity</th>
                        <th>Exploitability</th>
                        <th>Confidence</th>
                        <th>Title</th>
                        <th>Asset</th>
                        <th>Tool</th>
                        <th>CVE</th>
                        <th>Owner</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="findingsTableBody">
                    {''.join(finding_rows) or "<tr><td colspan='10'>No findings were parsed from the available outputs.</td></tr>"}
                </tbody>
            </table>
            <div class="findings-pages" id="findingsIndexPages"></div>
        </div>

        <h2>Detailed Findings</h2>
        <div class="card legend">
            Standards legend: OWASP = application risk categories, MITRE ATT&amp;CK = adversary behavior, CIS Controls and NIST CSF = control and governance alignment.
        </div>
        <div id="findingsDetailContainer">
            {''.join(finding_cards) or "<div class='card'>No findings available.</div>"}
        </div>
        <div class="findings-pages" id="findingsDetailPages"></div>

        <h2 id="compliance-crosswalk">Compliance Crosswalk</h2>
        <div class="card">
            <table>
                <thead>
                    <tr><th>Framework</th><th>Control / Technique ID</th><th>Related Finding IDs</th><th>Control Status</th></tr>
                </thead>
                <tbody>
                    {''.join(compliance_rows) or "<tr><td colspan='4'>No standards mapping data available.</td></tr>"}
                </tbody>
            </table>
        </div>
    </div>
    <!-- anchor for scroll-back -->
    <span id="findingsDetailSection"></span>
</body>
<script>
(function(){{
    // ── Findings Index: search + severity filter + pagination ──
    var PAGE_SIZE = 100;
    var allRows = Array.from(document.querySelectorAll('#findingsTableBody tr'));
    var currentPage = 0;
    var filteredRows = allRows;

    function buildPages(){{
        var pagesDiv = document.getElementById('findingsIndexPages');
        if (!pagesDiv) return;
        pagesDiv.innerHTML = '';
        var pages = Math.ceil(filteredRows.length / PAGE_SIZE);
        if (pages <= 1) {{ pagesDiv.style.display = 'none'; return; }}
        pagesDiv.style.display = 'flex';
        for (var i = 0; i < pages; i++) {{
            var btn = document.createElement('button');
            btn.textContent = i + 1;
            if (i === currentPage) btn.classList.add('active');
            btn.dataset.page = i;
            btn.addEventListener('click', function(e){{
                currentPage = parseInt(e.target.dataset.page);
                renderPage();
            }});
            pagesDiv.appendChild(btn);
        }}
    }}

    function renderPage(){{
        allRows.forEach(function(r){{ r.style.display='none'; }});
        var start = currentPage * PAGE_SIZE;
        filteredRows.slice(start, start + PAGE_SIZE).forEach(function(r){{ r.style.display=''; }});
        var countEl = document.getElementById('findingsCount');
        if (countEl) countEl.textContent = 'Showing ' + filteredRows.length + ' of ' + allRows.length + ' findings';
        var btns = document.querySelectorAll('#findingsIndexPages button');
        btns.forEach(function(b){{ b.classList.toggle('active', parseInt(b.dataset.page)===currentPage); }});
    }}

    function applyFilter(){{
        var query = (document.getElementById('findingsSearch') || {{}}).value || '';
        var sevFilter = (document.getElementById('findingsSevFilter') || {{}}).value || '';
        var exploitabilityFilter = (document.getElementById('findingsExploitabilityFilter') || {{}}).value || '';
        var statusFilter = (document.getElementById('findingsStatusFilter') || {{}}).value || '';
        query = query.toLowerCase();

        var sevCounts = {{critical: 0, high: 0, medium: 0, low: 0, info: 0}};
        allRows.forEach(function(r){{
            var sevVal = (r.dataset.severity || '').toLowerCase();
            if (Object.prototype.hasOwnProperty.call(sevCounts, sevVal)) sevCounts[sevVal] += 1;
        }});
        var sevSelect = document.getElementById('findingsSevFilter');
        if (sevSelect && !sevSelect.dataset.countsApplied) {{
            Array.from(sevSelect.options).forEach(function(opt){{
                var key = opt.value;
                if (!key || !Object.prototype.hasOwnProperty.call(sevCounts, key)) return;
                opt.textContent = opt.textContent.replace(/ \\(\\d+\\)$/, '') + ' (' + sevCounts[key] + ')';
            }});
            sevSelect.dataset.countsApplied = '1';
        }}

        filteredRows = allRows.filter(function(r){{
            var text = r.textContent.toLowerCase();
            var sev = (r.dataset.severity || '').toLowerCase();
            var exp = (r.dataset.exploitability || '').toLowerCase();
            var stat = (r.dataset.status || '').toLowerCase();
            var sevOk = !sevFilter || sev === sevFilter.toLowerCase();
            var expOk = !exploitabilityFilter || exp === exploitabilityFilter.toLowerCase();
            var statusOk = !statusFilter || stat === statusFilter.toLowerCase();
            return sevOk && expOk && statusOk && (!query || text.includes(query));
        }});
        currentPage = 0;
        buildPages();
        renderPage();
    }}

    var searchEl = document.getElementById('findingsSearch');
    var sevEl = document.getElementById('findingsSevFilter');
    var expEl = document.getElementById('findingsExploitabilityFilter');
    var statusEl = document.getElementById('findingsStatusFilter');
    if (searchEl) searchEl.addEventListener('input', applyFilter);
    if (sevEl) sevEl.addEventListener('change', applyFilter);
    if (expEl) expEl.addEventListener('change', applyFilter);
    if (statusEl) statusEl.addEventListener('change', applyFilter);
    buildPages();
    applyFilter();

    // ── Detailed Findings: pagination (PAGE_DETAIL cards at a time) ──
    var PAGE_DETAIL = 50;
    var allCards = Array.from(document.querySelectorAll('#findingsDetailContainer details.finding'));
    var detailPage = 0;

    function renderDetailPage(){{
        allCards.forEach(function(c){{ c.style.display='none'; }});
        var start = detailPage * PAGE_DETAIL;
        allCards.slice(start, start + PAGE_DETAIL).forEach(function(c){{ c.style.display=''; }});
        var btns = document.querySelectorAll('#findingsDetailPages button');
        btns.forEach(function(b){{ b.classList.toggle('active', parseInt(b.dataset.page)===detailPage); }});
    }}

    function buildDetailPages(){{
        var pagesDiv = document.getElementById('findingsDetailPages');
        if (!pagesDiv) return;
        var pages = Math.ceil(allCards.length / PAGE_DETAIL);
        if (pages <= 1) {{ pagesDiv.style.display='none'; return; }}
        pagesDiv.style.display = 'flex';
        pagesDiv.innerHTML = '<span style="color:var(--muted);font-size:13px;margin-right:4px">Page:</span>';
        for (var i = 0; i < pages; i++) {{
            var btn = document.createElement('button');
            btn.textContent = i + 1;
            btn.dataset.page = i;
            if (i === detailPage) btn.classList.add('active');
            btn.addEventListener('click', function(e){{
                detailPage = parseInt(e.target.dataset.page);
                renderDetailPage();
                document.getElementById('findingsDetailSection').scrollIntoView({{behavior:'smooth',block:'start'}});
            }});
            pagesDiv.appendChild(btn);
        }}
    }}

    buildDetailPages();
    renderDetailPage();
}})();
</script>
</html>"""


def generate_markdown_report(payload: dict) -> str:
    findings = payload.get("findings", [])
    summary = payload.get("summary", {})
    severity_counts = summary.get("severity_counts", {})
    overview = payload.get("overview", {})
    fingerprint = overview.get("fingerprint", {})
    discovery = overview.get("discovery", {})
    tool_runs = overview.get("tool_runs", [])
    include_manual_assessment = bool(payload.get("include_manual_assessment", True))
    report_profile = str(payload.get("report_profile", "technical")).strip().lower()
    if report_profile == "executive":
        include_manual_assessment = False
    assessment = payload.get("assessment", {}) if include_manual_assessment else {}
    workbook = assessment.get("workbook", {}) if isinstance(assessment, dict) else {}
    assessment_summary = _assessment_summary(assessment)

    lines = [
        "# OmniScan Comprehensive Assessment Report",
        "",
        f"- Target: {payload.get('target_url', '')}",
        f"- Scan started: {payload.get('scan_started_at', '')}",
        f"- Mode: {payload.get('scan_mode', '')}",
        f"- Requested profile: {overview.get('requested_profile', '')}",
        f"- Effective profile: {overview.get('effective_profile', '')}",
        f"- Duration: {payload.get('scan_duration_seconds', 0)}s",
        "",
        "## Executive Summary",
        "",
    ]
    lines.extend([f"- {item}" for item in summary.get("executive_summary", [])])
    lines.extend(
        [
            "",
            "## Severity Summary",
            "",
            f"- Total findings: {summary.get('finding_count', 0)}",
            f"- Critical: {severity_counts.get('critical', 0)}",
            f"- High: {severity_counts.get('high', 0)}",
            f"- Medium: {severity_counts.get('medium', 0)}",
            f"- Low: {severity_counts.get('low', 0)}",
            f"- Info: {severity_counts.get('info', 0)}",
            "",
            "## Fingerprint",
            "",
            f"- Title: {fingerprint.get('title', '') or '-'}",
            f"- Status code: {fingerprint.get('status_code', '') or '-'}",
            f"- Web server: {fingerprint.get('webserver', '') or '-'}",
            f"- Technologies: {', '.join(fingerprint.get('technologies', [])) or '-'}",
            f"- WhatWeb plugins: {', '.join(fingerprint.get('whatweb_plugins', [])) or '-'}",
            "",
            "## Scan Coverage",
            "",
            "| Tool | Phase | Status | Seconds | Note |",
            "|------|-------|--------|---------|------|",
        ]
    )

    for run in tool_runs:
        lines.append(
            f"| {run.get('label', run.get('name', 'tool'))} | {run.get('phase', '')} | "
            f"{run.get('status', '')} | {run.get('duration_seconds', 0)} | {run.get('note', '') or '-'} |"
        )

    lines.extend(
        [
            "",
            "## Discovery",
            "",
            f"- Subdomains: {discovery.get('subdomain_count', 0)}",
            f"- Parameters: {discovery.get('parameter_count', 0)}",
            f"- gau URLs: {discovery.get('gau_count', 0)}",
            f"- Katana URLs: {discovery.get('katana_count', 0)}",
            f"- ffuf hits: {discovery.get('ffuf_count', 0)}",
            f"- Feroxbuster hits: {discovery.get('feroxbuster_count', 0)}",
        ]
    )

    if include_manual_assessment:
        lines.extend(
            [
                "",
                "## Guided Manual Cases",
                "",
                "| Category | Case | Status | Verification | Owner |",
                "|----------|------|--------|--------------|-------|",
            ]
        )

        for case in workbook.get("cases", []):
            lines.append(
                f"| {case.get('category', '')} | {case.get('title', '')} | {case.get('status', '')} | "
                f"{case.get('verification_status', '')} | {case.get('owner', '') or '-'} |"
            )

        lines.extend(["", "## Operator Notes", ""])
        for note in workbook.get("operator_notes", []):
            lines.append(f"### {note.get('title', 'Note')} [{note.get('type', 'analysis')}]")
            lines.append(f"- Author: {note.get('author', '') or 'Unassigned analyst'}")
            lines.append(f"- Updated: {note.get('updated_at', note.get('created_at', ''))}")
            lines.append(f"- Body: {note.get('body', '')}")
            lines.append("")

        lines.extend(["## Verification Runs", ""])
        for run in workbook.get("verification_runs", []):
            lines.append(f"### {run.get('title', 'Verification run')} ({run.get('outcome', 'pending')})")
            lines.append(f"- Created: {run.get('created_at', '')}")
            lines.append(f"- Scope: {run.get('scope', '') or '-'}")
            lines.append(f"- Notes: {run.get('notes', '') or '-'}")
            lines.append("")

    lines.extend(["## Findings", ""])
    for finding in findings:
        lines.append(f"### [{finding.get('severity', 'info').upper()}] {finding.get('id', '')} {finding.get('title', '')}")
        lines.append(f"- Source: {finding.get('source_tool', '')}")
        if finding.get("cve"):
            lines.append(f"- CVE: {finding.get('cve', '')}")
        if finding.get("description"):
            lines.append(f"- Description: {finding.get('description', '')}")
        if finding.get("evidence"):
            lines.append(f"- Evidence: {finding.get('evidence', '')}")
        if finding.get("fix_steps"):
            lines.append("- Recommended fix:")
            for idx, step in enumerate(finding["fix_steps"], 1):
                lines.append(f"  {idx}. {step}")
        elif finding.get("fix"):
            lines.append(f"- Recommended fix: {finding.get('fix', '')}")
        if finding.get("references"):
            lines.append("- References:")
            for ref in finding["references"]:
                lines.append(f"  - {ref}")
        lines.append("")

    return "\n".join(lines)


def save_reports(
    findings: list[dict],
    target_url: str,
    scan_mode: str,
    start_time: datetime,
    scan_overview: dict | None = None,
    assessment: dict | None = None,
    output_dir: Path | None = None,
    output_formats: list[str] | None = None,
    report_profile: str = "technical",
    include_manual_assessment: bool = True,
) -> dict[str, Path]:
    """Generate and save HTML, Markdown, JSON, CSV, and SARIF reports."""
    base_dir = output_dir if output_dir is not None else REPORTS_DIR
    month_folder = start_time.strftime("%Y-%m")
    day_folder = start_time.strftime("%d")
    report_dir = base_dir / month_folder / day_folder
    report_dir.mkdir(parents=True, exist_ok=True)

    ts = start_time.strftime("%Y%m%d_%H%M%S")
    selected_formats = {str(item).strip().lower() for item in (output_formats or ["html", "markdown", "json", "sarif", "csv"]) if str(item).strip()}
    if not selected_formats:
        selected_formats = {"html", "markdown", "json"}

    payload = build_report_payload(
        findings,
        target_url,
        scan_mode,
        start_time,
        scan_overview,
        assessment,
        report_profile=report_profile,
        include_manual_assessment=include_manual_assessment,
    )

    paths: dict[str, Path] = {}

    if "html" in selected_formats:
        html_path = report_dir / f"report_{ts}.html"
        html_path.write_text(generate_html_report(payload), encoding="utf-8")
        paths["html"] = html_path

    if "markdown" in selected_formats or "md" in selected_formats:
        md_path = report_dir / f"report_{ts}.md"
        md_path.write_text(generate_markdown_report(payload), encoding="utf-8")
        paths["md"] = md_path

    if "json" in selected_formats:
        json_path = report_dir / f"report_{ts}.json"
        json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        paths["json"] = json_path

    if "sarif" in selected_formats:
        sarif_path = report_dir / f"report_{ts}.sarif"
        sarif_path.write_text(
            json.dumps(generate_sarif_report(payload), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        paths["sarif"] = sarif_path

    if "csv" in selected_formats:
        csv_path = report_dir / f"report_{ts}.csv"
        csv_path.write_text(generate_csv_report(payload), encoding="utf-8", newline="")
        paths["csv"] = csv_path

    try:
        _upsert_report_index(paths, payload)
    except Exception:
        pass

    return paths
