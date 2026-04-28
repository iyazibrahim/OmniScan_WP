"""Comprehensive HTML, Markdown, and JSON report generation."""

import html
import json
from datetime import datetime
from pathlib import Path

from lib.config import REPORTS_DIR


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = finding.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _tool_status_badge(status: str) -> str:
    cls = {
        "completed": "good",
        "completed_no_output": "warn",
        "missing": "muted",
        "skipped": "muted",
        "failed": "bad",
        "timeout": "bad",
    }.get(status, "muted")
    return f"<span class='pill {cls}'>{html.escape(status.replace('_', ' '))}</span>"


def _json_ready_tool_runs(tool_runs: list[dict]) -> list[dict]:
    output = []
    for run in tool_runs:
        item = dict(run)
        item["command"] = " ".join(run.get("command", []))
        output.append(item)
    return output


def build_report_payload(
    findings: list[dict],
    target_url: str,
    scan_mode: str,
    start_time: datetime,
    scan_overview: dict | None,
) -> dict:
    duration = datetime.now() - start_time
    duration_seconds = int(duration.total_seconds())
    return {
        "report_version": 2,
        "target_url": target_url,
        "scan_mode": scan_mode,
        "scan_started_at": start_time.isoformat(),
        "scan_duration_seconds": duration_seconds,
        "summary": {
            "finding_count": len(findings),
            "severity_counts": _severity_counts(findings),
        },
        "overview": scan_overview or {},
        "findings": findings,
    }


def generate_html_report(payload: dict) -> str:
    findings = payload.get("findings", [])
    summary = payload.get("summary", {})
    severity_counts = summary.get("severity_counts", {})
    overview = payload.get("overview", {})
    fingerprint = overview.get("fingerprint", {})
    discovery = overview.get("discovery", {})
    tool_runs = overview.get("tool_runs", [])

    tools_rows = []
    for run in tool_runs:
        outputs = run.get("output_files", [])
        output_html = "<br>".join(html.escape(Path(path).name) for path in outputs[:4]) or "None"
        tools_rows.append(
            "<tr>"
            f"<td>{html.escape(run.get('label', run.get('name', 'tool')))}</td>"
            f"<td>{html.escape(run.get('phase', ''))}</td>"
            f"<td>{_tool_status_badge(run.get('status', 'unknown'))}</td>"
            f"<td>{run.get('duration_seconds', 0)}</td>"
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
        rendered = "".join(f"<li>{html.escape(str(item))}</li>" for item in items[:20])
        discovery_blocks.append(f"<div class='card'><h3>{html.escape(label)}</h3><ul>{rendered}</ul></div>")

    finding_rows = []
    finding_cards = []
    for idx, finding in enumerate(findings, 1):
        severity = finding.get("severity", "info")
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
            "<tr>"
            f"<td>{idx}</td>"
            f"<td><span class='sev {severity}'>{severity}</span></td>"
            f"<td>{title}</td>"
            f"<td>{html.escape(finding.get('source_tool', ''))}</td>"
            f"<td>{cve or '-'}</td>"
            "</tr>"
        )
        finding_cards.append(
            f"""
            <div class="finding {severity}">
                <div class="finding-head">
                    <h3>{html.escape(finding.get('id', ''))} {title}</h3>
                    <span class="sev {severity}">{severity}</span>
                </div>
                <p class="meta">Source: {html.escape(finding.get('source_tool', ''))}{' | CVE: ' + cve if cve else ''}</p>
                <p>{description}</p>
                {'<pre>' + evidence + '</pre>' if evidence else ''}
                <div class="fix-block">
                    <h4>Recommended Fix</h4>
                    {fix_html}
                </div>
                {'<div class="refs"><h4>References</h4><ul>' + ref_html + '</ul></div>' if ref_html else ''}
            </div>
            """
        )

    scan_date = datetime.fromisoformat(payload["scan_started_at"]).strftime("%Y-%m-%d %H:%M:%S")
    duration_seconds = payload.get("scan_duration_seconds", 0)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OmniScan Report - {html.escape(payload.get('target_url', 'target'))}</title>
    <style>
        :root {{
            --bg: #0f172a;
            --panel: #111827;
            --panel-2: #172033;
            --text: #e5edf8;
            --muted: #9fb0c9;
            --border: #23314d;
            --accent: #38bdf8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #60a5fa;
            --info: #94a3b8;
            --good: #10b981;
        }}
        * {{ box-sizing: border-box; }}
        body {{ margin: 0; font-family: Segoe UI, Arial, sans-serif; background: linear-gradient(180deg, #08101f, #111827 30%); color: var(--text); }}
        .wrap {{ max-width: 1240px; margin: 0 auto; padding: 24px; }}
        .hero {{ background: linear-gradient(135deg, #0f172a, #172554); border: 1px solid var(--border); border-radius: 18px; padding: 28px; box-shadow: 0 20px 60px rgba(2, 6, 23, 0.35); }}
        .hero h1 {{ margin: 0 0 8px; font-size: 30px; }}
        .hero p {{ margin: 0; color: var(--muted); }}
        .grid {{ display: grid; gap: 16px; }}
        .meta-grid {{ grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-top: 18px; }}
        .summary-grid {{ grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); margin: 24px 0; }}
        .card {{ background: rgba(17, 24, 39, 0.92); border: 1px solid var(--border); border-radius: 16px; padding: 18px; }}
        .metric {{ font-size: 34px; font-weight: 700; margin-top: 8px; }}
        h2 {{ margin: 28px 0 12px; font-size: 22px; }}
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
        .pill.good {{ background: rgba(16,185,129,0.15); color: #6ee7b7; }}
        .pill.bad {{ background: rgba(239,68,68,0.15); color: #fca5a5; }}
        .pill.warn {{ background: rgba(245,158,11,0.15); color: #fcd34d; }}
        .pill.muted {{ background: rgba(148,163,184,0.15); color: #cbd5e1; }}
        .two {{ grid-template-columns: 1.2fr 1fr; }}
        .three {{ grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); }}
        .finding {{ border-left: 4px solid var(--border); margin-bottom: 16px; }}
        .finding.critical {{ border-left-color: var(--critical); }}
        .finding.high {{ border-left-color: var(--high); }}
        .finding.medium {{ border-left-color: var(--medium); }}
        .finding.low {{ border-left-color: var(--low); }}
        .finding.info {{ border-left-color: var(--info); }}
        .finding-head {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; }}
        .meta {{ color: var(--muted); }}
        pre {{ background: #0b1220; border: 1px solid var(--border); color: #dbeafe; padding: 12px; border-radius: 12px; white-space: pre-wrap; overflow-x: auto; }}
        ul, ol {{ padding-left: 20px; }}
        a {{ color: #7dd3fc; }}
        .muted {{ color: var(--muted); }}
        @media (max-width: 900px) {{
            .two {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="wrap">
        <section class="hero">
            <h1>OmniScan Comprehensive Security Report</h1>
            <p>{html.escape(payload.get('target_url', ''))}</p>
            <div class="grid meta-grid">
                <div class="card"><div class="muted">Scan Started</div><div class="metric" style="font-size:18px">{scan_date}</div></div>
                <div class="card"><div class="muted">Mode</div><div class="metric" style="font-size:18px">{html.escape(payload.get('scan_mode', ''))}</div></div>
                <div class="card"><div class="muted">Requested Profile</div><div class="metric" style="font-size:18px">{html.escape(overview.get('requested_profile', ''))}</div></div>
                <div class="card"><div class="muted">Effective Profile</div><div class="metric" style="font-size:18px">{html.escape(overview.get('effective_profile', ''))}</div></div>
                <div class="card"><div class="muted">Duration</div><div class="metric" style="font-size:18px">{duration_seconds}s</div></div>
            </div>
        </section>

        <section class="grid summary-grid">
            <div class="card"><div class="muted">Critical</div><div class="metric" style="color:var(--critical)">{severity_counts.get('critical', 0)}</div></div>
            <div class="card"><div class="muted">High</div><div class="metric" style="color:var(--high)">{severity_counts.get('high', 0)}</div></div>
            <div class="card"><div class="muted">Medium</div><div class="metric" style="color:var(--medium)">{severity_counts.get('medium', 0)}</div></div>
            <div class="card"><div class="muted">Low</div><div class="metric" style="color:var(--low)">{severity_counts.get('low', 0)}</div></div>
            <div class="card"><div class="muted">Info</div><div class="metric" style="color:var(--info)">{severity_counts.get('info', 0)}</div></div>
            <div class="card"><div class="muted">Total Findings</div><div class="metric">{summary.get('finding_count', 0)}</div></div>
        </section>

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

        <h2>Scan Coverage</h2>
        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>Tool</th>
                        <th>Phase</th>
                        <th>Status</th>
                        <th>Seconds</th>
                        <th>Outputs</th>
                        <th>Notes</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(tools_rows) or "<tr><td colspan='6'>No tool telemetry captured.</td></tr>"}
                </tbody>
            </table>
        </div>

        <h2>Discovery Artifacts</h2>
        <div class="grid three">
            {''.join(discovery_blocks) or "<div class='card'>No discovery artifacts captured.</div>"}
        </div>

        <h2>Findings Index</h2>
        <div class="card">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Severity</th>
                        <th>Title</th>
                        <th>Tool</th>
                        <th>CVE</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(finding_rows) or "<tr><td colspan='5'>No findings were parsed from the available outputs.</td></tr>"}
                </tbody>
            </table>
        </div>

        <h2>Detailed Findings</h2>
        <div>
            {''.join(finding_cards) or "<div class='card'>No findings available.</div>"}
        </div>
    </div>
</body>
</html>"""


def generate_markdown_report(payload: dict) -> str:
    findings = payload.get("findings", [])
    summary = payload.get("summary", {})
    severity_counts = summary.get("severity_counts", {})
    overview = payload.get("overview", {})
    fingerprint = overview.get("fingerprint", {})
    discovery = overview.get("discovery", {})
    tool_runs = overview.get("tool_runs", [])

    lines = [
        "# OmniScan Comprehensive Security Report",
        "",
        f"- Target: {payload.get('target_url', '')}",
        f"- Scan started: {payload.get('scan_started_at', '')}",
        f"- Mode: {payload.get('scan_mode', '')}",
        f"- Requested profile: {overview.get('requested_profile', '')}",
        f"- Effective profile: {overview.get('effective_profile', '')}",
        f"- Duration: {payload.get('scan_duration_seconds', 0)}s",
        "",
        "## Summary",
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
            "",
            "## Findings",
            "",
        ]
    )

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
    output_dir: Path | None = None,
) -> dict[str, Path]:
    """Generate and save comprehensive HTML, markdown, and JSON reports."""
    base_dir = output_dir if output_dir is not None else REPORTS_DIR
    month_folder = start_time.strftime("%Y-%m")
    day_folder = start_time.strftime("%d")
    report_dir = base_dir / month_folder / day_folder
    report_dir.mkdir(parents=True, exist_ok=True)

    ts = start_time.strftime("%Y%m%d_%H%M%S")
    payload = build_report_payload(findings, target_url, scan_mode, start_time, scan_overview)

    html_path = report_dir / f"report_{ts}.html"
    html_path.write_text(generate_html_report(payload), encoding="utf-8")

    md_path = report_dir / f"report_{ts}.md"
    md_path.write_text(generate_markdown_report(payload), encoding="utf-8")

    json_path = report_dir / f"report_{ts}.json"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    return {"html": html_path, "md": md_path, "json": json_path}
