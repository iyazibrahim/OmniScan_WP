"""Comprehensive HTML, Markdown, and JSON report generation."""

from __future__ import annotations

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
) -> dict:
    duration = datetime.now() - start_time
    duration_seconds = int(duration.total_seconds())
    payload = {
        "report_version": 3,
        "target_url": target_url,
        "scan_mode": scan_mode,
        "scan_started_at": start_time.isoformat(),
        "scan_duration_seconds": duration_seconds,
        "summary": {
            "finding_count": len(findings),
            "severity_counts": _severity_counts(findings),
        },
        "overview": scan_overview or {},
        "assessment": assessment or {},
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
        ("Verified Cases", verified, "good"),
        ("Analyst Notes", note_count, "info"),
        ("Total Findings", summary.get("finding_count", 0), "total"),
    ]
    return "".join(
        f"<div class='metric-card {css}'><div class='label'>{html.escape(label)}</div><div class='value'>{value}</div></div>"
        for label, value, css in metrics
    )


def generate_html_report(payload: dict) -> str:
    findings = payload.get("findings", [])
    summary = payload.get("summary", {})
    overview = payload.get("overview", {})
    fingerprint = overview.get("fingerprint", {})
    discovery = overview.get("discovery", {})
    tool_runs = overview.get("tool_runs", [])
    assessment = payload.get("assessment", {})
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
            <details class="finding {severity}">
                <summary>
                    <span class="sev {severity}">{severity}</span>
                    <span class="sum-title">{html.escape(finding.get('id', ''))} {title}</span>
                    <span class="url-cell" style="color:var(--muted);font-size:0.8em">{html.escape(finding.get('source_tool', ''))}{' &nbsp;&middot;&nbsp; ' + cve if cve else ''}</span>
                    <svg class="sum-chevron" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"></polyline></svg>
                </summary>
                <div class="finding-body">
                    <p class="meta">Source: {html.escape(finding.get('source_tool', ''))}{' | CVE: ' + cve if cve else ''}</p>
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
    for category, data in assessment_summary.get("category_coverage", {}).items():
        category_rows.append(
            f"<tr><td>{html.escape(category)}</td><td>{data.get('total', 0)}</td><td>{data.get('completed', 0)}</td><td>{data.get('confirmed', 0)}</td></tr>"
        )

    workbook_cases = workbook.get("cases", [])
    case_rows = []
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

    notes_html = ""
    for note in workbook.get("operator_notes", []):
        notes_html += (
            "<div class='note-card'>"
            f"<div class='note-head'><strong>{html.escape(note.get('title', 'Untitled note'))}</strong><span>{html.escape(note.get('type', 'analysis'))}</span></div>"
            f"<div class='note-meta'>{html.escape(note.get('author', '') or 'Unassigned analyst')} | {html.escape(note.get('updated_at', note.get('created_at', '')))}</div>"
            f"<p>{html.escape(note.get('body', '') or '')}</p>"
            "</div>"
        )

    verification_html = ""
    for run in workbook.get("verification_runs", []):
        verification_html += (
            "<div class='note-card'>"
            f"<div class='note-head'><strong>{html.escape(run.get('title', 'Verification run'))}</strong><span>{html.escape(run.get('outcome', 'pending'))}</span></div>"
            f"<div class='note-meta'>{html.escape(run.get('created_at', ''))}</div>"
            f"<p><strong>Scope:</strong> {html.escape(run.get('scope', '') or '-')}</p>"
            f"<p>{html.escape(run.get('notes', '') or '')}</p>"
            "</div>"
        )

    scan_date = datetime.fromisoformat(payload["scan_started_at"]).strftime("%Y-%m-%d %H:%M:%S")
    duration_seconds = payload.get("scan_duration_seconds", 0)
    auth_context_notes = html.escape(workbook.get("auth_context_notes", "") or "Not documented.")
    attack_hypotheses = html.escape(workbook.get("attack_path_hypotheses", "") or "No attack path hypotheses recorded yet.")
    verification_strategy = html.escape(workbook.get("verification_strategy", "") or "No explicit verification strategy recorded yet.")
    assessment_summary_text = html.escape(assessment_summary.get("summary", "") or "No analyst summary has been recorded for this target.")

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
        .three {{ grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }}
        .card, .metric-card {{ background: rgba(16,24,38,0.94); border: 1px solid var(--border); border-radius: 18px; padding: 18px; }}
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
        @media (max-width: 980px) {{ .two {{ grid-template-columns: 1fr; }} }}
        /* ── Text overflow fixes ─────────────────────────────────────────── */
        td, th {{ word-break: break-word; overflow-wrap: anywhere; max-width: 480px; }}
        td code {{ word-break: break-all; white-space: pre-wrap; }}
        pre {{ white-space: pre-wrap; overflow-wrap: anywhere; word-break: break-word; overflow-x: auto; max-width: 100%; }}
        .url-cell {{ word-break: break-all; font-size: 0.82em; }}
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
    </style>
</head>
<body>
    <div class="wrap">
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
        </section>

        <section class="grid metrics">
            {_render_metric_cards(summary, assessment_summary, overview)}
        </section>

        <h2>Executive Summary</h2>
        <div class="card">
            <ul class="exec-list">
                {''.join(f'<li>{html.escape(item)}</li>' for item in executive_summary)}
            </ul>
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

        <h2>Assessment Narrative</h2>
        <div class="grid two">
            <div class="card">
                <h3>Analyst Summary</h3>
                <div class="narrative">{assessment_summary_text}</div>
            </div>
            <div class="card">
                <h3>Authentication Context</h3>
                <div class="narrative">{auth_context_notes}</div>
            </div>
            <div class="card">
                <h3>Attack Path Hypotheses</h3>
                <div class="narrative">{attack_hypotheses}</div>
            </div>
            <div class="card">
                <h3>Verification Strategy</h3>
                <div class="narrative">{verification_strategy}</div>
            </div>
        </div>

        <h2>Manual Assessment Analytics</h2>
        <div class="grid two">
            <div class="card">
                <h3>Case Status</h3>
                <table>
                    <tr><th>Status</th><th>Count</th></tr>
                    {''.join(f"<tr><td>{html.escape(k.replace('_', ' '))}</td><td>{v}</td></tr>" for k, v in assessment_summary.get('case_status', {}).items()) or "<tr><td colspan='2'>No manual assessment activity yet.</td></tr>"}
                </table>
            </div>
            <div class="card">
                <h3>Verification Status</h3>
                <table>
                    <tr><th>Status</th><th>Count</th></tr>
                    {''.join(f"<tr><td>{html.escape(k.replace('_', ' '))}</td><td>{v}</td></tr>" for k, v in assessment_summary.get('verification_status', {}).items()) or "<tr><td colspan='2'>No verification records yet.</td></tr>"}
                </table>
            </div>
        </div>

        <div class="card">
            <h3>Category Coverage</h3>
            <table>
                <thead><tr><th>Category</th><th>Total Cases</th><th>Worked</th><th>Verified</th></tr></thead>
                <tbody>
                    {''.join(category_rows) or "<tr><td colspan='4'>No category coverage data yet.</td></tr>"}
                </tbody>
            </table>
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

        <h2>Discovery Artifacts</h2>
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

        <h2>Findings Index</h2>
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
                <span class="findings-count" id="findingsCount"></span>
            </div>
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
                <tbody id="findingsTableBody">
                    {''.join(finding_rows) or "<tr><td colspan='5'>No findings were parsed from the available outputs.</td></tr>"}
                </tbody>
            </table>
            <div class="findings-pages" id="findingsIndexPages"></div>
        </div>

        <h2>Detailed Findings</h2>
        <div id="findingsDetailContainer">
            {''.join(finding_cards) or "<div class='card'>No findings available.</div>"}
        </div>
        <div class="findings-pages" id="findingsDetailPages"></div>
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
        query = query.toLowerCase();
        filteredRows = allRows.filter(function(r){{
            var text = r.textContent.toLowerCase();
            var sev = (r.querySelector('.sev') || {{}}).textContent || '';
            var sevOk = !sevFilter || sev.toLowerCase() === sevFilter.toLowerCase();
            return sevOk && (!query || text.includes(query));
        }});
        currentPage = 0;
        buildPages();
        renderPage();
    }}

    var searchEl = document.getElementById('findingsSearch');
    var sevEl = document.getElementById('findingsSevFilter');
    if (searchEl) searchEl.addEventListener('input', applyFilter);
    if (sevEl) sevEl.addEventListener('change', applyFilter);
    buildPages();
    renderPage();

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
    assessment = payload.get("assessment", {})
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
            "## Manual Assessment Narrative",
            "",
            f"- Analyst summary: {assessment_summary.get('summary', '') or 'Not recorded'}",
            f"- Authentication context: {workbook.get('auth_context_notes', '') or 'Not recorded'}",
            f"- Attack path hypotheses: {workbook.get('attack_path_hypotheses', '') or 'Not recorded'}",
            f"- Verification strategy: {workbook.get('verification_strategy', '') or 'Not recorded'}",
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
) -> dict[str, Path]:
    """Generate and save comprehensive HTML, markdown, and JSON reports."""
    base_dir = output_dir if output_dir is not None else REPORTS_DIR
    month_folder = start_time.strftime("%Y-%m")
    day_folder = start_time.strftime("%d")
    report_dir = base_dir / month_folder / day_folder
    report_dir.mkdir(parents=True, exist_ok=True)

    ts = start_time.strftime("%Y%m%d_%H%M%S")
    payload = build_report_payload(findings, target_url, scan_mode, start_time, scan_overview, assessment)

    html_path = report_dir / f"report_{ts}.html"
    html_path.write_text(generate_html_report(payload), encoding="utf-8")

    md_path = report_dir / f"report_{ts}.md"
    md_path.write_text(generate_markdown_report(payload), encoding="utf-8")

    json_path = report_dir / f"report_{ts}.json"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    return {"html": html_path, "md": md_path, "json": json_path}
