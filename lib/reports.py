"""HTML, Markdown, and JSON report generation."""

import html
import json
from datetime import datetime
from pathlib import Path

from lib.config import load_json, HTML_TEMPLATE_FILE, REPORTS_DIR
from lib import ui

# ── Tool display names ──────────────────────────────────────────────────────────

TOOL_DISPLAY = [
    ("nuclei",  "Nuclei"),
    ("wpscan",  "WPScan"),
    ("nikto",   "Nikto"),
    ("zap-cli", "OWASP ZAP"),
    ("sqlmap",  "SQLMap"),
    ("sslyze",  "SSLyze"),
    ("whatweb", "WhatWeb"),
    ("httpx",   "httpx"),
    ("cmsmap",  "CMSMap"),
]


# ── HTML Report ─────────────────────────────────────────────────────────────────

def generate_html_report(findings: list[dict], target_url: str,
                         scan_mode: str, start_time: datetime,
                         tools_used: list[str]) -> str:
    """Generate an HTML report from findings using the template."""
    template = ""
    if HTML_TEMPLATE_FILE.exists():
        template = HTML_TEMPLATE_FILE.read_text(encoding="utf-8")
    else:
        return "<html><body><h1>Template not found</h1></body></html>"

    # Compute summary counts
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    duration = datetime.now() - start_time
    dur_str = f"{int(duration.total_seconds()) // 60:02d}:{int(duration.total_seconds()) % 60:02d}"
    scan_date = start_time.strftime("%d/%m/%Y %I:%M:%S %p")

    # Build tool badges
    tool_badges = ""
    for tool_key, tool_label in TOOL_DISPLAY:
        cls = "active" if tool_key in tools_used else "inactive"
        tool_badges += f"<span class='tool-badge {cls}'>{tool_label}</span>\n"

    # Build table rows
    table_rows = ""
    for i, f in enumerate(findings, 1):
        sev = f["severity"]
        table_rows += (
            f"<tr data-severity='{sev}'>"
            f"<td>{i}</td>"
            f"<td><span class='severity-badge sev-{sev}'>{sev}</span></td>"
            f"<td>{html.escape(f['title'])}</td>"
            f"<td>{html.escape(f.get('cve', ''))}</td>"
            f"<td>{f['source_tool']}</td>"
            f"</tr>\n"
        )

    # Build detailed findings
    details = ""
    for f in findings:
        # Fix steps HTML
        fix_html = ""
        steps = f.get("fix_steps", [])
        if steps:
            fix_html = "<ul class='fix-steps'>"
            for s in steps:
                fix_html += f"<li>{html.escape(str(s))}</li>"
            fix_html += "</ul>"
        else:
            fix_html = f"<p>{html.escape(f.get('fix', ''))}</p>"

        # References HTML
        ref_html = ""
        refs = f.get("references", [])
        if refs:
            ref_html = "<ul class='ref-list'>"
            for r in refs:
                ref_html += f"<li><a href='{html.escape(r)}' target='_blank'>{html.escape(r)}</a></li>"
            ref_html += "</ul>"

        # Evidence section
        evidence_html = ""
        if f.get("evidence"):
            evidence_html = (
                f"<div class='finding-section'>"
                f"<div class='finding-section-title'>Evidence</div>"
                f"<div class='evidence-box'>{html.escape(f['evidence'])}</div>"
                f"</div>"
            )

        # References section
        ref_section = ""
        if ref_html:
            ref_section = (
                f"<div class='finding-section'>"
                f"<div class='finding-section-title'>References</div>"
                f"{ref_html}</div>"
            )

        details += f"""<div class='finding' data-severity='{f["severity"]}'>
    <div class='finding-header'>
        <div class='finding-title'>{f["id"]} &mdash; {html.escape(f["title"])}</div>
        <span class='severity-badge sev-{f["severity"]}'>{f["severity"]}</span>
    </div>
    <div class='finding-meta'>Source: {f["source_tool"]} {"| CVE: " + f["cve"] if f.get("cve") else ""}</div>
    <div class='finding-section'><div class='finding-section-title'>Description</div><p>{html.escape(f.get("description", ""))}</p></div>
    {evidence_html}
    <div class='finding-section'><div class='finding-section-title'>Recommended Fix</div>{fix_html}</div>
    {ref_section}
</div>"""

    # Build remediation checklist
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_findings = sorted(findings, key=lambda x: sev_order.get(x["severity"], 4))
    checklist = ""
    for f in sorted_findings:
        fix_text = f.get("fix") or f.get("description", "Review this finding.")
        checklist += (
            f"<li><div class='checkbox'></div>"
            f"<span class='priority-indicator sev-{f['severity']}'>{f['severity']}</span> "
            f"{html.escape(fix_text)} "
            f"<span style='color:var(--text-muted)'>({f['id']})</span></li>\n"
        )

    # Replace all placeholders
    report = template
    replacements = {
        "{{TARGET_URL}}": html.escape(target_url),
        "{{SCAN_DATE}}": scan_date,
        "{{SCAN_MODE}}": html.escape(scan_mode),
        "{{SCAN_DURATION}}": dur_str,
        "{{TOTAL_COUNT}}": str(len(findings)),
        "{{CRITICAL_COUNT}}": str(sev_counts["critical"]),
        "{{HIGH_COUNT}}": str(sev_counts["high"]),
        "{{MEDIUM_COUNT}}": str(sev_counts["medium"]),
        "{{LOW_COUNT}}": str(sev_counts["low"]),
        "{{INFO_COUNT}}": str(sev_counts["info"]),
        "{{TOOL_BADGES}}": tool_badges,
        "{{FINDINGS_TABLE_ROWS}}": table_rows,
        "{{DETAILED_FINDINGS}}": details,
        "{{REMEDIATION_CHECKLIST}}": checklist,
    }
    for placeholder, value in replacements.items():
        report = report.replace(placeholder, value)

    return report


# ── Markdown Report ─────────────────────────────────────────────────────────────

def generate_markdown_report(findings: list[dict], target_url: str,
                             scan_mode: str, start_time: datetime,
                             tools_used: list[str]) -> str:
    """Generate a Markdown report from findings."""
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1

    duration = datetime.now() - start_time
    dur_str = f"{int(duration.total_seconds()) // 60:02d}:{int(duration.total_seconds()) % 60:02d}"
    scan_date = start_time.strftime("%d/%m/%Y %I:%M:%S %p")
    tools_str = ", ".join(tools_used) if tools_used else "None"

    lines = [
        "# OmniScan Security Report",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Target | {target_url} |",
        f"| Date | {scan_date} |",
        f"| Mode | {scan_mode} |",
        f"| Duration | {dur_str} |",
        f"| Tools Used | {tools_str} |",
        f"| Total Findings | {len(findings)} |",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Critical | {sev_counts['critical']} |",
        f"| High | {sev_counts['high']} |",
        f"| Medium | {sev_counts['medium']} |",
        f"| Low | {sev_counts['low']} |",
        f"| Info | {sev_counts['info']} |",
        "",
        "## Findings",
        "",
    ]

    for f in findings:
        sev_tag = f"[{f['severity'].upper()}]"
        lines.append(f"### {sev_tag} {f['id']} - {f['title']}")
        lines.append("")
        lines.append(f"- **Source:** {f['source_tool']}")
        if f.get("cve"):
            lines.append(f"- **CVE:** {f['cve']}")
        lines.append(f"- **Description:** {f.get('description', '')}")
        if f.get("evidence"):
            lines.append(f"- **Evidence:** {f['evidence']}")
        lines.append("")

        fix_text = f.get("fix", "")
        steps = f.get("fix_steps", [])
        if steps:
            lines.append(f"**Recommended Fix:** {fix_text}")
            for i, step in enumerate(steps, 1):
                lines.append(f"{i}. {step}")
        elif fix_text:
            lines.append(f"**Recommended Fix:** {fix_text}")

        refs = f.get("references", [])
        if refs:
            lines.append("")
            lines.append("**References:**")
            for r in refs:
                lines.append(f"- {r}")

        lines.append("")

    # Remediation checklist
    lines.append("## Remediation Checklist")
    lines.append("")
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda x: sev_order.get(x["severity"], 4)):
        fix = f.get("fix") or f.get("description", "Review manually")
        lines.append(f"- [ ] **{f['severity'].upper()}** - {fix} ({f['id']})")

    lines.append("")
    lines.append(f"---\n*Generated by OmniScan on {scan_date}*")


    return "\n".join(lines)


# ── Save Reports ────────────────────────────────────────────────────────────────

def save_reports(findings: list[dict], target_url: str, scan_mode: str,
                 start_time: datetime, tools_used: list[str],
                 output_dir: Path | None = None) -> dict[str, Path]:
    """Generate and save HTML, MD, and JSON reports.

    Reports are saved into a folder structure: reports/YYYY-MM/DD/
    Returns paths dict.
    """
    base_dir = output_dir if output_dir is not None else REPORTS_DIR

    # Organize into month/day folders: reports/2026-03/11/
    month_folder = start_time.strftime("%Y-%m")   # e.g. 2026-03
    day_folder = start_time.strftime("%d")         # e.g. 11
    output_dir = base_dir / month_folder / day_folder
    output_dir.mkdir(parents=True, exist_ok=True)

    ts = start_time.strftime("%Y%m%d_%H%M%S")

    # HTML
    html_content = generate_html_report(findings, target_url, scan_mode, start_time, tools_used)
    html_path = output_dir / f"report_{ts}.html"
    html_path.write_text(html_content, encoding="utf-8-sig")  # UTF-8 with BOM

    # Markdown
    md_content = generate_markdown_report(findings, target_url, scan_mode, start_time, tools_used)
    md_path = output_dir / f"report_{ts}.md"
    md_path.write_text(md_content, encoding="utf-8")

    # JSON
    json_path = output_dir / f"report_{ts}.json"
    json_path.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    return {"html": html_path, "md": md_path, "json": json_path}
