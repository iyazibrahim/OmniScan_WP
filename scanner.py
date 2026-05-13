#!/usr/bin/env python3
"""OmniScan - Multi-Tool Automated Security Pipeline.

Usage:
    python scanner.py                   # Interactive menu
    python scanner.py --check-tools     # Show installed tools
    python scanner.py --demo            # Generate demo report
    python scanner.py --target URL      # Scan a specific URL
    python scanner.py --target URL --mode active
    python scanner.py --install          # Install missing tools

CI/Cron Usage:
    python scanner.py --target URL --ci                    # Headless scan
    python scanner.py --target URL --ci --email             # Headless + email
    python scanner.py --target URL --ci --output-dir /tmp   # Custom output dir
"""

import argparse
import json
import os
import sys
import webbrowser
from datetime import datetime
from datetime import UTC
from pathlib import Path
from typing import Callable

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib import ui, config
from lib.tools import show_tool_status, run_all_tools, get_installed_tools
from lib.parsers import parse_all_results, collect_scan_overview
from lib.enrichment import enrich_findings
from lib.reports import save_reports
from lib.installer import install_missing_tools, install_tool
from lib.notifier import send_scan_email, configure_email
from lib.assessments import get_workbook, summarize_workbook
from lib.ai_runner import apply_verdicts_to_findings


def _is_ci() -> bool:
    """Check if running in CI/headless mode."""
    return ui.is_ci()


def _apply_ai_verdicts(findings: list[dict], target_url: str, scan_config: dict) -> list[dict]:
    if not bool(scan_config.get("ai_operator_enabled", False)):
        return findings

    results_file = config.CONFIG_DIR / "ai-results.json"
    if not results_file.exists():
        return findings

    try:
        store = json.loads(results_file.read_text(encoding="utf-8"))
    except Exception:
        return findings
    if not isinstance(store, dict):
        return findings

    target_results = store.get(target_url)
    if not isinstance(target_results, dict):
        return findings
    results = target_results.get("results")
    if not isinstance(results, list) or not results:
        return findings

    return apply_verdicts_to_findings(findings, results)


# ── Demo Mode ───────────────────────────────────────────────────────────────────

def run_demo(ci_mode: bool = False, send_email: bool = False):
    """Generate a demo report with sample findings."""
    ui.section("Demo Mode - Generating Sample Report")

    start_time = datetime.now(UTC)

    # Sample findings
    demo_findings = [
        {
            "title": "WordPress 5.8.1 - Outdated Core",
            "severity": "critical",
            "source_tool": "WPScan",
            "description": "WordPress core is outdated with known SQL injection vulnerability.",
            "cve": "CVE-2022-21661",
            "evidence": "Detected version: 5.8.1, Latest: 6.4.2",
            "fix": "",
            "fix_steps": [],
            "references": ["https://wordpress.org/news/category/security/"],
        },
        {
            "title": "Plugin Contact Form 7 v5.3.2 - Arbitrary File Upload",
            "severity": "high",
            "source_tool": "WPScan",
            "description": "Contact Form 7 allows unrestricted file upload.",
            "cve": "CVE-2020-35489",
            "evidence": "Version 5.3.2 detected",
            "fix": "",
            "fix_steps": [],
            "references": [],
        },
        {
            "title": "XML-RPC Endpoint Accessible",
            "severity": "medium",
            "source_tool": "Nuclei",
            "description": "xmlrpc.php is accessible and can be used for brute-force amplification.",
            "cve": "",
            "evidence": "https://example.com/xmlrpc.php returns 200",
            "fix": "",
            "fix_steps": [],
            "references": [],
        },
        {
            "title": "Missing X-Frame-Options Header",
            "severity": "medium",
            "source_tool": "Nikto",
            "description": "X-Frame-Options header not set, site vulnerable to clickjacking.",
            "cve": "",
            "evidence": "Header missing from HTTP response",
            "fix": "",
            "fix_steps": [],
            "references": [],
        },
        {
            "title": "TLS 1.0 Supported",
            "severity": "high",
            "source_tool": "SSLyze",
            "description": "Server accepts TLS 1.0 connections which is deprecated.",
            "cve": "",
            "evidence": "3 TLS 1.0 cipher suites accepted",
            "fix": "",
            "fix_steps": [],
            "references": [],
        },
        {
            "title": "WordPress User Enumeration via REST API",
            "severity": "low",
            "source_tool": "Nuclei",
            "description": "Usernames enumerable via /wp-json/wp/v2/users endpoint.",
            "cve": "",
            "evidence": "/wp-json/wp/v2/users returns user list",
            "fix": "",
            "fix_steps": [],
            "references": [],
        },
        {
            "title": "Directory Listing Enabled on /wp-content/uploads/",
            "severity": "medium",
            "source_tool": "Nuclei",
            "description": "Directory listing reveals uploaded files.",
            "cve": "",
            "evidence": "https://example.com/wp-content/uploads/ shows index",
            "fix": "",
            "fix_steps": [],
            "references": [],
        },
        {
            "title": "WP Debug Mode Enabled",
            "severity": "medium",
            "source_tool": "Nuclei",
            "description": "WP_DEBUG is enabled exposing error details.",
            "cve": "",
            "evidence": "PHP errors visible in page source",
            "fix": "",
            "fix_steps": [],
            "references": [],
        },
    ]

    # Enrich with remediation data
    enriched = enrich_findings(demo_findings)

    # Generate reports
    demo_overview = {
        "requested_profile": "auto",
        "effective_profile": "wordpress",
        "fingerprint": {
            "title": "Demo Company",
            "status_code": 200,
            "technologies": ["WordPress", "PHP", "Nginx"],
            "webserver": "nginx",
            "whatweb_plugins": ["WordPress", "PHP", "Nginx"],
        },
        "discovery": {
            "subdomains": ["blog.demo-company.com", "cdn.demo-company.com"],
            "subdomain_count": 2,
            "parameters": ["id", "redirect", "search"],
            "parameter_count": 3,
            "sample_urls": {
                "gau": ["https://demo-company.com/wp-login.php", "https://demo-company.com/wp-json/wp/v2/users"],
                "katana": ["https://demo-company.com/contact", "https://demo-company.com/search?q=test"],
                "ffuf": ["https://demo-company.com/.git/", "https://demo-company.com/backup.zip"],
                "feroxbuster": ["https://demo-company.com/admin/"],
            },
            "gau_count": 2,
            "katana_count": 2,
            "ffuf_count": 2,
            "feroxbuster_count": 1,
        },
        "tool_runs": [
            {"name": "httpx", "label": "httpx", "phase": "passive", "status": "completed", "duration_seconds": 4.2, "output_files": ["httpx.json"], "primary_output": "httpx.json", "command": ["httpx"], "note": "", "stdout_log": "", "stderr_log": "", "returncode": 0},
            {"name": "whatweb", "label": "WhatWeb", "phase": "passive", "status": "completed", "duration_seconds": 2.9, "output_files": ["whatweb.json"], "primary_output": "whatweb.json", "command": ["whatweb"], "note": "", "stdout_log": "", "stderr_log": "", "returncode": 0},
            {"name": "nuclei", "label": "Nuclei", "phase": "passive", "status": "completed", "duration_seconds": 15.8, "output_files": ["nuclei.jsonl"], "primary_output": "nuclei.jsonl", "command": ["nuclei"], "note": "", "stdout_log": "", "stderr_log": "", "returncode": 0},
            {"name": "wpscan", "label": "WPScan", "phase": "passive", "status": "completed", "duration_seconds": 18.4, "output_files": ["wpscan.json"], "primary_output": "wpscan.json", "command": ["wpscan"], "note": "", "stdout_log": "", "stderr_log": "", "returncode": 0},
            {"name": "nikto", "label": "Nikto", "phase": "passive", "status": "completed", "duration_seconds": 12.1, "output_files": ["nikto.json"], "primary_output": "nikto.json", "command": ["nikto"], "note": "", "stdout_log": "", "stderr_log": "", "returncode": 0},
            {"name": "dalfox", "label": "Dalfox", "phase": "active", "status": "completed", "duration_seconds": 9.3, "output_files": ["dalfox.json"], "primary_output": "dalfox.json", "command": ["dalfox"], "note": "", "stdout_log": "", "stderr_log": "", "returncode": 0},
        ],
    }
    demo_assessment = {
        "workbook": {
            "target_url": "https://demo-company.com",
            "updated_at": start_time.isoformat(),
            "summary": "Manual analyst review suggests the application has both known WordPress hygiene issues and at least one realistic abuse path through exposed administrative surface and weak update hygiene.",
            "auth_context_notes": "Anonymous review only. No authenticated admin session was provided for deeper access-control testing.",
            "attack_path_hypotheses": "An attacker could chain exposed plugin versioning, directory listing, and weak update hygiene into plugin exploitation or account compromise attempts.",
            "verification_strategy": "Prioritize retesting of update hygiene, harden exposed paths, then repeat CMS and content-discovery testing with authenticated coverage.",
            "operator_notes": [
                {"id": "note-demo-1", "created_at": start_time.isoformat(), "updated_at": start_time.isoformat(), "title": "Scope note", "body": "Demo assessment only covers public unauthenticated surface.", "type": "context", "author": "OmniScan Demo"}
            ],
            "verification_runs": [
                {"id": "verify-demo-1", "created_at": start_time.isoformat(), "title": "Demo validation pass", "scope": "Public web surface", "outcome": "confirmed", "notes": "Sample findings mapped to evidence successfully.", "related_case_ids": ["business-logic-flaws"], "related_finding_ids": ["F-001"]}
            ],
            "cases": [
                {"id": "business-logic-flaws", "category": "Business Logic", "title": "Business Logic Abuse Review", "priority": "high", "objective": "", "automation_support": "", "guided_steps": [], "evidence_expectations": [], "status": "needs_evidence", "verification_status": "not_verified", "owner": "", "notes": "No authenticated transactional flow available in demo scope.", "evidence": "", "attack_path_link": "", "related_finding_ids": [], "last_tested_at": start_time.isoformat(), "retest_notes": "", "remediation_advice": ""},
                {"id": "complex-auth-bypass", "category": "Authentication", "title": "Complex Authentication Bypass", "priority": "critical", "objective": "", "automation_support": "", "guided_steps": [], "evidence_expectations": [], "status": "not_started", "verification_status": "not_verified", "owner": "", "notes": "", "evidence": "", "attack_path_link": "", "related_finding_ids": [], "last_tested_at": "", "retest_notes": "", "remediation_advice": ""},
                {"id": "real-access-control-testing", "category": "Access Control", "title": "Real Access Control Testing", "priority": "critical", "objective": "", "automation_support": "", "guided_steps": [], "evidence_expectations": [], "status": "not_started", "verification_status": "not_verified", "owner": "", "notes": "", "evidence": "", "attack_path_link": "", "related_finding_ids": [], "last_tested_at": "", "retest_notes": "", "remediation_advice": ""},
                {"id": "multi-step-abuse-paths", "category": "Abuse Paths", "title": "Multi-Step Abuse Path Mapping", "priority": "high", "objective": "", "automation_support": "", "guided_steps": [], "evidence_expectations": [], "status": "in_progress", "verification_status": "reproduced", "owner": "", "notes": "Chaining concept documented from public surface evidence.", "evidence": "", "attack_path_link": "", "related_finding_ids": [], "last_tested_at": start_time.isoformat(), "retest_notes": "", "remediation_advice": ""},
                {"id": "tenant-isolation-failures", "category": "Multi-Tenancy", "title": "Tenant Isolation Review", "priority": "critical", "objective": "", "automation_support": "", "guided_steps": [], "evidence_expectations": [], "status": "not_started", "verification_status": "not_verified", "owner": "", "notes": "", "evidence": "", "attack_path_link": "", "related_finding_ids": [], "last_tested_at": "", "retest_notes": "", "remediation_advice": ""},
                {"id": "subtle-api-authorization-bugs", "category": "API Authorization", "title": "Subtle API Authorization Bugs", "priority": "critical", "objective": "", "automation_support": "", "guided_steps": [], "evidence_expectations": [], "status": "not_started", "verification_status": "not_verified", "owner": "", "notes": "", "evidence": "", "attack_path_link": "", "related_finding_ids": [], "last_tested_at": "", "retest_notes": "", "remediation_advice": ""}
            ]
        }
    }
    demo_assessment["summary"] = summarize_workbook(demo_assessment["workbook"])
    demo_scan_config = config.get_scan_config()
    demo_output_formats = demo_scan_config.get("output_formats", ["html", "markdown", "json", "sarif", "csv"])
    demo_report_profile = str(demo_scan_config.get("report_profile", "technical")).strip().lower()
    demo_include_manual = bool(demo_scan_config.get("include_manual_assessment", False))

    paths = save_reports(
        findings=enriched,
        target_url="https://demo-company.com",
        scan_mode="Full (Passive + Active)",
        start_time=start_time,
        scan_overview=demo_overview,
        assessment=demo_assessment if demo_include_manual else None,
        output_dir=config.REPORTS_DIR,
        output_formats=demo_output_formats,
        report_profile=demo_report_profile,
        include_manual_assessment=demo_include_manual,
    )

    ui.ok("Demo reports generated:")
    for label in ("html", "md", "json", "sarif", "csv"):
        if label in paths:
            print(f"  {label.upper():<5} {paths[label]}")

    # Send email if requested
    if send_email:
        duration = datetime.now() - start_time
        dur_str = f"{int(duration.total_seconds()) // 60:02d}:{int(duration.total_seconds()) % 60:02d}"
        send_scan_email(enriched, "https://demo-company.com", "Full (Passive + Active)", dur_str, paths)

    # Only prompt in interactive mode
    if not ci_mode:
        print()
        choice = input("  Open HTML report in browser? [y/N]: ").strip().lower()
        if choice == "y":
            webbrowser.open(str(paths["html"]))


# ── Scan Mode ───────────────────────────────────────────────────────────────────

def run_scan(url: str, mode: str = "passive", ci_mode: bool = False,
             send_email: bool = False, output_dir: Path | None = None, profile: str = "auto",
             progress_callback: Callable[[dict], None] | None = None,
             ci_fail_on_findings: bool = True,
             run_label: str | None = None,
             should_cancel: Callable[[], bool] | None = None):
    """Run a full scan on the given URL."""

    def _emit(event: dict):
        if progress_callback:
            progress_callback(event)

    ui.section(f"Starting {mode.upper()} scan on {url} (Profile: {profile.upper()})")
    start_time = datetime.now(UTC)
    _emit({
        "event": "stage",
        "stage": "initializing",
        "progress": 2,
        "current_tool": "Initializing",
        "message": f"Starting {mode} scan for {url}.",
    })
    ts = run_label or start_time.strftime("%Y%m%d_%H%M%S")
    scan_config = config.get_scan_config()
    tokens = config.get_tokens()
    report_profile = str(scan_config.get("report_profile", "technical")).strip().lower()
    include_manual_assessment = bool(scan_config.get("include_manual_assessment", False))
    output_formats = scan_config.get("output_formats", ["html", "markdown", "json", "sarif", "csv"])

    # Create scan output directory
    safe_host = url.replace("https://", "").replace("http://", "").replace("/", "_")
    base_dir = output_dir if output_dir else config.REPORTS_DIR
    scan_dir = base_dir / f"{safe_host}_{ts}"
    scan_dir.mkdir(parents=True, exist_ok=True)

    # Run tools
    _emit({
        "event": "stage",
        "stage": "tool_execution",
        "progress": 4,
        "current_tool": "Tool orchestration",
        "message": "Launching scan tools.",
    })
    execution = run_all_tools(url, scan_dir, scan_config, tokens, mode, profile, progress_callback=_emit, should_cancel=should_cancel)
    tools_used = execution.get("tools_used", [])
    tool_runs = execution.get("tools", [])

    if not tools_used:
        missing_tools = sorted({item.get("label") or item.get("name") or "unknown" for item in tool_runs if item.get("status") == "missing"})
        skipped_tools = sorted({item.get("label") or item.get("name") or "unknown" for item in tool_runs if item.get("status") == "skipped"})
        detail_bits = []
        if missing_tools:
            detail_bits.append(f"missing: {', '.join(missing_tools[:6])}{'...' if len(missing_tools) > 6 else ''}")
        if skipped_tools:
            detail_bits.append(f"skipped: {', '.join(skipped_tools[:6])}{'...' if len(skipped_tools) > 6 else ''}")
        detail_text = f" ({'; '.join(detail_bits)})" if detail_bits else ""
        ui.err(f"No tools were available to run{detail_text}. Install the missing tools or adjust the scan profile.")
        _emit({"event": "error", "message": f"No tools were available to run{detail_text}."})
        return

    # Parse results
    ui.section("Parsing Results")
    _emit({
        "event": "stage",
        "stage": "parsing",
        "progress": 84,
        "current_tool": "Parsing outputs",
        "message": "Parsing tool output files.",
    })
    findings = parse_all_results(scan_dir)
    overview = collect_scan_overview(
        scan_dir=scan_dir,
        target_url=url,
        requested_profile=execution.get("requested_profile", profile),
        effective_profile=execution.get("effective_profile", profile),
        tool_runs=tool_runs,
    )
    assessment = None
    if include_manual_assessment:
        assessment_workbook = get_workbook(url)
        assessment = {
            "workbook": assessment_workbook,
            "summary": summarize_workbook(assessment_workbook),
        }

    if not findings:
        ui.warn("No findings detected. The target may be well-secured or tools may need API tokens.")
    else:
        ui.ok(f"Total findings: {len(findings)}")

    # Enrich
    ui.section("Enriching Findings")
    _emit({
        "event": "stage",
        "stage": "enrichment",
        "progress": 90,
        "current_tool": "Enriching findings",
        "message": "Correlating findings with remediation guidance.",
    })
    enriched = enrich_findings(findings)
    enriched = _apply_ai_verdicts(enriched, url, scan_config)

    # Generate reports
    ui.section("Generating Reports")
    _emit({
        "event": "stage",
        "stage": "reporting",
        "progress": 96,
        "current_tool": "Generating reports",
        "message": "Building configured report outputs.",
    })
    mode_label = {"passive": "Passive", "active": "Active", "full": "Full (Passive + Active)"}
    paths = save_reports(
        findings=enriched,
        target_url=url,
        scan_mode=mode_label.get(mode, mode),
        start_time=start_time,
        scan_overview=overview,
        assessment=assessment,
        output_dir=scan_dir,
        output_formats=output_formats,
        report_profile=report_profile,
        include_manual_assessment=include_manual_assessment,
    )
    completion_path = scan_dir / "scan-complete.json"
    completion_path.write_text(
        json.dumps(
            {
                "target_url": url,
                "scan_mode": mode_label.get(mode, mode),
                "finished_at": datetime.now().isoformat(),
                "report_paths": {key: str(val) for key, val in paths.items()},
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    # Update target's last_scanned
    targets = config.get_targets()
    for t in targets:
        if t["url"] == url:
            t["last_scanned"] = start_time.strftime("%Y-%m-%d %I:%M %p")
    config.save_targets(targets)

    ui.section("Scan Complete")
    ui.ok(f"Reports saved to: {scan_dir}")
    for label in ("html", "md", "json", "sarif", "csv"):
        if label in paths:
            print(f"  {label.upper():<5} {paths[label]}")

    # Send email if requested
    if send_email:
        duration = datetime.now() - start_time
        dur_str = f"{int(duration.total_seconds()) // 60:02d}:{int(duration.total_seconds()) % 60:02d}"
        send_scan_email(enriched, url, mode_label.get(mode, mode), dur_str, paths)

    # Only prompt in interactive mode
    if not ci_mode:
        print()
        choice = input("  Open HTML report in browser? [y/N]: ").strip().lower()
        if choice == "y":
            webbrowser.open(str(paths["html"]))

    _emit({
        "event": "complete",
        "message": "Scan completed successfully.",
        "report_paths": {key: str(val) for key, val in paths.items()},
    })

    # In CI mode, exit with error if critical/high findings found
    if ci_mode and ci_fail_on_findings and enriched:
        crit_high = sum(1 for f in enriched if f.get("severity") in ("critical", "high"))
        if crit_high > 0:
            ui.warn(f"CI gate: {crit_high} critical/high finding(s) detected.")
            _emit({"event": "error", "message": f"CI gate failed: {crit_high} critical/high findings."})
            sys.exit(1)


# ── Previous Reports ────────────────────────────────────────────────────────────

def show_previous_reports():
    """List previously generated reports."""
    ui.section("Previous Reports")

    html_files = sorted(config.REPORTS_DIR.rglob("*.html"), reverse=True)
    if not html_files:
        ui.warn("No previous reports found.")
        return

    for i, f in enumerate(html_files[:20], 1):
        rel = f.relative_to(config.REPORTS_DIR)
        size_kb = f.stat().st_size / 1024
        print(f"  [{i}] {rel}  ({size_kb:.0f} KB)")

    print()
    choice = input("  Enter number to open (or press Enter to go back): ").strip()
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(html_files):
            webbrowser.open(str(html_files[idx]))
    except (ValueError, IndexError):
        pass


# ── Target Management ───────────────────────────────────────────────────────────

def manage_targets():
    """Interactive target management sub-menu."""
    while True:
        choice = ui.show_targets_menu()

        if choice == "1":
            targets = config.get_targets()
            if not targets:
                ui.warn("No targets saved.")
            else:
                ui.section("Saved Targets")
                for i, t in enumerate(targets, 1):
                    scanned = t.get("last_scanned") or "Never"
                    prof = t.get("profile", "auto")
                    print(f"  [{i}] {t['label']} - {t['url']} (Profile: {prof}, Last scan: {scanned})")

        elif choice == "2":
            url = input("  Enter target URL: ").strip()
            label = input("  Enter label/name: ").strip()
            prof = input("  Enter profile (auto/wordpress/joomla/drupal/webapp/api) [auto]: ").strip().lower() or "auto"
            if url and label:
                # Add profile manually since the old method didn't. We'll read existing dict and append.
                tList = config.get_targets()
                tList.append({"url": url, "label": label, "profile": prof, "last_scanned": None})
                config.save_targets(tList)
                ui.ok(f"Target added: {label} ({url}) as {prof}")
            else:
                ui.warn("URL and label are required.")

        elif choice == "3":
            targets = config.get_targets()
            if not targets:
                ui.warn("No targets to remove.")
            else:
                for i, t in enumerate(targets, 1):
                    print(f"  [{i}] {t['label']} - {t['url']}")
                idx_input = input("  Enter number to remove: ").strip()
                try:
                    idx = int(idx_input) - 1
                    removed = config.remove_target(idx)
                    if removed:
                        ui.ok("Target removed.")
                    else:
                        ui.warn("Invalid selection.")
                except ValueError:
                    ui.warn("Invalid input.")

        elif choice.upper() == "B":
            break


# ── Interactive Menu Loop ───────────────────────────────────────────────────────

def interactive_menu():
    """Main interactive menu loop."""
    ui.print_banner()

    while True:
        choice = ui.show_menu()

        if choice == "1":
            # Scan a target
            targets = config.get_targets()
            selected = config.select_target(targets)
            if selected:
                mode = ui.select_scan_mode()
                for target in selected:
                    run_scan(target["url"], mode, profile=target.get("profile", "auto"))

        elif choice == "2":
            manage_targets()

        elif choice == "3":
            config.configure_tokens()

        elif choice == "4":
            installed = show_tool_status()
            # Offer to install missing tools
            missing = sum(1 for v in installed.values() if not v)
            if missing > 0:
                print()
                install_choice = input(f"  {missing} tool(s) missing. Install them? [y/N]: ").strip().lower()
                if install_choice == "y":
                    install_missing_tools(installed)

        elif choice == "5":
            install_missing_tools(get_installed_tools())

        elif choice == "6":
            show_previous_reports()

        elif choice == "7":
            run_demo()

        elif choice == "8":
            configure_email()

        elif choice == "9":
            config.configure_performance_profile()

        elif choice.upper() == "Q":
            print(f"\n  Goodbye!\n")
            break

        else:
            ui.warn("Invalid option. Try again.")


# ── CLI Entry Point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="OmniScan - Multi-Tool Security Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python scanner.py                          Interactive menu
  python scanner.py --check-tools            Show installed tools
  python scanner.py --install                Install missing tools
  python scanner.py --demo                   Generate demo report
  python scanner.py --target https://example.com
  python scanner.py --target https://example.com --mode active

CI/Cron examples:
  python scanner.py --target https://example.com --ci
  python scanner.py --target https://example.com --ci --email
  python scanner.py --demo --ci --email
""",
    )
    parser.add_argument("--check-tools", action="store_true", help="Show installed tool status")
    parser.add_argument("--install", action="store_true", help="Install missing security tools")
    parser.add_argument("--demo", action="store_true", help="Generate a demo report with sample data")
    parser.add_argument("--target", type=str, help="Target URL to scan")
    parser.add_argument("--mode", choices=["passive", "active", "full"], default="passive",
                        help="Scan mode (default: passive)")
    parser.add_argument("--profile", choices=["auto", "wordpress", "joomla", "drupal", "webapp", "api"], default="auto",
                        help="Target profile type (default: auto)")
    parser.add_argument("--ci", action="store_true",
                        help="CI/headless mode: skip all prompts, no browser open")
    parser.add_argument("--email", action="store_true",
                        help="Send email notification with scan results")
    parser.add_argument("--output-dir", type=str, default=None,
                        help="Custom output directory for reports")
    parser.add_argument("--configure-email", action="store_true",
                        help="Interactive email configuration")

    args = parser.parse_args()

    # CI mode also set via CI environment variable
    ci_mode = args.ci or _is_ci()

    if args.configure_email:
        ui.print_banner()
        configure_email()
    elif args.check_tools:
        ui.print_banner()
        installed = show_tool_status()
        if not ci_mode:
            missing = sum(1 for v in installed.values() if not v)
            if missing > 0:
                print()
                choice = input(f"  {missing} tool(s) missing. Install them? [y/N]: ").strip().lower()
                if choice == "y":
                    install_missing_tools(installed)
    elif args.install:
        ui.print_banner()
        installed = get_installed_tools()
        install_missing_tools(installed)
    elif args.demo:
        ui.print_banner()
        run_demo(ci_mode=ci_mode, send_email=args.email)
    elif args.target:
        ui.print_banner()
        out_dir = Path(args.output_dir) if args.output_dir else None
        run_scan(args.target, args.mode, ci_mode=ci_mode,
                 send_email=args.email, output_dir=out_dir, profile=args.profile)
    else:
        interactive_menu()


if __name__ == "__main__":
    main()
