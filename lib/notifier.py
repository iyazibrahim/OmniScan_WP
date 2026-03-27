"""Email notification for scan results.

Sends a summary email with the HTML report attached after a scan completes.
Configure via environment variables or config/email-config.json.
"""

import json
import os
import smtplib
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from lib import ui
from lib.config import CONFIG_DIR, load_json, save_json

EMAIL_CONFIG_FILE = CONFIG_DIR / "email-config.json"

# ── Default config ──────────────────────────────────────────────────────────────

_DEFAULT_CONFIG = {
    "enabled": False,
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "use_tls": True,
    "sender_email": "",
    "sender_password": "",
    "recipient_emails": [],
}


def get_email_config() -> dict:
    """Load email config from file, with env var overrides."""
    data = load_json(EMAIL_CONFIG_FILE)
    if not isinstance(data, dict):
        data = _DEFAULT_CONFIG.copy()

    # Environment variables override file values (useful for cron/CI)
    env_map = {
        "SMTP_SERVER": "smtp_server",
        "SMTP_PORT": "smtp_port",
        "SMTP_USE_TLS": "use_tls",
        "SMTP_SENDER": "sender_email",
        "SMTP_PASSWORD": "sender_password",
        "SMTP_RECIPIENTS": "recipient_emails",
    }
    for env_key, config_key in env_map.items():
        val = os.environ.get(env_key)
        if val:
            if config_key == "smtp_port":
                data[config_key] = int(val)
            elif config_key == "use_tls":
                data[config_key] = val.lower() in ("true", "1", "yes")
            elif config_key == "recipient_emails":
                data[config_key] = [e.strip() for e in val.split(",") if e.strip()]
            else:
                data[config_key] = val

    return data


def save_email_config(config: dict):
    """Save email configuration to file."""
    save_json(EMAIL_CONFIG_FILE, config)


def configure_email():
    """Interactive email configuration."""
    config = get_email_config()
    ui.section("Email Notification Configuration")

    print(f"  Current SMTP server:  {config.get('smtp_server', '')}")
    print(f"  Current SMTP port:    {config.get('smtp_port', 587)}")
    print(f"  Current sender:       {config.get('sender_email', '') or '[NOT SET]'}")
    print(f"  Current password:     {'[SET]' if config.get('sender_password') else '[NOT SET]'}")
    print(f"  Current recipients:   {', '.join(config.get('recipient_emails', [])) or '[NONE]'}")
    print(f"  Enabled:              {config.get('enabled', False)}")
    print()
    print("  Press Enter to keep current value, or type new value.")
    print()

    server = input("  SMTP server [smtp.gmail.com]: ").strip()
    if server:
        config["smtp_server"] = server

    port = input(f"  SMTP port [{config.get('smtp_port', 587)}]: ").strip()
    if port:
        config["smtp_port"] = int(port)

    sender = input("  Sender email: ").strip()
    if sender:
        config["sender_email"] = sender

    password = input("  Sender password / app password: ").strip()
    if password:
        config["sender_password"] = password

    recipients = input("  Recipient email(s) (comma-separated): ").strip()
    if recipients:
        config["recipient_emails"] = [e.strip() for e in recipients.split(",") if e.strip()]

    config["enabled"] = True
    save_email_config(config)
    ui.ok("Email configuration saved.")
    ui.info("For Gmail, use an App Password: https://myaccount.google.com/apppasswords")


# ── Build email content ─────────────────────────────────────────────────────────

def _build_summary(findings: list[dict], target_url: str,
                    scan_mode: str, duration_str: str) -> str:
    """Build a plain-text summary for the email body."""
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

    lines = [
        "WordPress Vulnerability Scan Complete",
        "=" * 40,
        "",
        f"Target:     {target_url}",
        f"Mode:       {scan_mode}",
        f"Duration:   {duration_str}",
        f"Total:      {len(findings)} finding(s)",
        "",
        "Severity Breakdown:",
        f"  Critical: {sev_counts['critical']}",
        f"  High:     {sev_counts['high']}",
        f"  Medium:   {sev_counts['medium']}",
        f"  Low:      {sev_counts['low']}",
        f"  Info:     {sev_counts['info']}",
        "",
    ]

    # Top findings preview
    if findings:
        lines.append("Top Findings:")
        for f in findings[:10]:
            cve = f" ({f['cve']})" if f.get("cve") else ""
            lines.append(f"  [{f['severity'].upper()}] {f['title']}{cve}")

    lines.append("")
    lines.append("Full report is attached as HTML.")
    lines.append("")
    lines.append("-- OmniScan (automated)")

    return "\n".join(lines)


# ── Send email ──────────────────────────────────────────────────────────────────

def send_scan_email(
    findings: list[dict],
    target_url: str,
    scan_mode: str,
    duration_str: str,
    report_paths: dict[str, Path],
) -> bool:
    """Send scan results via email. Returns True if sent successfully."""
    config = get_email_config()

    if not config.get("enabled") and not os.environ.get("SMTP_SENDER"):
        ui.warn("Email not configured. Run 'Configure email' from the menu or set SMTP_* env vars.")
        return False

    sender = config.get("sender_email") or os.environ.get("SMTP_SENDER", "")
    password = config.get("sender_password") or os.environ.get("SMTP_PASSWORD", "")
    recipients = config.get("recipient_emails", [])
    smtp_server = config.get("smtp_server", "smtp.gmail.com")
    smtp_port = config.get("smtp_port", 587)
    use_tls = config.get("use_tls", True)

    if not sender or not password or not recipients:
        ui.warn("Email config incomplete: need sender, password, and at least one recipient.")
        return False

    # Build the email
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev_counts[f.get("severity", "info")] = sev_counts.get(f.get("severity", "info"), 0) + 1

    subject = (
        f"[WP Scan] {target_url} — "
        f"{sev_counts['critical']}C/{sev_counts['high']}H/"
        f"{sev_counts['medium']}M/{sev_counts['low']}L "
        f"({len(findings)} total)"
    )

    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject

    # Plain text body
    body = _build_summary(findings, target_url, scan_mode, duration_str)
    msg.attach(MIMEText(body, "plain", "utf-8"))

    # Attach HTML report
    html_path = report_paths.get("html")
    if html_path and Path(html_path).exists():
        with open(html_path, "rb") as f:
            attachment = MIMEApplication(f.read(), _subtype="html")
            attachment.add_header(
                "Content-Disposition", "attachment",
                filename=Path(html_path).name,
            )
            msg.attach(attachment)

    # Attach JSON report
    json_path = report_paths.get("json")
    if json_path and Path(json_path).exists():
        with open(json_path, "rb") as f:
            attachment = MIMEApplication(f.read(), _subtype="json")
            attachment.add_header(
                "Content-Disposition", "attachment",
                filename=Path(json_path).name,
            )
            msg.attach(attachment)

    # Send
    try:
        ui.status(f"Sending email to {', '.join(recipients)}...")
        if use_tls:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=30)
            server.starttls()
        else:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=30)

        server.login(sender, password)
        server.sendmail(sender, recipients, msg.as_string())
        server.quit()

        ui.ok(f"Email sent to {', '.join(recipients)}")
        return True

    except smtplib.SMTPAuthenticationError:
        ui.err("Email auth failed. For Gmail, use an App Password (not your regular password).")
        ui.info("Generate one at: https://myaccount.google.com/apppasswords")
        return False
    except Exception as e:
        ui.err(f"Email failed: {e}")
        return False
