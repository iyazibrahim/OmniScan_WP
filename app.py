import os
import json
import threading
from pathlib import Path
from collections import defaultdict
from flask import Flask, jsonify, request, send_from_directory

app = Flask(__name__, static_folder='web')

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
CONFIG_DIR = BASE_DIR / "config"
TARGETS_FILE = CONFIG_DIR / "targets.json"
SCAN_CONFIG_FILE = CONFIG_DIR / "scan-config.json"
TOKENS_FILE = CONFIG_DIR / "tokens.json"

# ── Static / SPA ────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(app.static_folder, path)

# ── Helpers ─────────────────────────────────────────────────────────────────────

def _load_json(path: Path):
    try:
        if path.exists():
            return json.loads(path.read_text(encoding='utf-8'))
    except (json.JSONDecodeError, OSError):
        pass
    return None

def _save_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False), encoding='utf-8')

# ── Targets CRUD ────────────────────────────────────────────────────────────────

@app.route('/api/targets', methods=['GET'])
def get_targets():
    data = _load_json(TARGETS_FILE)
    if isinstance(data, list):
        return jsonify(data)
    return jsonify([])

@app.route('/api/targets', methods=['POST'])
def add_target():
    body = request.json or {}
    url = body.get('url', '').strip().rstrip('/')
    label = body.get('label', '').strip()
    profile = body.get('profile', 'wordpress').strip().lower()
    if not url or not label:
        return jsonify({"error": "url and label are required"}), 400

    data = _load_json(TARGETS_FILE)
    if not isinstance(data, list):
        data = []

    target = {"url": url, "label": label, "profile": profile, "last_scanned": None}
    data.append(target)
    _save_json(TARGETS_FILE, data)
    return jsonify(target), 201

@app.route('/api/targets/<int:index>', methods=['DELETE'])
def delete_target(index):
    data = _load_json(TARGETS_FILE)
    if not isinstance(data, list):
        return jsonify({"error": "No targets found"}), 404
    if index < 0 or index >= len(data):
        return jsonify({"error": "Invalid index"}), 404

    removed = data.pop(index)
    _save_json(TARGETS_FILE, data)
    return jsonify({"removed": removed})

# ── Scan Config ─────────────────────────────────────────────────────────────────

@app.route('/api/config', methods=['GET'])
def get_config():
    data = _load_json(SCAN_CONFIG_FILE)
    if isinstance(data, dict):
        return jsonify(data)
    return jsonify({})

@app.route('/api/config', methods=['PUT'])
def update_config():
    body = request.json
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400
    _save_json(SCAN_CONFIG_FILE, body)
    return jsonify({"message": "Configuration saved", "config": body})

# ── Tokens ──────────────────────────────────────────────────────────────────────

@app.route('/api/tokens', methods=['GET'])
def get_tokens():
    data = _load_json(TOKENS_FILE)
    if not isinstance(data, dict):
        data = {"wpscan_api_token": "", "zap_api_key": ""}
    # Mask values for security
    masked = {}
    for key, val in data.items():
        if key.startswith('_'):
            continue
        if val and len(str(val)) > 4:
            masked[key] = str(val)[:4] + '•' * (len(str(val)) - 4)
        elif val:
            masked[key] = '••••'
        else:
            masked[key] = ''
    return jsonify(masked)

@app.route('/api/tokens', methods=['PUT'])
def update_tokens():
    body = request.json
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400

    # Load existing tokens so we don't overwrite with masked values
    existing = _load_json(TOKENS_FILE)
    if not isinstance(existing, dict):
        existing = {"wpscan_api_token": "", "zap_api_key": ""}

    for key, val in body.items():
        # Only update if the value doesn't contain mask chars (user actually changed it)
        if '•' not in str(val):
            existing[key] = val

    _save_json(TOKENS_FILE, existing)
    return jsonify({"message": "Tokens saved"})

# ── Tools Status ────────────────────────────────────────────────────────────────

@app.route('/api/tools-status', methods=['GET'])
def tools_status():
    import shutil
    tools = [
        {"name": "nuclei",  "label": "Nuclei",    "phase": "passive"},
        {"name": "wpscan",  "label": "WPScan",    "phase": "passive"},
        {"name": "nikto",   "label": "Nikto",     "phase": "passive"},
        {"name": "zap-cli", "label": "OWASP ZAP", "phase": "active"},
        {"name": "sqlmap",  "label": "SQLMap",     "phase": "active"},
        {"name": "sslyze",  "label": "SSLyze",    "phase": "passive"},
        {"name": "whatweb", "label": "WhatWeb",    "phase": "passive"},
        {"name": "httpx",   "label": "httpx",      "phase": "passive"},
        {"name": "cmsmap",  "label": "CMSMap",     "phase": "active"},
    ]
    for t in tools:
        t["installed"] = shutil.which(t["name"]) is not None
    return jsonify(tools)

# ── Reports ─────────────────────────────────────────────────────────────────────

@app.route('/api/reports', methods=['GET'])
def list_reports():
    reports = []
    if REPORTS_DIR.exists():
        # Find all HTML report files recursively
        for html_file in sorted(REPORTS_DIR.rglob("*.html"), reverse=True):
            rel = html_file.relative_to(REPORTS_DIR)
            size_kb = html_file.stat().st_size / 1024
            mtime = html_file.stat().st_mtime

            # Try to find companion JSON for severity counts
            json_companion = html_file.with_suffix('.json')
            if not json_companion.exists():
                # Check for report_*.json in the same folder
                parent = html_file.parent
                json_files = list(parent.glob("report_*.json"))
                json_companion = json_files[0] if json_files else None

            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            if json_companion and json_companion.exists():
                try:
                    findings = json.loads(json_companion.read_text(encoding='utf-8'))
                    if isinstance(findings, list):
                        for f in findings:
                            sev = f.get('severity', 'low').lower()
                            if sev in severity_counts:
                                severity_counts[sev] += 1
                except Exception:
                    pass

            reports.append({
                "path": str(rel).replace('\\', '/'),
                "name": html_file.stem,
                "folder": str(rel.parent).replace('\\', '/'),
                "size_kb": round(size_kb, 1),
                "modified": mtime,
                "severities": severity_counts,
            })

    return jsonify(reports[:50])  # Limit to 50 most recent

@app.route('/api/reports/<path:filepath>')
def serve_report(filepath):
    return send_from_directory(str(REPORTS_DIR), filepath)

# ── Monthly Stats (for chart) ──────────────────────────────────────────────────

@app.route('/api/monthly-stats', methods=['GET'])
def get_monthly_stats():
    stats = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})

    if REPORTS_DIR.exists():
        for json_file in REPORTS_DIR.rglob("report_*.json"):
            parts = json_file.parts
            month_str = "Unknown"
            for part in parts:
                if len(part) == 7 and part[4] == '-' and part[:4].isdigit():
                    month_str = part
                    break
            if month_str == "Unknown":
                continue
            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    findings = json.load(f)
                    for finding in findings:
                        sev = finding.get('severity', 'low').lower()
                        if sev in stats[month_str]:
                            stats[month_str][sev] += 1
            except Exception:
                pass

    sorted_months = sorted(stats.keys())
    result = {
        "labels": sorted_months,
        "datasets": {
            "critical": [stats[m]["critical"] for m in sorted_months],
            "high": [stats[m]["high"] for m in sorted_months],
            "medium": [stats[m]["medium"] for m in sorted_months],
            "low": [stats[m]["low"] for m in sorted_months],
        }
    }
    return jsonify(result)

# ── Scan ────────────────────────────────────────────────────────────────────────

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    mode = data.get('mode', 'passive')
    profile = data.get('profile', 'wordpress').strip().lower()

    if not target:
        return jsonify({"error": "Target is required"}), 400

    from scanner import run_scan
    thread = threading.Thread(target=run_scan, args=(target, mode, True, False, None, profile))
    thread.start()

    return jsonify({"message": f"Scan started successfully on {target} in {mode} mode", "status": "running"})

# ── Entry Point ─────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
