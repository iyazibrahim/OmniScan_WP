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

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(app.static_folder, path)

@app.route('/api/targets', methods=['GET'])
def get_targets():
    if TARGETS_FILE.exists():
        with open(TARGETS_FILE, 'r', encoding='utf-8') as f:
            return jsonify(json.load(f))
    return jsonify([])

@app.route('/api/monthly-stats', methods=['GET'])
def get_monthly_stats():
    # Parse all report_*.json files
    stats = defaultdict(lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0})
    
    if REPORTS_DIR.exists():
        # rglob searches recursively through reports directory
        for json_file in REPORTS_DIR.rglob("report_*.json"):
            # Extract month from folder structure (e.g. 2026-03)
            parts = json_file.parts
            month_str = "Unknown"
            
            # Find the YYYY-MM folder part
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
                        # Extract severity (default to low if unknown)
                        sev = finding.get('severity', 'low').lower()
                        if sev in stats[month_str]:
                            stats[month_str][sev] += 1
            except Exception:
                pass

    # Sort and format for chart.js
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

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    mode = data.get('mode', 'passive')
    
    if not target:
        return jsonify({"error": "Target is required"}), 400
        
    # Run scan in background thread to not block the web server
    from scanner import run_scan
    thread = threading.Thread(target=run_scan, args=(target, mode, True, False, None))
    thread.start()
    
    return jsonify({"message": f"Scan started successfully on {target} in {mode} mode", "status": "running"})

if __name__ == '__main__':
    # Makes the app accessible in the network
    app.run(host='0.0.0.0', port=5000, debug=True)
