import os
import json
import threading
import uuid
import time
from pathlib import Path
from collections import defaultdict
from flask import Flask, jsonify, request, send_from_directory
from lib.assessments import get_catalog, get_workbook, save_workbook, summarize_workbook

app = Flask(__name__, static_folder='web')

BASE_DIR = Path(__file__).resolve().parent
REPORTS_DIR = BASE_DIR / "reports"
CONFIG_DIR = BASE_DIR / "config"
TARGETS_FILE = CONFIG_DIR / "targets.json"
SCAN_CONFIG_FILE = CONFIG_DIR / "scan-config.json"
TOKENS_FILE = CONFIG_DIR / "tokens.json"

SCAN_JOBS: dict[str, dict] = {}
SCAN_JOBS_LOCK = threading.Lock()

DEFAULT_SCAN_ESTIMATES_SECONDS = {
    "passive": 8 * 60,
    "active": 15 * 60,
    "full": 23 * 60,
}

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


def _require_target_arg():
    target = (request.args.get("target") or "").strip().rstrip("/")
    if not target:
        return None
    return target


def _safe_int(value, fallback=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


def _format_eta(seconds: int) -> str:
    total = max(0, int(seconds))
    mins, secs = divmod(total, 60)
    if mins >= 60:
        hours, mins = divmod(mins, 60)
        return f"~{hours}h {mins}m"
    if mins > 0:
        return f"~{mins}m {secs:02d}s"
    return f"~{secs}s"


def _compute_scan_estimates() -> dict:
    durations: dict[str, list[int]] = {"passive": [], "active": [], "full": []}
    tool_durations: dict[str, list[int]] = defaultdict(list)

    if REPORTS_DIR.exists():
        for json_file in REPORTS_DIR.rglob("report_*.json"):
            try:
                report_data = json.loads(json_file.read_text(encoding="utf-8"))
            except Exception:
                continue
            if not isinstance(report_data, dict):
                continue

            mode_raw = str(report_data.get("scan_mode", "")).lower().strip()
            duration = _safe_int(report_data.get("scan_duration_seconds"), 0)
            if duration > 0:
                if mode_raw.startswith("passive"):
                    durations["passive"].append(duration)
                elif mode_raw.startswith("active"):
                    durations["active"].append(duration)
                elif mode_raw.startswith("full"):
                    durations["full"].append(duration)

            for run in (report_data.get("tool_runs") or []):
                if not isinstance(run, dict):
                    continue
                tool_name = run.get("name") or run.get("tool") or ""
                tool_dur = _safe_int(run.get("duration_seconds"), 0)
                if tool_name and tool_dur > 0:
                    tool_durations[tool_name].append(tool_dur)

    estimates: dict = {}
    for mode, fallback in DEFAULT_SCAN_ESTIMATES_SECONDS.items():
        values = sorted(durations.get(mode, []))
        if values:
            mid = len(values) // 2
            median = values[mid] if len(values) % 2 == 1 else (values[mid - 1] + values[mid]) // 2
            estimate_seconds = max(45, median)
            source = "historical"
        else:
            estimate_seconds = fallback
            source = "default"

        estimates[mode] = {
            "seconds": estimate_seconds,
            "label": _format_eta(estimate_seconds),
            "source": source,
        }

    tool_estimates: dict = {}
    for tool_name, durs in tool_durations.items():
        sorted_durs = sorted(durs)
        mid = len(sorted_durs) // 2
        median = sorted_durs[mid] if len(sorted_durs) % 2 == 1 else (sorted_durs[mid - 1] + sorted_durs[mid]) // 2
        tool_estimates[tool_name] = {
            "seconds": median,
            "label": _format_eta(median),
        }
    estimates["tool_estimates"] = tool_estimates

    return estimates


def _update_scan_job(scan_id: str, patch: dict):
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if not job:
            return
        job.update(patch)
        job["updated_at"] = time.time()


def _append_scan_event(scan_id: str, message: str):
    if not message:
        return
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if not job:
            return
        events = job.setdefault("events", [])
        events.append({"at": time.time(), "message": message})
        if len(events) > 35:
            del events[:-35]

# ── Targets CRUD ────────────────────────────────────────────────────────────────

@app.route('/api/targets', methods=['GET'])
def get_targets():
    data = _load_json(TARGETS_FILE)
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and not item.get("profile"):
                item["profile"] = "auto"
        return jsonify(data)
    return jsonify([])

@app.route('/api/targets', methods=['POST'])
def add_target():
    body = request.json or {}
    url = body.get('url', '').strip().rstrip('/')
    label = body.get('label', '').strip()
    profile = body.get('profile', 'auto').strip().lower()
    if not url or not label:
        return jsonify({"error": "url and label are required"}), 400

    data = _load_json(TARGETS_FILE)
    if not isinstance(data, list):
        data = []

    target = {"url": url, "label": label, "profile": profile or "auto", "last_scanned": None}
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
    from lib.tools import TOOLS
    
    tools = [dict(t) for t in TOOLS]
    for t in tools:
        t["installed"] = shutil.which(t["name"]) is not None
    return jsonify(tools)


# ── Guided Assessments ──────────────────────────────────────────────────────────

@app.route('/api/assessments/catalog', methods=['GET'])
def assessments_catalog():
    return jsonify(get_catalog())


@app.route('/api/assessments', methods=['GET'])
def get_assessment():
    target = _require_target_arg()
    if not target:
        return jsonify({"error": "target query parameter is required"}), 400
    workbook = get_workbook(target)
    summary = summarize_workbook(workbook)
    return jsonify({"workbook": workbook, "summary": summary})


@app.route('/api/assessments', methods=['PUT'])
def update_assessment():
    target = _require_target_arg()
    if not target:
        return jsonify({"error": "target query parameter is required"}), 400
    body = request.json
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object required"}), 400
    workbook = save_workbook(target, body)
    summary = summarize_workbook(workbook)
    return jsonify({"message": "Assessment workbook saved", "workbook": workbook, "summary": summary})

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
            target_url = ""
            effective_profile = ""
            assessment_summary = {}
            if json_companion and json_companion.exists():
                try:
                    report_data = json.loads(json_companion.read_text(encoding='utf-8'))
                    if isinstance(report_data, dict):
                        findings = report_data.get("findings", [])
                        target_url = report_data.get("target_url", "")
                        effective_profile = report_data.get("overview", {}).get("effective_profile", "")
                        assessment_summary = report_data.get("assessment", {}).get("summary", {})
                    else:
                        findings = report_data
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
                "target_url": target_url,
                "profile": effective_profile,
                "assessment_summary": assessment_summary,
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
                    report_data = json.load(f)
                    findings = report_data.get("findings", []) if isinstance(report_data, dict) else report_data
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
    data = request.json or {}
    target = str(data.get('target', '')).strip().rstrip('/')
    mode = str(data.get('mode', 'passive')).strip().lower()
    profile = str(data.get('profile', 'auto')).strip().lower() or "auto"

    if not target:
        return jsonify({"error": "Target is required"}), 400
    if mode not in {"passive", "active", "full"}:
        return jsonify({"error": "Invalid mode"}), 400

    estimates = _compute_scan_estimates()
    estimated_seconds = estimates.get(mode, {}).get("seconds", DEFAULT_SCAN_ESTIMATES_SECONDS["full"])
    scan_id = uuid.uuid4().hex

    with SCAN_JOBS_LOCK:
        SCAN_JOBS[scan_id] = {
            "scan_id": scan_id,
            "target": target,
            "mode": mode,
            "profile": profile,
            "status": "running",
            "started_at": time.time(),
            "updated_at": time.time(),
            "progress": 1,
            "phase": "initializing",
            "current_tool": "Preparing scan",
            "completed_tools": 0,
            "total_tools": 0,
            "tool_status": [],
            "estimated_seconds": estimated_seconds,
            "events": [{"at": time.time(), "message": "Scan queued and initializing."}],
            "message": f"Scan started on {target} in {mode} mode.",
        }

    def _progress_callback(event: dict):
        if not isinstance(event, dict):
            return

        patch = {}
        event_type = event.get("event")

        if isinstance(event.get("message"), str) and event.get("message"):
            _append_scan_event(scan_id, event["message"])

        if event_type == "plan_updated":
            patch["total_tools"] = _safe_int(event.get("total_tools"), 0)
            if isinstance(event.get("phase"), str):
                patch["phase"] = event["phase"]

        elif event_type == "tool_started":
            with SCAN_JOBS_LOCK:
                _job = SCAN_JOBS.get(scan_id)
                if _job and _job.get("cancel_requested"):
                    raise InterruptedError("Scan cancelled by user.")
            tool_name = event.get("tool_label") or event.get("tool") or "Tool"
            patch.update(
                {
                    "phase": event.get("phase", "tool_execution"),
                    "current_tool": tool_name,
                    "completed_tools": _safe_int(event.get("completed_tools"), 0),
                    "total_tools": _safe_int(event.get("total_tools"), 0),
                    "progress": max(2, min(96, _safe_int(event.get("progress"), 2))),
                }
            )
            _append_scan_event(scan_id, f"Running {tool_name}...")

        elif event_type == "tool_finished":
            tool_name = event.get("tool_label") or event.get("tool") or "Tool"
            status = event.get("status", "completed")
            patch.update(
                {
                    "completed_tools": _safe_int(event.get("completed_tools"), 0),
                    "total_tools": _safe_int(event.get("total_tools"), 0),
                    "progress": max(2, min(96, _safe_int(event.get("progress"), 2))),
                }
            )
            _append_scan_event(scan_id, f"{tool_name} finished with status: {status}.")

            with SCAN_JOBS_LOCK:
                job = SCAN_JOBS.get(scan_id)
                if job is not None:
                    tool_status = job.setdefault("tool_status", [])
                    tool_status.append(
                        {
                            "name": event.get("tool") or tool_name,
                            "label": tool_name,
                            "phase": event.get("phase", ""),
                            "status": status,
                            "duration_seconds": event.get("duration_seconds", 0),
                        }
                    )
                    if len(tool_status) > 40:
                        del tool_status[:-40]

        elif event_type == "stage":
            patch["phase"] = event.get("stage", "processing")
            patch["progress"] = max(2, min(99, _safe_int(event.get("progress"), 2)))
            if event.get("current_tool"):
                patch["current_tool"] = event.get("current_tool")

        elif event_type == "complete":
            patch.update(
                {
                    "status": "completed",
                    "phase": "completed",
                    "progress": 100,
                    "current_tool": "Completed",
                    "finished_at": time.time(),
                    "message": event.get("message", "Scan completed."),
                }
            )
            if event.get("report_paths"):
                patch["report_paths"] = event.get("report_paths")
            _append_scan_event(scan_id, "Scan completed successfully.")

        elif event_type == "error":
            patch.update(
                {
                    "status": "failed",
                    "phase": "failed",
                    "current_tool": "Failed",
                    "finished_at": time.time(),
                    "message": event.get("message", "Scan failed."),
                }
            )
            _append_scan_event(scan_id, f"Scan failed: {event.get('message', 'Unknown error')}")

        if patch:
            _update_scan_job(scan_id, patch)

    def _run_scan_job():
        from scanner import run_scan

        try:
            run_scan(
                target,
                mode,
                True,
                False,
                None,
                profile,
                progress_callback=_progress_callback,
                ci_fail_on_findings=False,
            )
            with SCAN_JOBS_LOCK:
                job = SCAN_JOBS.get(scan_id)
            if job and job.get("status") == "running":
                _progress_callback({"event": "complete", "message": "Scan completed."})
        except InterruptedError:
            _update_scan_job(scan_id, {
                "status": "cancelled",
                "phase": "cancelled",
                "current_tool": "Cancelled",
                "finished_at": time.time(),
                "message": "Scan cancelled by user.",
            })
            _append_scan_event(scan_id, "Scan cancelled by user.")
        except SystemExit as exc:
            _progress_callback({"event": "error", "message": f"Scan aborted (exit {exc.code})."})
        except Exception as exc:
            _progress_callback({"event": "error", "message": str(exc)})

    thread = threading.Thread(target=_run_scan_job, daemon=True)
    thread.start()

    return jsonify(
        {
            "scan_id": scan_id,
            "message": f"Scan started successfully on {target} in {mode} mode.",
            "status": "running",
            "estimated_seconds": estimated_seconds,
            "estimated_label": _format_eta(estimated_seconds),
        }
    )


@app.route('/api/scan-status/<scan_id>', methods=['GET'])
def get_scan_status(scan_id):
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if not job:
            return jsonify({"error": "Scan not found"}), 404
        payload = dict(job)

    elapsed = max(0, int(time.time() - payload.get("started_at", time.time())))
    estimate = max(1, _safe_int(payload.get("estimated_seconds"), DEFAULT_SCAN_ESTIMATES_SECONDS["full"]))
    payload["elapsed_seconds"] = elapsed
    payload["elapsed_label"] = _format_eta(elapsed)
    payload["estimated_label"] = _format_eta(estimate)
    payload["eta_seconds"] = max(0, estimate - elapsed) if payload.get("status") == "running" else 0
    payload["eta_label"] = _format_eta(payload["eta_seconds"]) if payload.get("status") == "running" else "~0s"

    return jsonify(payload)


@app.route('/api/scan-estimates', methods=['GET'])
def get_scan_estimates():
    return jsonify(_compute_scan_estimates())


@app.route('/api/scan/<scan_id>/cancel', methods=['POST'])
def cancel_scan(scan_id):
    with SCAN_JOBS_LOCK:
        job = SCAN_JOBS.get(scan_id)
        if not job:
            return jsonify({"error": "Scan not found"}), 404
        if job.get("status") not in ("running", "cancelling"):
            return jsonify({"error": "Scan is not running"}), 400
        job["cancel_requested"] = True
        job["status"] = "cancelling"
        job["updated_at"] = time.time()
    return jsonify({"message": "Cancel requested."})


@app.route('/api/scan-jobs', methods=['GET'])
def list_scan_jobs():
    with SCAN_JOBS_LOCK:
        jobs = list(SCAN_JOBS.values())
    now = time.time()
    result = []
    for job in sorted(jobs, key=lambda x: x.get("started_at", 0), reverse=True)[:10]:
        elapsed = max(0, int(now - job.get("started_at", now)))
        estimate = max(1, _safe_int(job.get("estimated_seconds"), DEFAULT_SCAN_ESTIMATES_SECONDS["full"]))
        status = job.get("status", "unknown")
        result.append({
            "scan_id": job.get("scan_id"),
            "target": job.get("target"),
            "mode": job.get("mode"),
            "profile": job.get("profile"),
            "status": status,
            "progress": job.get("progress", 0),
            "started_at": job.get("started_at"),
            "elapsed_label": _format_eta(elapsed),
            "eta_label": _format_eta(max(0, estimate - elapsed)) if status == "running" else None,
            "current_tool": job.get("current_tool"),
        })
    return jsonify(result)



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
