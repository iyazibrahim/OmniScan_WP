"""Lightweight monitoring, heartbeat, and module registry support."""

from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from lib.config import CONFIG_DIR, load_json, save_json

MODULES_FILE = CONFIG_DIR / "modules.json"
MONITORING_ASSETS_FILE = CONFIG_DIR / "monitoring-assets.json"
MONITORING_SETTINGS_FILE = CONFIG_DIR / "monitoring-settings.json"
MONITORING_STATE_FILE = CONFIG_DIR / "monitoring-state.json"
MONITORING_EVENTS_FILE = CONFIG_DIR / "monitoring-events.json"
HEARTBEAT_STATE_FILE = CONFIG_DIR / "heartbeat-state.json"
MONITORING_ROLLUPS_FILE = CONFIG_DIR / "monitoring-rollups.json"

DEFAULT_MODULES = {
    "dashboard": True,
    "monitoring": True,
    "scan": True,
    "reports": True,
    "assessments": False,
    "targets": True,
    "settings": True,
}

DEFAULT_MONITORING_SETTINGS = {
    "enabled": True,
    "worker_interval_seconds": 15,
    "default_check_interval_seconds": 300,
    "default_timeout_seconds": 8,
    "heartbeat_grace_multiplier": 2,
    "retention_days": 14,
    "max_events": 1000,
    "telegram": {
        "enabled": False,
        "bot_token": "",
        "chat_id": "",
        "notify_on_up": True,
        "notify_on_down": True,
        "notify_on_degraded": True,
        "cooldown_seconds": 300,
    },
}

SUPPORTED_ASSET_TYPES = {
    "website_http",
    "host_ping",
    "heartbeat_agent",
    "wan_probe",
    "network_site",
}

ROLLUP_BUCKET_MINUTES = 5
ROLLUP_MAX_BUCKETS = 288


def _now_utc() -> datetime:
    return datetime.now(UTC)


def _parse_iso(value: Any) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    except ValueError:
        return None


def _merge_defaults(base: dict[str, Any], data: Any) -> dict[str, Any]:
    merged = dict(base)
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(merged.get(key), dict) and isinstance(value, dict):
                merged[key] = _merge_defaults(merged[key], value)
            else:
                merged[key] = value
    return merged


def get_modules() -> dict[str, bool]:
    data = load_json(MODULES_FILE)
    merged = _merge_defaults(DEFAULT_MODULES, data)
    return {key: bool(value) for key, value in merged.items()}


def save_modules(modules: dict[str, Any]) -> dict[str, bool]:
    merged = get_modules()
    for key, value in modules.items():
        if key in DEFAULT_MODULES:
            merged[key] = bool(value)
    save_json(MODULES_FILE, merged)
    return merged


def get_monitoring_assets() -> list[dict[str, Any]]:
    data = load_json(MONITORING_ASSETS_FILE)
    if not isinstance(data, list):
        return []
    assets: list[dict[str, Any]] = []
    for item in data:
        if isinstance(item, dict):
            assets.append(item)
    return assets


def save_monitoring_assets(assets: list[dict[str, Any]]) -> None:
    save_json(MONITORING_ASSETS_FILE, assets)


def get_monitoring_settings() -> dict[str, Any]:
    data = load_json(MONITORING_SETTINGS_FILE)
    return _merge_defaults(DEFAULT_MONITORING_SETTINGS, data)


def save_monitoring_settings(settings: dict[str, Any]) -> dict[str, Any]:
    merged = _merge_defaults(DEFAULT_MONITORING_SETTINGS, settings)
    save_json(MONITORING_SETTINGS_FILE, merged)
    return merged


def get_monitoring_state() -> dict[str, dict[str, Any]]:
    data = load_json(MONITORING_STATE_FILE)
    if not isinstance(data, dict):
        return {}
    return {str(key): value for key, value in data.items() if isinstance(value, dict)}


def save_monitoring_state(state: dict[str, dict[str, Any]]) -> None:
    save_json(MONITORING_STATE_FILE, state)


def get_monitoring_events() -> list[dict[str, Any]]:
    data = load_json(MONITORING_EVENTS_FILE)
    if not isinstance(data, list):
        return []
    return [item for item in data if isinstance(item, dict)]


def save_monitoring_events(events: list[dict[str, Any]]) -> None:
    save_json(MONITORING_EVENTS_FILE, events)


def get_heartbeat_state() -> dict[str, dict[str, Any]]:
    data = load_json(HEARTBEAT_STATE_FILE)
    if not isinstance(data, dict):
        return {}
    return {str(key): value for key, value in data.items() if isinstance(value, dict)}


def save_heartbeat_state(state: dict[str, dict[str, Any]]) -> None:
    save_json(HEARTBEAT_STATE_FILE, state)


def get_monitoring_rollups() -> dict[str, list[dict[str, Any]]]:
    data = load_json(MONITORING_ROLLUPS_FILE)
    if not isinstance(data, dict):
        return {"uptime_buckets": [], "incident_buckets": []}
    uptime = data.get("uptime_buckets")
    incidents = data.get("incident_buckets")
    return {
        "uptime_buckets": uptime if isinstance(uptime, list) else [],
        "incident_buckets": incidents if isinstance(incidents, list) else [],
    }


def save_monitoring_rollups(rollups: dict[str, list[dict[str, Any]]]) -> None:
    save_json(MONITORING_ROLLUPS_FILE, rollups)


def normalize_asset(payload: dict[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    record = dict(existing or {})
    record["id"] = str(payload.get("id") or record.get("id") or uuid.uuid4().hex)
    record["label"] = str(payload.get("label") or record.get("label") or "").strip()
    record["asset_type"] = str(payload.get("asset_type") or record.get("asset_type") or "").strip().lower()
    record["target"] = str(payload.get("target") or record.get("target") or "").strip()
    record["site_name"] = str(payload.get("site_name") or record.get("site_name") or "").strip()
    record["enabled"] = bool(payload.get("enabled", record.get("enabled", True)))
    record["check_interval_seconds"] = max(30, int(payload.get("check_interval_seconds") or record.get("check_interval_seconds") or DEFAULT_MONITORING_SETTINGS["default_check_interval_seconds"]))
    record["timeout_seconds"] = max(2, int(payload.get("timeout_seconds") or record.get("timeout_seconds") or DEFAULT_MONITORING_SETTINGS["default_timeout_seconds"]))
    record["expected_heartbeat_seconds"] = max(30, int(payload.get("expected_heartbeat_seconds") or record.get("expected_heartbeat_seconds") or 300))
    record["alert_profile"] = str(payload.get("alert_profile") or record.get("alert_profile") or "default").strip()
    metadata = payload.get("metadata", record.get("metadata") or {})
    record["metadata"] = metadata if isinstance(metadata, dict) else {}

    if record["asset_type"] not in SUPPORTED_ASSET_TYPES:
        raise ValueError(f"Unsupported asset_type '{record['asset_type']}'")
    if not record["label"]:
        raise ValueError("label is required")
    if record["asset_type"] != "heartbeat_agent" and not record["target"]:
        raise ValueError("target is required")
    if record["asset_type"] == "heartbeat_agent" and not str(record["metadata"].get("agent_id") or "").strip():
        raise ValueError("metadata.agent_id is required for heartbeat_agent")
    return record


def summarize_monitoring(assets: list[dict[str, Any]] | None = None, state: dict[str, dict[str, Any]] | None = None, events: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    assets = assets if assets is not None else get_monitoring_assets()
    state = state if state is not None else get_monitoring_state()
    events = events if events is not None else get_monitoring_events()
    rollups = get_monitoring_rollups()

    enabled_assets = [asset for asset in assets if asset.get("enabled", True)]
    counts = {"healthy": 0, "degraded": 0, "down": 0, "unknown": 0}
    incident_assets: list[dict[str, Any]] = []
    uptime_values: list[float] = []

    for asset in enabled_assets:
        asset_state = state.get(str(asset.get("id")), {})
        status = str(asset_state.get("status") or "unknown").lower()
        if status not in counts:
            status = "unknown"
        counts[status] += 1
        uptime = float(asset_state.get("uptime_24h_pct") or 0.0)
        if uptime > 0:
            uptime_values.append(uptime)
        if status in {"down", "degraded"}:
            incident_assets.append(
                {
                    "asset_id": asset.get("id"),
                    "label": asset.get("label"),
                    "asset_type": asset.get("asset_type"),
                    "status": status,
                    "message": asset_state.get("message") or "",
                    "last_change_at": asset_state.get("last_change_at"),
                }
            )

    avg_uptime = round(sum(uptime_values) / max(1, len(uptime_values)), 2) if uptime_values else 0.0
    recent_events = sorted(events, key=lambda item: str(item.get("created_at", "")), reverse=True)[:10]
    generated_at = _now_utc()
    last_evaluated = None
    checked_times = [
        _parse_iso((state.get(str(asset.get("id")), {}) or {}).get("checked_at"))
        for asset in enabled_assets
    ]
    checked_times = [item for item in checked_times if item is not None]
    if checked_times:
        last_evaluated = max(checked_times)

    assets_with_timing = []
    for asset in assets:
        asset_state = state.get(str(asset.get("id")), {})
        checked_at = _parse_iso(asset_state.get("checked_at"))
        interval = max(30, int(asset.get("check_interval_seconds") or DEFAULT_MONITORING_SETTINGS["default_check_interval_seconds"]))
        next_due = checked_at + timedelta(seconds=interval) if checked_at else None
        assets_with_timing.append(
            {
                **asset,
                "state": {
                    **asset_state,
                    "next_check_due_at": next_due.isoformat() if next_due else None,
                    "check_interval_seconds": interval,
                },
            }
        )

    return {
        "generated_at": generated_at.isoformat(),
        "overview": {
            "enabled_assets": len(enabled_assets),
            "healthy_assets": counts["healthy"],
            "degraded_assets": counts["degraded"],
            "down_assets": counts["down"],
            "unknown_assets": counts["unknown"],
            "active_incidents": counts["down"] + counts["degraded"],
            "uptime_24h_pct": avg_uptime,
            "last_evaluated_at": last_evaluated.isoformat() if last_evaluated else None,
        },
        "status_breakdown": [
            {"label": "Healthy", "value": counts["healthy"], "status": "healthy"},
            {"label": "Degraded", "value": counts["degraded"], "status": "degraded"},
            {"label": "Down", "value": counts["down"], "status": "down"},
            {"label": "Unknown", "value": counts["unknown"], "status": "unknown"},
        ],
        "uptime_trend": list(rollups.get("uptime_buckets", []))[-12:],
        "incident_trend": list(rollups.get("incident_buckets", []))[-12:],
        "assets": assets_with_timing,
        "incidents": incident_assets[:20],
        "events": recent_events,
    }


def _event_prune(events: list[dict[str, Any]], retention_days: int, max_events: int) -> list[dict[str, Any]]:
    cutoff = _now_utc() - timedelta(days=max(1, retention_days))
    kept = [item for item in events if _parse_iso(item.get("created_at")) and _parse_iso(item.get("created_at")) >= cutoff]
    kept.sort(key=lambda item: str(item.get("created_at", "")))
    if len(kept) > max_events:
        kept = kept[-max_events:]
    return kept


def _prune_rollup_buckets(items: list[dict[str, Any]], retention_days: int) -> list[dict[str, Any]]:
    cutoff = _now_utc() - timedelta(days=max(1, retention_days))
    kept = [item for item in items if _parse_iso(item.get("bucket")) and _parse_iso(item.get("bucket")) >= cutoff]
    kept.sort(key=lambda item: str(item.get("bucket", "")))
    if len(kept) > ROLLUP_MAX_BUCKETS:
        kept = kept[-ROLLUP_MAX_BUCKETS:]
    return kept


def _bucket_start(dt: datetime) -> datetime:
    minute = (dt.minute // ROLLUP_BUCKET_MINUTES) * ROLLUP_BUCKET_MINUTES
    return dt.replace(minute=minute, second=0, microsecond=0)


def _update_monitoring_rollups(
    *,
    state: dict[str, dict[str, Any]],
    status_changed: bool,
    checked_at: datetime,
    retention_days: int,
) -> None:
    rollups = get_monitoring_rollups()
    bucket = _bucket_start(checked_at).isoformat()

    healthy = 0
    degraded = 0
    down = 0
    total = 0
    uptime_values: list[float] = []
    for item in state.values():
        if not isinstance(item, dict):
            continue
        total += 1
        status = str(item.get("status") or "unknown").lower()
        if status == "healthy":
            healthy += 1
        elif status == "degraded":
            degraded += 1
        elif status == "down":
            down += 1
        uptime = float(item.get("uptime_24h_pct") or 0.0)
        if uptime > 0:
            uptime_values.append(uptime)

    avg_uptime = round(sum(uptime_values) / max(1, len(uptime_values)), 2) if uptime_values else 0.0

    uptime_buckets = [item for item in rollups.get("uptime_buckets", []) if isinstance(item, dict)]
    incident_buckets = [item for item in rollups.get("incident_buckets", []) if isinstance(item, dict)]

    uptime_entry = next((item for item in uptime_buckets if str(item.get("bucket")) == bucket), None)
    if uptime_entry is None:
        uptime_entry = {"bucket": bucket}
        uptime_buckets.append(uptime_entry)
    uptime_entry.update(
        {
            "bucket": bucket,
            "uptime_pct": avg_uptime,
            "healthy": healthy,
            "degraded": degraded,
            "down": down,
            "total": total,
        }
    )

    incident_entry = next((item for item in incident_buckets if str(item.get("bucket")) == bucket), None)
    if incident_entry is None:
        incident_entry = {"bucket": bucket, "transitions": 0}
        incident_buckets.append(incident_entry)
    incident_entry["bucket"] = bucket
    incident_entry["transitions"] = int(incident_entry.get("transitions") or 0) + (1 if status_changed else 0)
    incident_entry["active_incidents"] = down + degraded
    incident_entry["down"] = down
    incident_entry["degraded"] = degraded

    rollups["uptime_buckets"] = _prune_rollup_buckets(uptime_buckets, retention_days)
    rollups["incident_buckets"] = _prune_rollup_buckets(incident_buckets, retention_days)
    save_monitoring_rollups(rollups)


def _host_and_port(target: str, fallback_port: int = 443) -> tuple[str, int]:
    parsed = urlparse(target)
    if parsed.scheme:
        host = parsed.hostname or ""
        if parsed.port:
            return host, parsed.port
        return host, 443 if parsed.scheme == "https" else 80
    if ":" in target and target.count(":") == 1:
        host, port_text = target.rsplit(":", 1)
        try:
            return host.strip(), int(port_text)
        except ValueError:
            return target.strip(), fallback_port
    return target.strip(), fallback_port


def _http_check(asset: dict[str, Any]) -> dict[str, Any]:
    target = str(asset.get("target", "")).strip()
    request = urllib.request.Request(target, headers={"User-Agent": "DP-Security-Platform-Monitor/1.0"})
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=int(asset.get("timeout_seconds", 8))) as response:
            latency_ms = round((time.perf_counter() - started) * 1000, 1)
            code = int(getattr(response, "status", 200) or 200)
            status = "healthy" if 200 <= code < 400 else "degraded"
            return {
                "status": status,
                "latency_ms": latency_ms,
                "message": f"HTTP {code}",
                "source": "http",
            }
    except Exception as exc:
        return {
            "status": "down",
            "latency_ms": None,
            "message": str(exc),
            "source": "http",
        }


def _tcp_check(asset: dict[str, Any]) -> dict[str, Any]:
    target = str(asset.get("target", "")).strip()
    metadata = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
    default_port = int(metadata.get("port") or 443)
    host, port = _host_and_port(target, fallback_port=default_port)
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=int(asset.get("timeout_seconds", 8))):
            latency_ms = round((time.perf_counter() - started) * 1000, 1)
            return {
                "status": "healthy",
                "latency_ms": latency_ms,
                "message": f"TCP {host}:{port} reachable",
                "source": "tcp",
            }
    except Exception as exc:
        return {
            "status": "down",
            "latency_ms": None,
            "message": str(exc),
            "source": "tcp",
        }


def _heartbeat_check(asset: dict[str, Any], heartbeat_state: dict[str, dict[str, Any]], settings: dict[str, Any]) -> dict[str, Any]:
    metadata = asset.get("metadata") if isinstance(asset.get("metadata"), dict) else {}
    agent_id = str(metadata.get("agent_id") or "").strip()
    entry = heartbeat_state.get(agent_id, {})
    sent_at = _parse_iso(entry.get("sent_at")) or _parse_iso(entry.get("checked_at"))
    if not sent_at:
        return {
            "status": "unknown",
            "latency_ms": None,
            "message": "No heartbeat received yet",
            "source": "heartbeat",
        }

    grace = max(1, int(settings.get("heartbeat_grace_multiplier", 2)))
    threshold = int(asset.get("expected_heartbeat_seconds") or 300) * grace
    age_seconds = max(0, int((_now_utc() - sent_at).total_seconds()))
    if age_seconds > threshold:
        return {
            "status": "down",
            "latency_ms": None,
            "message": f"Heartbeat overdue by {age_seconds - threshold}s",
            "source": "heartbeat",
        }

    return {
        "status": "healthy",
        "latency_ms": None,
        "message": f"Last heartbeat {age_seconds}s ago",
        "source": "heartbeat",
    }


def _send_telegram_message(settings: dict[str, Any], text: str) -> tuple[bool, str]:
    telegram = settings.get("telegram") if isinstance(settings.get("telegram"), dict) else {}
    if not telegram.get("enabled"):
        return False, "Telegram notifications are disabled"
    token = str(telegram.get("bot_token") or os.environ.get("DP_TELEGRAM_BOT_TOKEN") or "").strip()
    chat_id = str(telegram.get("chat_id") or os.environ.get("DP_TELEGRAM_CHAT_ID") or "").strip()
    if not token or not chat_id:
        return False, "Telegram bot_token and chat_id are required"

    payload = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read().decode("utf-8", errors="replace")
        data = json.loads(raw)
        if not isinstance(data, dict) or not data.get("ok"):
            return False, "Telegram API returned a non-ok response"
        return True, "Telegram message sent"
    except urllib.error.URLError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, str(exc)


class MonitoringService:
    """Small background worker for low-storage monitoring checks."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def start(self) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._run_loop, name="dp-monitoring", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def snapshot(self) -> dict[str, Any]:
        return summarize_monitoring()

    def upsert_asset(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            assets = get_monitoring_assets()
            existing = next((item for item in assets if str(item.get("id")) == str(payload.get("id"))), None)
            normalized = normalize_asset(payload, existing=existing)
            if existing:
                idx = assets.index(existing)
                assets[idx] = normalized
            else:
                assets.append(normalized)
            save_monitoring_assets(assets)
            return normalized

    def delete_asset(self, asset_id: str) -> bool:
        with self._lock:
            assets = get_monitoring_assets()
            new_assets = [asset for asset in assets if str(asset.get("id")) != str(asset_id)]
            if len(new_assets) == len(assets):
                return False
            save_monitoring_assets(new_assets)

            state = get_monitoring_state()
            if asset_id in state:
                state.pop(asset_id, None)
                save_monitoring_state(state)
            return True

    def update_settings(self, payload: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            current = get_monitoring_settings()
            merged = _merge_defaults(current, payload)
            return save_monitoring_settings(merged)

    def test_telegram(self) -> tuple[bool, str]:
        return _send_telegram_message(get_monitoring_settings(), "DP Security Platform test notification: monitoring channel is reachable.")

    def receive_heartbeat(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = str(payload.get("agent_id") or "").strip()
        agent_secret = str(payload.get("agent_secret") or "").strip()
        if not agent_id or not agent_secret:
            raise ValueError("agent_id and agent_secret are required")

        with self._lock:
            assets = get_monitoring_assets()
            asset = next(
                (
                    item
                    for item in assets
                    if item.get("asset_type") == "heartbeat_agent"
                    and str((item.get("metadata") or {}).get("agent_id") or "").strip() == agent_id
                ),
                None,
            )
            if not asset:
                raise ValueError("Unknown heartbeat agent_id")

            expected_secret = str((asset.get("metadata") or {}).get("agent_secret") or "").strip()
            if expected_secret and agent_secret != expected_secret:
                raise ValueError("Invalid heartbeat secret")

            heartbeat_state = get_heartbeat_state()
            sent_at = _parse_iso(payload.get("sent_at")) or _now_utc()
            heartbeat_state[agent_id] = {
                "asset_id": asset.get("id"),
                "agent_id": agent_id,
                "hostname": str(payload.get("hostname") or "").strip(),
                "site_name": str(payload.get("site_name") or "").strip(),
                "sent_at": sent_at.isoformat(),
                "boot_time": str(payload.get("boot_time") or "").strip(),
                "local_ip": str(payload.get("local_ip") or "").strip(),
                "metrics": payload.get("metrics") if isinstance(payload.get("metrics"), dict) else {},
                "checked_at": _now_utc().isoformat(),
            }
            save_heartbeat_state(heartbeat_state)
            self._apply_result(asset, {"status": "healthy", "latency_ms": None, "message": "Heartbeat received", "source": "heartbeat"}, checked_at=sent_at)
            return heartbeat_state[agent_id]

    def _run_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_pending_checks()
            except Exception:
                pass
            settings = get_monitoring_settings()
            sleep_for = max(5, int(settings.get("worker_interval_seconds", 15)))
            self._stop.wait(sleep_for)

    def run_pending_checks(self) -> None:
        with self._lock:
            settings = get_monitoring_settings()
            if not settings.get("enabled", True):
                return

            assets = get_monitoring_assets()
            state = get_monitoring_state()
            heartbeat_state = get_heartbeat_state()
            now = _now_utc()

            for asset in assets:
                if not asset.get("enabled", True):
                    continue
                asset_id = str(asset.get("id"))
                entry = state.get(asset_id, {})
                checked_at = _parse_iso(entry.get("checked_at"))
                interval = max(30, int(asset.get("check_interval_seconds") or settings.get("default_check_interval_seconds", 300)))
                due = checked_at is None or (now - checked_at).total_seconds() >= interval
                if not due:
                    continue

                result = self._run_check(asset, heartbeat_state, settings)
                self._apply_result(asset, result, checked_at=now)

    def _run_check(self, asset: dict[str, Any], heartbeat_state: dict[str, dict[str, Any]], settings: dict[str, Any]) -> dict[str, Any]:
        asset_type = str(asset.get("asset_type") or "").lower()
        if asset_type == "website_http":
            return _http_check(asset)
        if asset_type == "heartbeat_agent":
            return _heartbeat_check(asset, heartbeat_state, settings)
        return _tcp_check(asset)

    def _apply_result(self, asset: dict[str, Any], result: dict[str, Any], checked_at: datetime | None = None) -> None:
        checked_at = checked_at or _now_utc()
        state = get_monitoring_state()
        settings = get_monitoring_settings()
        events = get_monitoring_events()
        asset_id = str(asset.get("id"))
        previous = state.get(asset_id, {})
        previous_status = str(previous.get("status") or "unknown").lower()
        new_status = str(result.get("status") or "unknown").lower()

        success_count = int(previous.get("success_count") or 0)
        failure_count = int(previous.get("failure_count") or 0)
        if new_status == "healthy":
            success_count += 1
        elif new_status in {"down", "degraded"}:
            failure_count += 1

        total = max(1, success_count + failure_count)
        state[asset_id] = {
            "asset_id": asset_id,
            "status": new_status,
            "latency_ms": result.get("latency_ms"),
            "checked_at": checked_at.isoformat(),
            "last_change_at": previous.get("last_change_at") if previous_status == new_status else checked_at.isoformat(),
            "failure_count": failure_count,
            "success_count": success_count,
            "uptime_24h_pct": round((success_count / total) * 100, 2),
            "message": str(result.get("message") or "").strip(),
            "source": str(result.get("source") or "").strip(),
            "last_alert_at": previous.get("last_alert_at"),
        }
        if previous_status != new_status:
            state[asset_id]["last_change_at"] = checked_at.isoformat()
            event = {
                "id": uuid.uuid4().hex,
                "asset_id": asset_id,
                "asset_label": asset.get("label"),
                "asset_type": asset.get("asset_type"),
                "status": new_status,
                "previous_status": previous_status,
                "message": str(result.get("message") or "").strip(),
                "created_at": checked_at.isoformat(),
                "source": str(result.get("source") or "").strip(),
            }
            events.append(event)
            self._maybe_send_transition_alert(asset, state[asset_id], previous_status)

        _update_monitoring_rollups(
            state=state,
            status_changed=previous_status != new_status,
            checked_at=checked_at,
            retention_days=int(settings.get("retention_days", 14)),
        )
        pruned = _event_prune(events, int(settings.get("retention_days", 14)), int(settings.get("max_events", 1000)))
        save_monitoring_state(state)
        save_monitoring_events(pruned)

    def _maybe_send_transition_alert(self, asset: dict[str, Any], state_entry: dict[str, Any], previous_status: str) -> None:
        settings = get_monitoring_settings()
        telegram = settings.get("telegram") if isinstance(settings.get("telegram"), dict) else {}
        status = str(state_entry.get("status") or "unknown").lower()
        allow = (
            (status == "healthy" and telegram.get("notify_on_up", True))
            or (status == "down" and telegram.get("notify_on_down", True))
            or (status == "degraded" and telegram.get("notify_on_degraded", True))
        )
        if not allow:
            return

        last_alert_at = _parse_iso(state_entry.get("last_alert_at"))
        cooldown = max(0, int(telegram.get("cooldown_seconds", 300)))
        if last_alert_at and (_now_utc() - last_alert_at).total_seconds() < cooldown:
            return

        icon = {"healthy": "RECOVERED", "degraded": "DEGRADED", "down": "DOWN"}.get(status, status.upper())
        text = (
            f"DP Security Platform Monitoring\n"
            f"Asset: {asset.get('label')}\n"
            f"Type: {asset.get('asset_type')}\n"
            f"State: {icon}\n"
            f"Previous: {previous_status}\n"
            f"Message: {state_entry.get('message') or '-'}"
        )
        success, _message = _send_telegram_message(settings, text)
        if success:
            state = get_monitoring_state()
            entry = state.get(str(asset.get("id")))
            if isinstance(entry, dict):
                entry["last_alert_at"] = _now_utc().isoformat()
                state[str(asset.get("id"))] = entry
                save_monitoring_state(state)
