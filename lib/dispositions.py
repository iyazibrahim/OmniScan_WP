"""Persistent finding dispositions: confirm, false positive, suppress future scans."""

from __future__ import annotations

from datetime import datetime, UTC
from urllib.parse import urlparse
import hashlib
import re

from lib import config

DISPOSITIONS_FILE = config.CONFIG_DIR / "finding-dispositions.json"

OPEN_STATUSES = {"needs_review", "confirmed", "new", "known", "in_progress", "verified", ""}
CLOSED_STATUSES = {"false_positive", "fixed"}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_host(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = f"https://{text}"
    try:
        parsed = urlparse(text)
        return (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return text.lower()


def _normalize_title_family(title: str) -> str:
    text = re.sub(r"\s+", " ", str(title or "").strip().lower())
    text = re.sub(r"https?://\S+", "", text)
    text = re.sub(r"\b\d+(\.\d+){1,3}\b", "", text)
    text = re.sub(r"[^a-z0-9\s\-_/]", "", text)
    return re.sub(r"\s+", " ", text).strip()[:160]


def fingerprint_finding(finding: dict, target_url: str = "") -> str:
    host = _normalize_host(
        finding.get("asset")
        or finding.get("url")
        or finding.get("endpoint")
        or target_url
    )
    kind = str(finding.get("evidence_kind") or "").strip().lower() or "unknown"
    title = _normalize_title_family(str(finding.get("title") or ""))
    path = str(finding.get("path") or "").strip().lower()
    if not path:
        raw_url = str(finding.get("url") or finding.get("endpoint") or "").strip()
        if raw_url:
            try:
                path = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}").path.lower()
            except Exception:
                path = ""
    parameter = str(finding.get("parameter") or "").strip().lower()
    material = "|".join([host, kind, title, path, parameter])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:24]


def load_store() -> dict:
    data = config.load_json(DISPOSITIONS_FILE)
    if not isinstance(data, dict):
        return {"items": {}}
    items = data.get("items")
    if not isinstance(items, dict):
        data["items"] = {}
    return data


def save_store(store: dict) -> None:
    if not isinstance(store, dict):
        store = {"items": {}}
    store.setdefault("items", {})
    store["updated_at"] = _now_iso()
    config.save_json(DISPOSITIONS_FILE, store)


def list_dispositions(target: str = "", suppressed_only: bool = False) -> list[dict]:
    store = load_store()
    items = store.get("items") or {}
    host_filter = _normalize_host(target) if target else ""
    rows: list[dict] = []
    for fingerprint, record in items.items():
        if not isinstance(record, dict):
            continue
        if host_filter and _normalize_host(record.get("host") or record.get("target_url") or "") != host_filter:
            continue
        if suppressed_only and not bool(record.get("suppress_future")):
            continue
        row = dict(record)
        row["fingerprint"] = fingerprint
        rows.append(row)
    rows.sort(key=lambda item: str(item.get("updated_at") or ""), reverse=True)
    return rows


def upsert_disposition(
    finding: dict,
    status: str,
    *,
    target_url: str = "",
    suppress_future: bool = False,
    note: str = "",
    report_path: str = "",
    finding_id: str = "",
) -> dict:
    status_norm = str(status or "").strip().lower()
    if status_norm not in {"confirmed", "false_positive", "fixed", "needs_review"}:
        raise ValueError("status must be confirmed, false_positive, fixed, or needs_review")

    fingerprint = fingerprint_finding(finding, target_url=target_url)
    store = load_store()
    items = store.setdefault("items", {})
    existing = items.get(fingerprint) if isinstance(items.get(fingerprint), dict) else {}
    host = _normalize_host(finding.get("asset") or finding.get("url") or target_url)
    record = {
        **existing,
        "fingerprint": fingerprint,
        "status": status_norm,
        "suppress_future": bool(suppress_future) if status_norm == "false_positive" else False,
        "note": str(note or "").strip(),
        "host": host,
        "target_url": str(target_url or existing.get("target_url") or "").strip(),
        "title": str(finding.get("title") or existing.get("title") or "").strip(),
        "evidence_kind": str(finding.get("evidence_kind") or existing.get("evidence_kind") or "").strip(),
        "path": str(finding.get("path") or existing.get("path") or "").strip(),
        "parameter": str(finding.get("parameter") or existing.get("parameter") or "").strip(),
        "finding_id": str(finding_id or finding.get("id") or existing.get("finding_id") or "").strip(),
        "report_path": str(report_path or existing.get("report_path") or "").strip(),
        "updated_at": _now_iso(),
        "created_at": existing.get("created_at") or _now_iso(),
    }
    if status_norm == "needs_review":
        record["suppress_future"] = False
    items[fingerprint] = record
    save_store(store)
    return record


def reopen_disposition(fingerprint: str) -> dict | None:
    store = load_store()
    items = store.get("items") or {}
    record = items.get(fingerprint)
    if not isinstance(record, dict):
        return None
    record["status"] = "needs_review"
    record["suppress_future"] = False
    record["updated_at"] = _now_iso()
    items[fingerprint] = record
    save_store(store)
    return record


def apply_dispositions_to_findings(findings: list[dict], target_url: str = "") -> list[dict]:
    """Apply persisted suppressions / statuses onto freshly parsed findings."""
    store = load_store()
    items = store.get("items") or {}
    if not items:
        return findings

    updated: list[dict] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        row = dict(finding)
        fp = fingerprint_finding(row, target_url=target_url)
        row["fingerprint"] = fp
        record = items.get(fp)
        if isinstance(record, dict):
            status = str(record.get("status") or "").strip().lower()
            if bool(record.get("suppress_future")) and status == "false_positive":
                row["status"] = "false_positive"
                row["verification_status"] = "false_positive"
                row["disposition_source"] = "suppress_future"
                row["disposition_note"] = record.get("note") or ""
            elif status in {"confirmed", "false_positive", "fixed"}:
                # Carry forward previous operator decision for the same fingerprint.
                row["status"] = status
                row["verification_status"] = status if status != "confirmed" else "confirmed"
                row["disposition_source"] = "prior_disposition"
                row["disposition_note"] = record.get("note") or ""
        updated.append(row)
    return updated


def is_open_finding(finding: dict) -> bool:
    status = str(finding.get("status") or "").strip().lower()
    if status in CLOSED_STATUSES:
        return False
    verification = str(finding.get("verification_status") or "").strip().lower()
    if verification in CLOSED_STATUSES:
        return False
    return True
