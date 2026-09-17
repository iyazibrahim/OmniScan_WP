"""OpenRouter last-step finding recommendations (never auto-applies status)."""

from __future__ import annotations

from datetime import datetime, UTC
from urllib import error, request
import json
import os

from lib import config


OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_MODEL = "openai/gpt-4o-mini"


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _get_openrouter_settings(scan_config: dict | None = None) -> dict:
    tokens = config.get_tokens()
    cfg = scan_config or {}
    api_key = str(tokens.get("openrouter_api_key") or os.environ.get("OPENROUTER_API_KEY") or "").strip()
    model = str(
        tokens.get("openrouter_model")
        or cfg.get("openrouter_model")
        or os.environ.get("OPENROUTER_MODEL")
        or DEFAULT_MODEL
    ).strip()
    enabled = bool(cfg.get("ai_verify_findings", True)) and bool(api_key)
    return {"api_key": api_key, "model": model, "enabled": enabled}


def _compact_finding(finding: dict) -> dict:
    keys = (
        "id",
        "title",
        "severity",
        "source_tool",
        "evidence_kind",
        "url",
        "path",
        "parameter",
        "payload",
        "matched_evidence",
        "description",
        "confidence",
        "status",
        "verification_status",
        "last_retest",
        "ai_hint",
    )
    return {key: finding.get(key) for key in keys if finding.get(key) not in (None, "", [], {})}


def _call_openrouter(api_key: str, model: str, findings: list[dict], target_url: str) -> list[dict]:
    system = (
        "You are a security analyst assistant. Review scanner findings and recommend "
        "confirmed, false_positive, or needs_review. Use live retest snapshots when present. "
        "Never invent new vulnerabilities. Respond with JSON only: "
        '{"recommendations":[{"id":"...","recommendation":"confirmed|false_positive|needs_review","reason":"..."}]}'
    )
    user_payload = {
        "target_url": target_url,
        "findings": [_compact_finding(item) for item in findings],
    }
    body = {
        "model": model,
        "temperature": 0.1,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(user_payload, ensure_ascii=False)},
        ],
        "response_format": {"type": "json_object"},
    }
    req = request.Request(
        OPENROUTER_URL,
        data=json.dumps(body).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://localhost",
            "X-Title": "DP Security Platform",
        },
    )
    with request.urlopen(req, timeout=60) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    content = (
        (((payload.get("choices") or [{}])[0]).get("message") or {}).get("content")
        or "{}"
    )
    if isinstance(content, list):
        content = "".join(str(part.get("text") or "") for part in content if isinstance(part, dict))
    parsed = json.loads(content)
    recommendations = parsed.get("recommendations") if isinstance(parsed, dict) else None
    if not isinstance(recommendations, list):
        return []
    return [item for item in recommendations if isinstance(item, dict)]


def recommend_findings(findings: list[dict], target_url: str = "", scan_config: dict | None = None) -> list[dict]:
    """Attach ai_recommendation + ai_reason. Does not change status/verification_status."""
    settings = _get_openrouter_settings(scan_config)
    if not settings["enabled"]:
        return findings

    candidates = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        status = str(finding.get("status") or "").strip().lower()
        if status in {"false_positive", "fixed", "confirmed"}:
            continue
        candidates.append(finding)

    if not candidates:
        return findings

    # Cap to keep cost/latency bounded.
    batch = candidates[:25]
    try:
        recommendations = _call_openrouter(settings["api_key"], settings["model"], batch, target_url)
    except error.HTTPError as exc:
        reason = f"OpenRouter HTTP {exc.code}"
        return [
            {
                **dict(f),
                "ai_recommendation": "",
                "ai_reason": reason,
                "ai_reviewed_at": _now_iso(),
            }
            if f in batch
            else f
            for f in findings
        ]
    except Exception as exc:
        reason = f"OpenRouter error: {str(exc)[:160]}"
        return [
            {
                **dict(f),
                "ai_recommendation": "",
                "ai_reason": reason,
                "ai_reviewed_at": _now_iso(),
            }
            if any(f is item for item in batch)
            else f
            for f in findings
        ]

    by_id = {}
    by_title = {}
    for item in recommendations:
        rec = str(item.get("recommendation") or "").strip().lower()
        if rec not in {"confirmed", "false_positive", "needs_review"}:
            continue
        reason = str(item.get("reason") or "").strip()[:400]
        fid = str(item.get("id") or "").strip()
        title = str(item.get("title") or "").strip().lower()
        if fid:
            by_id[fid] = (rec, reason)
        if title:
            by_title[title] = (rec, reason)

    updated = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        row = dict(finding)
        fid = str(row.get("id") or "").strip()
        title = str(row.get("title") or "").strip().lower()
        match = by_id.get(fid) or by_title.get(title)
        if match:
            row["ai_recommendation"] = match[0]
            row["ai_reason"] = match[1]
            row["ai_reviewed_at"] = _now_iso()
            row["ai_model"] = settings["model"]
        updated.append(row)
    return updated
