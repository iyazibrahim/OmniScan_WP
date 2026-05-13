"""Policy validation for AI-generated pentest action plans."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urljoin
import json

DEFAULT_POLICY = {
    "allowed_methods": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"],
    "blocked_payload_classes": ["destructive", "rce", "lateral_movement", "malware"],
    "high_impact_payload_classes": ["state_change", "privilege", "credential", "destructive"],
    "allow_subdomains": True,
    "max_actions_per_plan": 50,
    "rate_limits": {"requests_per_minute": 30},
}


@dataclass
class PolicyDecision:
    approved: bool
    requires_approval: bool
    reason: str
    normalized_action: dict


def load_policy(path: Path) -> dict:
    if not path.exists():
        return dict(DEFAULT_POLICY)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            merged = dict(DEFAULT_POLICY)
            merged.update(data)
            if not isinstance(merged.get("rate_limits"), dict):
                merged["rate_limits"] = dict(DEFAULT_POLICY["rate_limits"])
            return merged
    except Exception:
        pass
    return dict(DEFAULT_POLICY)


def _is_in_scope(candidate_url: str, target_url: str, allow_subdomains: bool) -> bool:
    try:
        target_host = (urlparse(target_url).hostname or "").lower()
        cand_host = (urlparse(candidate_url).hostname or "").lower()
    except Exception:
        return False
    if not target_host or not cand_host:
        return False
    if cand_host == target_host:
        return True
    if allow_subdomains and cand_host.endswith("." + target_host):
        return True
    return False


def _normalize_action(raw: dict, target_url: str, idx: int) -> dict:
    action = dict(raw) if isinstance(raw, dict) else {}
    method = str(action.get("method", "GET")).upper().strip() or "GET"
    action_id = str(action.get("id") or f"action-{idx:03d}")
    payload_class = str(action.get("payload_class", "safe")).strip().lower() or "safe"
    url = str(action.get("url", "")).strip()
    if not url:
        path = str(action.get("path", "")).strip() or "/"
        url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))

    headers = action.get("headers") if isinstance(action.get("headers"), dict) else {}
    body = action.get("body") if isinstance(action.get("body"), (str, bytes)) else ""
    json_body = action.get("json") if isinstance(action.get("json"), (dict, list)) else None

    normalized = {
        "id": action_id,
        "method": method,
        "url": url,
        "payload_class": payload_class,
        "headers": headers,
        "body": body,
        "json": json_body,
        "finding_id": action.get("finding_id", ""),
        "finding_title": action.get("finding_title", ""),
        "expectation": str(action.get("expectation", "vulnerable")).strip().lower() or "vulnerable",
        "assert": action.get("assert") if isinstance(action.get("assert"), dict) else {},
        "metadata": action.get("metadata") if isinstance(action.get("metadata"), dict) else {},
    }
    return normalized


def evaluate_action(
    raw_action: dict,
    target_url: str,
    policy: dict,
    require_approval_high_impact: bool,
    allow_full_testing_bypass: bool,
    idx: int,
) -> PolicyDecision:
    action = _normalize_action(raw_action, target_url, idx)

    allowed_methods = {str(m).upper() for m in policy.get("allowed_methods", [])}
    blocked_classes = {str(c).lower() for c in policy.get("blocked_payload_classes", [])}
    high_impact_classes = {str(c).lower() for c in policy.get("high_impact_payload_classes", [])}

    if action["method"] not in allowed_methods:
        return PolicyDecision(False, False, f"Method {action['method']} is not allowed by policy.", action)

    if action["payload_class"] in blocked_classes:
        return PolicyDecision(False, False, f"Payload class {action['payload_class']} is blocked by policy.", action)

    if not _is_in_scope(action["url"], target_url, bool(policy.get("allow_subdomains", True))):
        return PolicyDecision(False, False, "Target URL is outside allowed scope.", action)

    high_impact = action["payload_class"] in high_impact_classes or action["method"] in {"POST", "PUT", "PATCH", "DELETE"}
    requires_approval = bool(require_approval_high_impact and high_impact and not allow_full_testing_bypass)

    return PolicyDecision(True, requires_approval, "approved", action)


def evaluate_plan(
    plan_actions: list,
    target_url: str,
    policy: dict,
    require_approval_high_impact: bool,
    allow_full_testing_bypass: bool,
) -> dict:
    max_actions = max(1, int(policy.get("max_actions_per_plan", DEFAULT_POLICY["max_actions_per_plan"])))
    approved_actions: list[dict] = []
    rejected_actions: list[dict] = []

    for idx, raw in enumerate(plan_actions[:max_actions], 1):
        decision = evaluate_action(
            raw,
            target_url,
            policy,
            require_approval_high_impact=require_approval_high_impact,
            allow_full_testing_bypass=allow_full_testing_bypass,
            idx=idx,
        )
        if not decision.approved:
            rejected_actions.append({
                "id": decision.normalized_action.get("id", f"action-{idx:03d}"),
                "reason": decision.reason,
                "action": decision.normalized_action,
            })
            continue

        approved_actions.append({
            **decision.normalized_action,
            "requires_approval": decision.requires_approval,
            "approved": not decision.requires_approval,
        })

    return {
        "approved_actions": approved_actions,
        "rejected_actions": rejected_actions,
        "requires_approval_count": sum(1 for action in approved_actions if action.get("requires_approval")),
        "max_actions_enforced": max_actions,
    }
