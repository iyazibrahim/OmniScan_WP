"""Guided assessment catalog and target workbook storage."""

from __future__ import annotations

import copy
from datetime import datetime, UTC

from lib.config import CONFIG_DIR, load_json, save_json

ASSESSMENT_CATALOG_FILE = CONFIG_DIR / "assessment-catalog.json"
ASSESSMENTS_FILE = CONFIG_DIR / "assessments.json"

DEFAULT_CATALOG = [
    {
        "id": "business-logic-flaws",
        "category": "Business Logic",
        "title": "Business Logic Abuse Review",
        "priority": "high",
        "objective": "Identify workflow abuse that violates the intended business rules without relying on classic technical exploits.",
        "automation_support": "Use scan output to map forms, endpoints, parameters, and hidden workflow URLs before manual chaining.",
        "guided_steps": [
            "Identify core workflows such as purchase, approval, account recovery, rewards, booking, or submission flows.",
            "Attempt step skipping, replay, duplicate submission, negative values, stale state reuse, and race-condition style repetition.",
            "Compare client-side restrictions with server-side enforcement and capture evidence for inconsistent state transitions.",
        ],
        "evidence_expectations": [
            "Affected workflow name",
            "Sequence of requests or steps",
            "Observed business impact",
            "Server-side response proving the flaw",
        ],
    },
    {
        "id": "complex-auth-bypass",
        "category": "Authentication",
        "title": "Complex Authentication Bypass",
        "priority": "critical",
        "objective": "Test multi-step authentication and recovery paths for bypasses across login, password reset, MFA, invite, and activation flows.",
        "automation_support": "Use discovery results to locate login, reset, invitation, and callback endpoints.",
        "guided_steps": [
            "Map all authentication entry points including SSO callbacks, password reset, OTP, invite acceptance, and device trust flows.",
            "Test state tampering, token reuse, replay after logout, cross-account reset flows, and alternate identity providers.",
            "Validate whether MFA, email verification, or account activation can be bypassed by direct API or step desynchronization.",
        ],
        "evidence_expectations": [
            "Preconditions and account state",
            "Bypass path or token handling issue",
            "Impact on account takeover or privilege gain",
        ],
    },
    {
        "id": "real-access-control-testing",
        "category": "Access Control",
        "title": "Real Access Control Testing",
        "priority": "critical",
        "objective": "Validate authorization boundaries using role, ownership, horizontal, and vertical access-control tests instead of only status codes.",
        "automation_support": "Use crawler, parameter, and content-discovery output to enumerate object IDs, admin URLs, and API resources.",
        "guided_steps": [
            "Establish at least two user roles and two users in the same role when possible.",
            "Replay requests across roles, tenants, and object owners with only identifiers changed.",
            "Check both UI and direct API access to privileged actions, exports, admin functions, and hidden resources.",
        ],
        "evidence_expectations": [
            "Actor role and target object owner",
            "Original authorized request and unauthorized variant",
            "Observed unauthorized data access or action success",
        ],
    },
    {
        "id": "multi-step-abuse-paths",
        "category": "Abuse Paths",
        "title": "Multi-Step Abuse Path Mapping",
        "priority": "high",
        "objective": "Chain individually weak controls into a practical attack path that creates meaningful business impact.",
        "automation_support": "Use fingerprinting, discovery, and automated findings as candidate starting points for chaining.",
        "guided_steps": [
            "List all low- and medium-severity findings that could assist later stages such as endpoint discovery, open redirects, verbose errors, and missing validation.",
            "Model at least one path from reconnaissance to impact using multiple weaknesses.",
            "Capture prerequisites, transition points, and where a defensive control should have interrupted the path.",
        ],
        "evidence_expectations": [
            "Attack path narrative",
            "Linked findings or assumptions",
            "Business impact if executed end to end",
        ],
    },
    {
        "id": "tenant-isolation-failures",
        "category": "Multi-Tenancy",
        "title": "Tenant Isolation Review",
        "priority": "critical",
        "objective": "Validate hard tenant boundaries across identifiers, exports, search, shared resources, and caching layers.",
        "automation_support": "Use parameter discovery and API endpoint mapping to locate tenant identifiers and cross-tenant object references.",
        "guided_steps": [
            "Compare requests from multiple tenants and identify all tenant identifiers in headers, paths, query strings, and payloads.",
            "Test whether tenant IDs can be swapped, omitted, or overruled by hidden parameters or cached artifacts.",
            "Check exports, attachments, logs, notifications, and background jobs for cross-tenant data leakage.",
        ],
        "evidence_expectations": [
            "Tenant A and Tenant B context",
            "Cross-tenant object or data exposed",
            "Whether access was read-only or write-capable",
        ],
    },
    {
        "id": "subtle-api-authorization-bugs",
        "category": "API Authorization",
        "title": "Subtle API Authorization Bugs",
        "priority": "critical",
        "objective": "Look for fine-grained API authorization gaps that do not appear as obvious 200/403 mismatches.",
        "automation_support": "Use API discovery, parameter extraction, and replay of authenticated traffic to build test cases.",
        "guided_steps": [
            "Inspect create, update, bulk action, export, and search endpoints for hidden fields and ownership controls.",
            "Test field-level authorization, mass assignment, object reassignment, and scope confusion between list and detail endpoints.",
            "Compare API behavior against UI restrictions and role documentation to find mismatched enforcement.",
        ],
        "evidence_expectations": [
            "Affected endpoint and method",
            "Unauthorized field, object, or action",
            "Observed response proving the authorization gap",
        ],
    },
]


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def get_catalog() -> list[dict]:
    data = load_json(ASSESSMENT_CATALOG_FILE)
    if isinstance(data, list) and data:
        return data
    return copy.deepcopy(DEFAULT_CATALOG)


def _default_note(title: str = "", body: str = "", note_type: str = "analysis") -> dict:
    return {
        "id": f"note-{datetime.now(UTC).timestamp():.6f}".replace(".", "-"),
        "created_at": _now_iso(),
        "updated_at": _now_iso(),
        "title": title,
        "body": body,
        "type": note_type,
        "author": "",
    }


def _default_case(item: dict) -> dict:
    return {
        "id": item["id"],
        "category": item.get("category", ""),
        "title": item.get("title", ""),
        "priority": item.get("priority", "medium"),
        "objective": item.get("objective", ""),
        "automation_support": item.get("automation_support", ""),
        "guided_steps": list(item.get("guided_steps", [])),
        "evidence_expectations": list(item.get("evidence_expectations", [])),
        "status": "not_started",
        "verification_status": "not_verified",
        "owner": "",
        "notes": "",
        "evidence": "",
        "attack_path_link": "",
        "related_finding_ids": [],
        "last_tested_at": "",
        "retest_notes": "",
        "remediation_advice": "",
    }


def _default_workbook(target_url: str) -> dict:
    catalog = get_catalog()
    return {
        "target_url": target_url,
        "updated_at": _now_iso(),
        "summary": "",
        "auth_context_notes": "",
        "attack_path_hypotheses": "",
        "verification_strategy": "",
        "operator_notes": [_default_note("Initial assessment context", "", "context")],
        "verification_runs": [],
        "cases": [_default_case(item) for item in catalog],
    }


def _normalize_workbook(target_url: str, data: dict | None) -> dict:
    workbook = copy.deepcopy(data) if isinstance(data, dict) else _default_workbook(target_url)
    workbook["target_url"] = target_url
    workbook.setdefault("updated_at", _now_iso())
    workbook.setdefault("summary", "")
    workbook.setdefault("auth_context_notes", "")
    workbook.setdefault("attack_path_hypotheses", "")
    workbook.setdefault("verification_strategy", "")
    workbook.setdefault("operator_notes", [])
    workbook.setdefault("verification_runs", [])
    workbook.setdefault("cases", [])

    catalog_map = {item["id"]: item for item in get_catalog()}
    cases_by_id = {case.get("id"): case for case in workbook["cases"] if isinstance(case, dict) and case.get("id")}

    normalized_cases = []
    for case_id, catalog_item in catalog_map.items():
        current = cases_by_id.get(case_id, {})
        merged = _default_case(catalog_item)
        if isinstance(current, dict):
            merged.update({k: v for k, v in current.items() if k in merged or k in {"notes", "evidence", "status", "verification_status", "owner", "related_finding_ids", "last_tested_at", "retest_notes", "remediation_advice", "attack_path_link"}})
        normalized_cases.append(merged)
    workbook["cases"] = normalized_cases

    cleaned_notes = []
    for note in workbook["operator_notes"]:
        if not isinstance(note, dict):
            continue
        cleaned = _default_note()
        cleaned.update(note)
        cleaned.setdefault("created_at", _now_iso())
        cleaned.setdefault("updated_at", _now_iso())
        cleaned_notes.append(cleaned)
    workbook["operator_notes"] = cleaned_notes or [_default_note("Initial assessment context", "", "context")]

    cleaned_runs = []
    for run in workbook["verification_runs"]:
        if not isinstance(run, dict):
            continue
        cleaned_runs.append(
            {
                "id": run.get("id") or f"verify-{datetime.now(UTC).timestamp():.6f}".replace(".", "-"),
                "created_at": run.get("created_at") or _now_iso(),
                "title": run.get("title", ""),
                "scope": run.get("scope", ""),
                "outcome": run.get("outcome", "pending"),
                "notes": run.get("notes", ""),
                "related_case_ids": list(run.get("related_case_ids", [])),
                "related_finding_ids": list(run.get("related_finding_ids", [])),
            }
        )
    workbook["verification_runs"] = cleaned_runs
    return workbook


def _load_store() -> dict:
    data = load_json(ASSESSMENTS_FILE)
    if isinstance(data, dict):
        return data
    return {}


def get_workbook(target_url: str) -> dict:
    store = _load_store()
    workbook = store.get(target_url)
    normalized = _normalize_workbook(target_url, workbook)
    if workbook != normalized:
        store[target_url] = normalized
        save_json(ASSESSMENTS_FILE, store)
    return normalized


def save_workbook(target_url: str, workbook: dict) -> dict:
    store = _load_store()
    normalized = _normalize_workbook(target_url, workbook)
    normalized["updated_at"] = _now_iso()
    store[target_url] = normalized
    save_json(ASSESSMENTS_FILE, store)
    return normalized


def summarize_workbook(workbook: dict) -> dict:
    cases = workbook.get("cases", [])
    by_status: dict[str, int] = {}
    by_verification: dict[str, int] = {}
    by_category: dict[str, dict[str, int]] = {}
    for case in cases:
        status = case.get("status", "not_started")
        verification = case.get("verification_status", "not_verified")
        category = case.get("category", "Other")
        by_status[status] = by_status.get(status, 0) + 1
        by_verification[verification] = by_verification.get(verification, 0) + 1
        category_bucket = by_category.setdefault(category, {"total": 0, "completed": 0, "confirmed": 0})
        category_bucket["total"] += 1
        if status in {"in_progress", "confirmed", "fixed", "needs_evidence"}:
            category_bucket["completed"] += 1
        if verification in {"confirmed", "reproduced", "fixed"}:
            category_bucket["confirmed"] += 1

    return {
        "updated_at": workbook.get("updated_at", ""),
        "summary": workbook.get("summary", ""),
        "note_count": len(workbook.get("operator_notes", [])),
        "verification_run_count": len(workbook.get("verification_runs", [])),
        "case_status": by_status,
        "verification_status": by_verification,
        "category_coverage": by_category,
    }
