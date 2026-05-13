"""Deterministic runner for approved AI pentest actions and verdict mapping."""

from __future__ import annotations

from datetime import datetime, UTC
from pathlib import Path
from urllib import request, error
import hashlib
import json
import time


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _assert_match(assertions: dict, status_code: int, body_text: str) -> tuple[bool, list[str]]:
    failures: list[str] = []
    status_in = assertions.get("status_in") if isinstance(assertions.get("status_in"), list) else []
    body_contains = assertions.get("body_contains") if isinstance(assertions.get("body_contains"), list) else []
    body_not_contains = assertions.get("body_not_contains") if isinstance(assertions.get("body_not_contains"), list) else []

    if status_in and status_code not in [int(x) for x in status_in if isinstance(x, (int, str)) and str(x).isdigit()]:
        failures.append(f"status {status_code} not in status_in")

    for needle in body_contains:
        token = str(needle)
        if token and token.lower() not in body_text.lower():
            failures.append(f"body missing expected token: {token[:80]}")

    for needle in body_not_contains:
        token = str(needle)
        if token and token.lower() in body_text.lower():
            failures.append(f"body unexpectedly contains token: {token[:80]}")

    return (len(failures) == 0), failures


def _derive_verdict(action: dict, status_code: int, assert_ok: bool, failures: list[str], body_text: str) -> tuple[str, str]:
    expectation = str(action.get("expectation", "vulnerable")).lower()
    if assert_ok:
        if expectation == "fixed":
            return "appears_fixed", "Assertion matched expected fixed behavior."
        return "confirmed_vulnerable", "Assertion matched expected vulnerable behavior."

    if failures:
        if expectation == "vulnerable":
            return "inconclusive", "; ".join(failures)[:280]
        return "likely_vulnerable", "; ".join(failures)[:280]

    # Fallback heuristic when no assertions are provided.
    if expectation == "vulnerable" and status_code < 400 and body_text.strip():
        return "likely_vulnerable", "Response indicates behavior consistent with exploit attempt."
    if expectation == "fixed" and status_code >= 400:
        return "appears_fixed", "Response indicates access/control is enforced."
    return "inconclusive", "No strong assertion signal available."


def execute_actions(actions: list[dict], requests_per_minute: int = 30, timeout_seconds: int = 20) -> dict:
    rpm = max(1, int(requests_per_minute))
    min_interval = 60.0 / rpm

    results: list[dict] = []
    last_sent_at = 0.0

    for action in actions:
        if not action.get("approved"):
            continue

        now = time.perf_counter()
        if (now - last_sent_at) < min_interval:
            time.sleep(min_interval - (now - last_sent_at))

        method = str(action.get("method", "GET")).upper()
        url = str(action.get("url", "")).strip()
        headers = dict(action.get("headers") or {})
        payload = None
        if action.get("json") is not None:
            payload = json.dumps(action["json"]).encode("utf-8")
            headers.setdefault("Content-Type", "application/json")
        elif action.get("body"):
            payload = str(action.get("body", "")).encode("utf-8")

        req = request.Request(url=url, method=method, data=payload, headers=headers)
        started_at = _now_iso()
        status_code = 0
        response_headers = {}
        body_text = ""
        error_text = ""
        duration_ms = 0

        t0 = time.perf_counter()
        try:
            with request.urlopen(req, timeout=timeout_seconds) as resp:
                status_code = int(resp.getcode() or 0)
                response_headers = dict(resp.headers.items())
                body_text = (resp.read() or b"").decode("utf-8", errors="ignore")[:20000]
        except error.HTTPError as exc:
            status_code = int(exc.code or 0)
            response_headers = dict(exc.headers.items()) if exc.headers else {}
            body_text = (exc.read() or b"").decode("utf-8", errors="ignore")[:20000]
            error_text = str(exc)
        except Exception as exc:
            error_text = str(exc)
        duration_ms = int((time.perf_counter() - t0) * 1000)
        last_sent_at = time.perf_counter()

        assert_ok, failures = _assert_match(action.get("assert", {}), status_code, body_text)
        verdict, rationale = _derive_verdict(action, status_code, assert_ok, failures, body_text)

        body_hash = hashlib.sha256(body_text.encode("utf-8", errors="ignore")).hexdigest() if body_text else ""
        results.append(
            {
                "action_id": action.get("id", ""),
                "finding_id": action.get("finding_id", ""),
                "finding_title": action.get("finding_title", ""),
                "started_at": started_at,
                "method": method,
                "url": url,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "response_headers": response_headers,
                "body_excerpt": body_text[:2000],
                "body_sha256": body_hash,
                "error": error_text,
                "assert_ok": assert_ok,
                "assert_failures": failures,
                "verdict": verdict,
                "rationale": rationale,
            }
        )

    return {
        "executed_at": _now_iso(),
        "result_count": len(results),
        "results": results,
        "verdict_counts": {
            "confirmed_vulnerable": sum(1 for r in results if r.get("verdict") == "confirmed_vulnerable"),
            "likely_vulnerable": sum(1 for r in results if r.get("verdict") == "likely_vulnerable"),
            "inconclusive": sum(1 for r in results if r.get("verdict") == "inconclusive"),
            "appears_fixed": sum(1 for r in results if r.get("verdict") == "appears_fixed"),
        },
    }


def persist_evidence(scan_dir: Path | None, execution: dict) -> dict:
    if scan_dir is None:
        return {"evidence_file": "", "actions_file": ""}
    scan_dir.mkdir(parents=True, exist_ok=True)
    evidence_path = scan_dir / "ai-evidence.jsonl"
    actions_path = scan_dir / "ai-actions.json"

    results = execution.get("results", [])
    with evidence_path.open("a", encoding="utf-8") as f:
        for row in results:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    actions_path.write_text(json.dumps(execution, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"evidence_file": str(evidence_path), "actions_file": str(actions_path)}


def apply_verdicts_to_findings(findings: list[dict], ai_results: list[dict]) -> list[dict]:
    by_finding_id: dict[str, list[dict]] = {}
    by_title: dict[str, list[dict]] = {}
    for result in ai_results:
        fid = str(result.get("finding_id", "")).strip()
        title = str(result.get("finding_title", "")).strip().lower()
        if fid:
            by_finding_id.setdefault(fid, []).append(result)
        if title:
            by_title.setdefault(title, []).append(result)

    for finding in findings:
        fid = str(finding.get("id", "")).strip()
        title_key = str(finding.get("title", "")).strip().lower()
        matched = by_finding_id.get(fid) or by_title.get(title_key) or []
        if not matched:
            continue

        # Prioritize strongest verdict seen for the finding.
        priority = {
            "confirmed_vulnerable": 4,
            "likely_vulnerable": 3,
            "appears_fixed": 2,
            "inconclusive": 1,
        }
        best = sorted(matched, key=lambda r: priority.get(str(r.get("verdict", "")), 0), reverse=True)[0]
        verdict = str(best.get("verdict", "inconclusive"))
        finding["ai_verdict"] = verdict
        finding["ai_verdict_rationale"] = str(best.get("rationale", ""))
        finding["ai_last_tested_at"] = str(best.get("started_at", ""))

        if verdict == "confirmed_vulnerable":
            finding["verification_status"] = "confirmed"
            finding["status"] = "verified"
            finding["confidence"] = "confirmed"
        elif verdict == "likely_vulnerable":
            finding["verification_status"] = "reproduced"
            finding["status"] = "in_progress"
            finding["confidence"] = "probable"
        elif verdict == "appears_fixed":
            finding["verification_status"] = "fixed"
            finding["status"] = "fixed"
            finding["confidence"] = "probable"
        else:
            finding.setdefault("verification_status", "not_verified")
            finding["confidence"] = "possible"

        evidence_excerpt = str(best.get("body_excerpt", ""))
        if evidence_excerpt:
            finding["evidence"] = (finding.get("evidence", "") + "\n\nAI verification evidence:\n" + evidence_excerpt[:800]).strip()

    return findings
