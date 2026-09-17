"""Deterministic live retests for checkable finding evidence kinds."""

from __future__ import annotations

from datetime import datetime, UTC
from urllib import error, request
from urllib.parse import urlparse
import ssl

from lib.header_check import (
    canonical_target_url,
    fetch_headers,
    header_finding_is_false_positive,
)


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _opener():
    ctx = ssl.create_default_context()
    return request.build_opener(request.HTTPSHandler(context=ctx), request.HTTPHandler())


def _http_request(url: str, method: str = "GET", headers: dict | None = None, timeout: int = 12) -> dict:
    target = str(url or "").strip()
    if not target:
        return {"ok": False, "status_code": 0, "body": "", "headers": {}, "error": "empty url", "final_url": ""}
    if "://" not in target:
        target = f"https://{target}"
    req = request.Request(
        target,
        method=method.upper(),
        headers={
            "User-Agent": "DP-Security-Platform-Retest/1.0",
            **(headers or {}),
        },
    )
    try:
        with _opener().open(req, timeout=timeout) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            return {
                "ok": True,
                "status_code": int(getattr(resp, "status", 0) or 0),
                "body": body,
                "headers": {str(k).lower(): str(v) for k, v in resp.headers.items()},
                "error": "",
                "final_url": str(resp.geturl() or target),
            }
    except error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(65536).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {
            "ok": True,
            "status_code": int(exc.code or 0),
            "body": body,
            "headers": {str(k).lower(): str(v) for k, v in (exc.headers.items() if exc.headers else [])},
            "error": "",
            "final_url": target,
        }
    except Exception as exc:
        return {"ok": False, "status_code": 0, "body": "", "headers": {}, "error": str(exc)[:240], "final_url": target}


def _finding_url(finding: dict, target_url: str = "") -> str:
    for key in ("url", "endpoint", "reproduction", "asset"):
        value = str(finding.get(key) or "").strip()
        if value.startswith("http://") or value.startswith("https://"):
            return value
    path = str(finding.get("path") or "").strip()
    base = str(target_url or "").strip()
    if base and path:
        if "://" not in base:
            base = f"https://{base}"
        parsed = urlparse(base)
        return f"{parsed.scheme}://{parsed.netloc}{path if path.startswith('/') else '/' + path}"
    return canonical_target_url(target_url, finding)


def retest_finding(finding: dict, target_url: str = "") -> dict:
    """Return a retest result dict. May recommend status changes for checkable kinds."""
    kind = str(finding.get("evidence_kind") or "").strip().lower()
    title = str(finding.get("title") or "")
    result = {
        "checked_at": _now_iso(),
        "evidence_kind": kind,
        "outcome": "needs_review",
        "reason": "",
        "snapshot": {},
        "auto_apply_status": None,
    }

    if kind == "headers" or "header" in title.lower() or "hsts" in title.lower() or "csp" in title.lower():
        url = canonical_target_url(target_url, finding)
        snapshot = fetch_headers(url)
        result["snapshot"] = snapshot
        is_fp, reason = header_finding_is_false_positive(finding, snapshot)
        result["reason"] = reason
        if is_fp:
            result["outcome"] = "false_positive"
            result["auto_apply_status"] = "false_positive"
        else:
            result["outcome"] = "needs_review"
        return result

    if kind in {"exposure", "content"}:
        url = _finding_url(finding, target_url)
        snapshot = _http_request(url, method="GET")
        result["snapshot"] = {
            "url": url,
            "status_code": snapshot.get("status_code"),
            "final_url": snapshot.get("final_url"),
            "error": snapshot.get("error"),
        }
        code = int(snapshot.get("status_code") or 0)
        if snapshot.get("ok") and code in {404, 410}:
            result["outcome"] = "false_positive"
            result["auto_apply_status"] = "false_positive"
            result["reason"] = f"Reported URL returned HTTP {code}"
        elif not snapshot.get("ok"):
            result["outcome"] = "needs_review"
            result["reason"] = snapshot.get("error") or "request failed"
        else:
            result["outcome"] = "needs_review"
            result["reason"] = f"URL still reachable (HTTP {code})"
        return result

    if kind == "cors":
        url = _finding_url(finding, target_url) or canonical_target_url(target_url, finding)
        snapshot = _http_request(
            url,
            method="OPTIONS",
            headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "GET"},
        )
        acao = str((snapshot.get("headers") or {}).get("access-control-allow-origin") or "")
        result["snapshot"] = {"url": url, "acao": acao, "status_code": snapshot.get("status_code")}
        if snapshot.get("ok") and acao not in {"*", "https://evil.example"}:
            result["outcome"] = "false_positive"
            result["auto_apply_status"] = "false_positive"
            result["reason"] = f"ACAO is not open ({acao or 'missing'})"
        else:
            result["outcome"] = "needs_review"
            result["reason"] = f"ACAO={acao or 'missing'}"
        return result

    if kind in {"xss", "injection"}:
        url = _finding_url(finding, target_url)
        payload = str(finding.get("payload") or "").strip()
        matched = str(finding.get("matched_evidence") or finding.get("evidence") or "").strip()
        if not url or not payload:
            result["outcome"] = "needs_review"
            result["reason"] = "Missing URL or payload for safe replay"
            return result
        snapshot = _http_request(url, method=str(finding.get("method") or "GET").upper())
        body = str(snapshot.get("body") or "")
        reflected = bool(payload) and payload[:40] in body
        result["snapshot"] = {
            "url": url,
            "status_code": snapshot.get("status_code"),
            "reflected": reflected,
            "error": snapshot.get("error"),
        }
        if snapshot.get("ok") and not reflected:
            result["outcome"] = "needs_review"
            result["reason"] = "Payload not reflected on replay; recommend false_positive review"
            result["ai_hint"] = "false_positive"
        elif reflected:
            result["outcome"] = "needs_review"
            result["reason"] = "Payload reflection observed; operator confirmation required"
            result["ai_hint"] = "confirmed"
        else:
            result["outcome"] = "needs_review"
            result["reason"] = snapshot.get("error") or matched or "replay inconclusive"
        return result

    if kind == "tls":
        url = canonical_target_url(target_url, finding)
        snapshot = fetch_headers(url)
        result["snapshot"] = snapshot
        result["outcome"] = "needs_review"
        result["reason"] = "TLS findings require operator review of certificate/protocol evidence"
        return result

    result["outcome"] = "needs_review"
    result["reason"] = f"No deterministic live check for evidence_kind={kind or 'unknown'}"
    return result


def apply_retest_to_finding(finding: dict, retest: dict) -> dict:
    row = dict(finding)
    row["last_retest"] = {
        "checked_at": retest.get("checked_at"),
        "outcome": retest.get("outcome"),
        "reason": retest.get("reason"),
        "snapshot": retest.get("snapshot") or {},
    }
    auto_status = retest.get("auto_apply_status")
    if auto_status == "false_positive":
        row["status"] = "false_positive"
        row["verification_status"] = "false_positive"
        row["retest_source"] = "auto_retest"
    elif not str(row.get("status") or "").strip():
        row["status"] = "needs_review"
    if retest.get("ai_hint") and not row.get("ai_recommendation"):
        row["ai_hint"] = retest.get("ai_hint")
    return row


def retest_findings(findings: list[dict], target_url: str = "") -> list[dict]:
    updated = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        kind = str(finding.get("evidence_kind") or "").strip().lower()
        title = str(finding.get("title") or "").lower()
        should_check = kind in {"headers", "exposure", "content", "cors", "xss", "injection", "tls"} or any(
            token in title for token in ("header", "hsts", "csp", "cors", "xss")
        )
        if not should_check:
            row = dict(finding)
            if not str(row.get("status") or "").strip():
                row["status"] = "needs_review"
            updated.append(row)
            continue
        retest = retest_finding(finding, target_url=target_url)
        updated.append(apply_retest_to_finding(finding, retest))
    return updated
