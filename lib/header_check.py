"""Live HTTP security-header checks against a canonical URL."""

from __future__ import annotations

from urllib import error, request
from urllib.parse import urljoin, urlparse
import ssl


SECURITY_HEADERS = {
    "strict-transport-security": ("hsts", "strict-transport-security", "hsts"),
    "content-security-policy": ("content-security-policy", "csp"),
    "x-content-type-options": ("x-content-type-options", "nosniff"),
    "x-frame-options": ("x-frame-options", "frame-options", "clickjacking"),
    "referrer-policy": ("referrer-policy",),
    "permissions-policy": ("permissions-policy", "feature-policy"),
}


def _build_opener():
    ctx = ssl.create_default_context()
    return request.build_opener(request.HTTPSHandler(context=ctx), request.HTTPHandler())


def fetch_headers(url: str, timeout: int = 12) -> dict:
    """GET the URL (follow redirects) and return lowercase header map + final URL."""
    target = str(url or "").strip()
    if not target:
        return {"ok": False, "error": "empty url", "headers": {}, "final_url": "", "status_code": 0}
    if "://" not in target:
        target = f"https://{target}"

    opener = _build_opener()
    req = request.Request(
        target,
        method="GET",
        headers={
            "User-Agent": "DP-Security-Platform-HeaderCheck/1.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
    )
    try:
        with opener.open(req, timeout=timeout) as resp:
            headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
            return {
                "ok": True,
                "error": "",
                "headers": headers,
                "final_url": str(resp.geturl() or target),
                "status_code": int(getattr(resp, "status", 0) or 0),
            }
    except error.HTTPError as exc:
        headers = {str(k).lower(): str(v) for k, v in (exc.headers.items() if exc.headers else [])}
        return {
            "ok": True,
            "error": "",
            "headers": headers,
            "final_url": str(exc.geturl() if hasattr(exc, "geturl") else target),
            "status_code": int(exc.code or 0),
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:240], "headers": {}, "final_url": target, "status_code": 0}


def present_security_headers(headers: dict) -> dict[str, str]:
    present = {}
    for name in SECURITY_HEADERS:
        value = str(headers.get(name) or "").strip()
        if value:
            present[name] = value
    # CSP frame-ancestors can substitute for X-Frame-Options.
    csp = str(headers.get("content-security-policy") or "").lower()
    if "frame-ancestors" in csp and "x-frame-options" not in present:
        present["x-frame-options"] = "frame-ancestors (via CSP)"
    return present


def claimed_missing_headers(text: str) -> list[str]:
    blob = str(text or "").lower()
    claimed = []
    for header_name, tokens in SECURITY_HEADERS.items():
        if header_name in blob or any(token in blob for token in tokens):
            claimed.append(header_name)
    return claimed


def header_finding_is_false_positive(finding: dict, header_snapshot: dict) -> tuple[bool, str]:
    if not header_snapshot.get("ok"):
        return False, header_snapshot.get("error") or "header fetch failed"
    headers = header_snapshot.get("headers") or {}
    present = present_security_headers(headers)
    text = " ".join(
        [
            str(finding.get("title") or ""),
            str(finding.get("description") or ""),
            str(finding.get("matched_evidence") or ""),
            str(finding.get("evidence") or ""),
        ]
    )
    claimed = claimed_missing_headers(text)
    if not claimed:
        # Generic "missing security headers" with several present → treat as FP.
        if "header" in text.lower() and len(present) >= 4:
            return True, f"Multiple security headers present on {header_snapshot.get('final_url')}: {', '.join(sorted(present))}"
        return False, "no specific missing header claimed"

    missing = [name for name in claimed if name not in present]
    if not missing:
        return True, f"Claimed headers are present: {', '.join(claimed)}"
    return False, f"Still missing: {', '.join(missing)}"


def canonical_target_url(target_url: str, finding: dict | None = None) -> str:
    if finding:
        for key in ("url", "endpoint", "asset"):
            value = str(finding.get(key) or "").strip()
            if value.startswith("http://") or value.startswith("https://"):
                parsed = urlparse(value)
                if parsed.scheme and parsed.netloc:
                    return f"{parsed.scheme}://{parsed.netloc}/"
    base = str(target_url or "").strip()
    if not base:
        return ""
    if "://" not in base:
        base = f"https://{base}"
    parsed = urlparse(base)
    if not parsed.netloc:
        return base
    return f"{parsed.scheme}://{parsed.netloc}/"
