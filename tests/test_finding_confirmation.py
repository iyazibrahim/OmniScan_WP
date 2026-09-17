import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lib import dispositions
from lib.header_check import header_finding_is_false_positive, present_security_headers
from lib.finding_retest import apply_retest_to_finding, retest_finding
from lib.parsers import parse_all_results, _derive_confidence_status
from lib.ai_verify import recommend_findings


class DispositionAndVerifyTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)
        dispositions.DISPOSITIONS_FILE = self.tmp_path / "finding-dispositions.json"

    def test_fingerprint_stable(self):
        finding = {
            "title": "Missing Strict-Transport-Security header",
            "evidence_kind": "headers",
            "url": "https://example.com/admin",
            "path": "/admin",
            "parameter": "",
        }
        a = dispositions.fingerprint_finding(finding, "https://example.com")
        b = dispositions.fingerprint_finding(finding, "https://example.com/")
        self.assertEqual(a, b)

    def test_suppress_future_applies_on_next_scan(self):
        finding = {
            "title": "Reflected XSS",
            "evidence_kind": "xss",
            "url": "https://example.com/search?q=1",
            "path": "/search",
            "parameter": "q",
            "status": "needs_review",
        }
        dispositions.upsert_disposition(
            finding,
            "false_positive",
            target_url="https://example.com",
            suppress_future=True,
            note="manual check",
        )
        applied = dispositions.apply_dispositions_to_findings([finding], "https://example.com")
        self.assertEqual(applied[0]["status"], "false_positive")
        self.assertEqual(applied[0]["verification_status"], "false_positive")

    def test_reopen_clears_suppress(self):
        finding = {
            "title": "Open CORS",
            "evidence_kind": "cors",
            "url": "https://example.com/api",
            "path": "/api",
        }
        record = dispositions.upsert_disposition(
            finding,
            "false_positive",
            target_url="https://example.com",
            suppress_future=True,
        )
        reopened = dispositions.reopen_disposition(record["fingerprint"])
        self.assertEqual(reopened["status"], "needs_review")
        self.assertFalse(reopened["suppress_future"])

    def test_header_false_positive_when_present(self):
        finding = {"title": "The anti-clickjacking X-Frame-Options header is not present"}
        snapshot = {
            "ok": True,
            "headers": {
                "x-frame-options": "SAMEORIGIN",
                "content-security-policy": "default-src 'self'",
                "strict-transport-security": "max-age=31536000",
                "x-content-type-options": "nosniff",
            },
            "final_url": "https://example.com/",
        }
        is_fp, reason = header_finding_is_false_positive(finding, snapshot)
        self.assertTrue(is_fp)
        self.assertIn("present", reason.lower())

    def test_present_security_headers_frame_ancestors(self):
        present = present_security_headers({
            "content-security-policy": "frame-ancestors 'self'",
        })
        self.assertIn("x-frame-options", present)

    def test_dalfox_metadata_dict_not_parsed_as_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_dir = Path(tmp)
            (scan_dir / "dalfox.json").write_text(
                json.dumps({"version": "2.0", "message": "scan complete", "stats": {"total": 0}}),
                encoding="utf-8",
            )
            findings = parse_all_results(scan_dir)
            self.assertEqual([f for f in findings if f.get("source_tool") == "Dalfox"], [])

    def test_xss_confidence_not_reproduced_from_url_message(self):
        confidence, verification = _derive_confidence_status(
            {
                "evidence_kind": "xss",
                "url": "https://example.com/?q=1",
                "matched_evidence": "Possible XSS",
            }
        )
        self.assertEqual(confidence, "weak_signal")
        self.assertEqual(verification, "needs_review")

    def test_retest_headers_auto_marks_false_positive(self):
        finding = {
            "title": "Missing Strict-Transport-Security header",
            "evidence_kind": "headers",
            "url": "https://example.com/",
        }
        fake = {
            "ok": True,
            "headers": {"strict-transport-security": "max-age=31536000", "x-content-type-options": "nosniff"},
            "final_url": "https://example.com/",
            "status_code": 200,
            "error": "",
        }
        with patch("lib.finding_retest.fetch_headers", return_value=fake):
            result = retest_finding(finding, "https://example.com")
        self.assertEqual(result["auto_apply_status"], "false_positive")
        updated = apply_retest_to_finding(finding, result)
        self.assertEqual(updated["status"], "false_positive")

    def test_ai_recommend_does_not_change_status(self):
        findings = [
            {
                "id": "VULN-001",
                "title": "Reflected XSS",
                "status": "needs_review",
                "verification_status": "needs_review",
                "evidence_kind": "xss",
            }
        ]

        def fake_call(api_key, model, batch, target_url):
            return [{"id": "VULN-001", "recommendation": "false_positive", "reason": "No reflection"}]

        with patch("lib.ai_verify._get_openrouter_settings", return_value={"api_key": "x", "model": "m", "enabled": True}):
            with patch("lib.ai_verify._call_openrouter", side_effect=fake_call):
                updated = recommend_findings(findings, "https://example.com", {"ai_verify_findings": True})
        self.assertEqual(updated[0]["status"], "needs_review")
        self.assertEqual(updated[0]["ai_recommendation"], "false_positive")
        self.assertIn("reflection", updated[0]["ai_reason"].lower())


if __name__ == "__main__":
    unittest.main()
