import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from lib.parsers import parse_all_results
from lib.reports import build_report_payload, generate_csv_report, generate_html_report, generate_markdown_report, generate_sarif_report


class StructuredFindingsTest(unittest.TestCase):
    def _write(self, directory: Path, name: str, payload, as_text: bool = False) -> None:
        path = directory / name
        if as_text:
            path.write_text(str(payload), encoding="utf-8")
            return
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def test_parse_all_results_emits_structured_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_dir = Path(tmp)
            self._write(
                scan_dir,
                "dalfox.json",
                {
                    "results": [
                        {
                            "type": "Reflected XSS",
                            "url": "https://example.com/search?q=test",
                            "param": "q",
                            "payload": "<svg/onload=alert(1)>",
                            "evidence": "payload reflected in response",
                            "request": "GET /search?q=test HTTP/1.1",
                            "response": "<html>...payload reflected in response...</html>",
                        }
                    ]
                },
            )
            self._write(
                scan_dir,
                "wpscan.json",
                {
                    "target_url": "https://example.com",
                    "plugins": {
                        "contact-form-7": {
                            "version": {"number": "5.3.2"},
                            "vulnerabilities": [
                                {
                                    "title": "Plugin Contact Form 7 v5.3.2 - Arbitrary File Upload",
                                    "severity": "high",
                                    "references": {"cve": ["2020-35489"], "url": ["https://wpscan.com/vulnerability/abc"]},
                                }
                            ],
                        }
                    },
                },
            )
            self._write(
                scan_dir,
                "ffuf.json",
                {
                    "results": [
                        {
                            "url": "https://example.com/admin/",
                            "status": 403,
                            "words": 10,
                            "length": 123,
                        }
                    ]
                },
            )

            findings = parse_all_results(scan_dir)
            self.assertGreaterEqual(len(findings), 3)

            by_tool = {item["source_tool"]: item for item in findings}
            dalfox = by_tool["Dalfox"]
            self.assertEqual(dalfox["url"], "https://example.com/search?q=test")
            self.assertEqual(dalfox["parameter"], "q")
            self.assertEqual(dalfox["payload"], "<svg/onload=alert(1)>")
            self.assertIn(dalfox["confidence"], {"confirmed", "detected", "weak_signal"})
            self.assertTrue(dalfox["evidence"])

            wpscan = by_tool["WPScan"]
            self.assertEqual(wpscan["component"], "plugin/contact-form-7")
            self.assertEqual(wpscan["component_version"], "5.3.2")
            self.assertTrue(wpscan["protection_target"])

            ffuf = by_tool["ffuf"]
            self.assertEqual(ffuf["path"], "/admin/")
            self.assertEqual(ffuf["confidence"], "weak_signal")
            self.assertTrue(ffuf["reproduction"])

    def test_reports_render_structured_details_and_exports(self):
        findings = [
            {
                "id": "VULN-001",
                "title": "Reflected XSS",
                "severity": "high",
                "source_tool": "Dalfox",
                "description": "Reflected payload returned in the response.",
                "evidence": "url: https://example.com/search?q=test\nparameter: q",
                "asset": "https://example.com",
                "url": "https://example.com/search?q=test",
                "path": "/search",
                "method": "GET",
                "parameter": "q",
                "payload": "<svg/onload=alert(1)>",
                "matched_evidence": "payload reflected in response",
                "reproduction": "https://example.com/search?q=%3Csvg%2Fonload%3Dalert(1)%3E",
                "protection_target": "Parameter q reflected into the response",
                "fix_target": "search handler output encoding",
                "verification_status": "reproduced",
                "confidence": "confirmed",
                "references": ["https://owasp.org/www-community/attacks/xss/"],
                "fix": "Apply contextual output encoding.",
                "fix_steps": [],
                "owasp": [],
                "mitre_attack": [],
                "cis_controls": [],
                "nist_csf": [],
            }
        ]
        payload = build_report_payload(
            findings=findings,
            target_url="https://example.com",
            scan_mode="full",
            start_time=datetime.now(timezone.utc),
            scan_overview={"tool_runs": []},
        )

        html = generate_html_report(payload)
        self.assertIn("Affected Asset", html)
        self.assertIn("Safe Verification Step", html)
        self.assertIn("Where To Protect", html)

        csv_output = generate_csv_report(payload)
        self.assertIn("verification_status", csv_output)
        self.assertIn("protection_target", csv_output)

        markdown = generate_markdown_report(payload)
        self.assertIn("- Verification: reproduced", markdown)
        self.assertIn("- Where to protect: Parameter q reflected into the response", markdown)

        sarif = generate_sarif_report(payload)
        result = sarif["runs"][0]["results"][0]
        self.assertEqual(result["properties"]["parameter"], "q")
        self.assertEqual(result["properties"]["confidence"], "confirmed")


if __name__ == "__main__":
    unittest.main()
