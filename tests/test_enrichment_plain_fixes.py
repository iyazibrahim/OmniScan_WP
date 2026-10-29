"""Enrichment should attach concrete fix steps for common header/info findings."""

import unittest

from lib.enrichment import enrich_findings


class EnrichmentPlainFixesTest(unittest.TestCase):
    def test_link_header_finding_gets_concrete_steps(self):
        findings = enrich_findings(
            [
                {
                    "title": 'Link header(s) found with value(s): <https://example.com/wp-json/>; rel="https://api.w.org/"',
                    "description": "Nikto informational header",
                    "severity": "info",
                    "source_tool": "Nikto",
                    "fix": "",
                    "fix_steps": [],
                }
            ]
        )
        finding = findings[0]
        self.assertTrue(finding.get("fix_steps"))
        self.assertNotEqual(
            finding.get("fix"),
            "Review this finding manually and apply appropriate security measures.",
        )

    def test_litespeed_header_maps_to_info_category(self):
        findings = enrich_findings(
            [
                {
                    "title": "Uncommon header(s) 'x-litespeed-cache' found, with contents: hit.",
                    "description": "Uncommon header(s) 'x-litespeed-cache' found, with contents: hit.",
                    "severity": "info",
                    "source_tool": "Nikto",
                    "fix": "",
                    "fix_steps": [],
                }
            ]
        )
        finding = findings[0]
        self.assertIn("header", finding.get("fix", "").lower())
        self.assertGreaterEqual(len(finding.get("fix_steps") or []), 2)


if __name__ == "__main__":
    unittest.main()
