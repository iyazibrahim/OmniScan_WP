"""Unit tests for tool status mapping (no live network)."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from lib.tools import (
    NUCLEI_TEMPLATES_PATH,
    _annotate_coverage,
    _nuclei_cmd,
    _nuclei_missing_templates_signal,
    _run_tool,
    run_httpx,
    run_nuclei,
    run_wpscan,
)


class ToolStatusMappingTest(unittest.TestCase):
    def test_run_httpx_uses_websocket_flag_not_ws(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_dir = Path(tmp)
            captured = {}

            def fake_run_tool(cmd, *args, **kwargs):
                captured["cmd"] = list(cmd)
                return _annotate_coverage(
                    {
                        "name": "httpx",
                        "label": "httpx",
                        "phase": "passive",
                        "command": list(cmd),
                        "status": "completed",
                        "returncode": 0,
                        "duration_seconds": 1.0,
                        "stdout_log": "",
                        "stderr_log": "",
                        "output_files": ["httpx.json"],
                        "primary_output": "httpx.json",
                        "note": "",
                    }
                )

            with patch("lib.tools._resolve_httpx_binary", return_value="/usr/local/bin/httpx"), patch(
                "lib.tools._run_tool", side_effect=fake_run_tool
            ):
                result = run_httpx("https://example.com", {"httpx_rate_limit": 40}, scan_dir)

            self.assertEqual(result["status"], "completed")
            self.assertIn("-websocket", captured["cmd"])
            self.assertNotIn("-ws", captured["cmd"])

    def test_wpscan_exit_code_5_is_completed_with_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_dir = Path(tmp)
            output_file = scan_dir / "wpscan.json"
            output_file.write_text('{"target_url":"https://example.com"}', encoding="utf-8")

            mock_proc = MagicMock()
            mock_proc.pid = 12345
            mock_proc.poll.return_value = 5
            mock_proc.returncode = 5
            mock_proc.communicate.return_value = ("", "")

            with patch("lib.tools._spawn_tool_process", return_value=mock_proc):
                result = _run_tool(
                    ["wpscan", "--url", "https://example.com"],
                    "wpscan",
                    "WPScan",
                    "passive",
                    scan_dir,
                    output_files=[output_file],
                    acceptable_returncodes={0, 5},
                )

            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["returncode"], 5)

    def test_failed_without_stderr_includes_returncode_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_dir = Path(tmp)

            mock_proc = MagicMock()
            mock_proc.pid = 12345
            mock_proc.poll.return_value = 2
            mock_proc.returncode = 2
            mock_proc.communicate.return_value = ("", "")

            with patch("lib.tools._spawn_tool_process", return_value=mock_proc):
                result = _run_tool(
                    ["httpx", "-u", "https://example.com"],
                    "httpx",
                    "httpx",
                    "passive",
                    scan_dir,
                    output_files=[scan_dir / "httpx.json"],
                    acceptable_returncodes={0, 1},
                )

            self.assertEqual(result["status"], "failed")
            self.assertIn("Exited with code 2", result.get("note", ""))
            self.assertIn("Exited with code 2", result.get("coverage_reason", ""))

    def test_nuclei_missing_templates_signal(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_dir = Path(tmp)
            stderr = scan_dir / "nuclei.stderr.log"
            stderr.write_text("Could not find template / no templates found\n", encoding="utf-8")
            result = {"note": "", "stderr_log": str(stderr), "stdout_log": ""}
            self.assertTrue(_nuclei_missing_templates_signal(result))

    def test_nuclei_cmd_pins_templates_directory(self):
        cmd = _nuclei_cmd("-u", "https://example.com", "-silent")
        self.assertEqual(cmd[0], "nuclei")
        self.assertEqual(cmd[1:3], ["-ud", NUCLEI_TEMPLATES_PATH])
        self.assertIn("-u", cmd)

    def test_run_nuclei_passes_ud_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_dir = Path(tmp)
            captured = {}

            def fake_run_tool(cmd, *args, **kwargs):
                captured["cmd"] = list(cmd)
                return _annotate_coverage(
                    {
                        "name": "nuclei",
                        "label": "Nuclei",
                        "phase": "passive",
                        "command": list(cmd),
                        "status": "completed",
                        "returncode": 0,
                        "duration_seconds": 1.0,
                        "stdout_log": "",
                        "stderr_log": "",
                        "output_files": ["nuclei.jsonl"],
                        "primary_output": "nuclei.jsonl",
                        "note": "",
                    }
                )

            with patch("lib.tools._run_tool", side_effect=fake_run_tool):
                result = run_nuclei(
                    "https://example.com",
                    {
                        "nuclei_tags": "cve",
                        "nuclei_severity": "high",
                        "nuclei_rate_limit": 10,
                        "nuclei_timeout_seconds": 60,
                        "nuclei_retry_auto_scan_on_empty": False,
                        "nuclei_retry_full_template_on_empty_full": False,
                    },
                    scan_dir,
                    "webapp",
                    scan_mode="passive",
                )

            self.assertEqual(result["status"], "completed")
            self.assertEqual(captured["cmd"][1:3], ["-ud", NUCLEI_TEMPLATES_PATH])

    def test_run_wpscan_passes_vulnerable_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan_dir = Path(tmp)
            captured = {}

            def fake_run_tool(*args, **kwargs):
                captured["acceptable_returncodes"] = kwargs.get("acceptable_returncodes")
                return _annotate_coverage(
                    {
                        "name": "wpscan",
                        "label": "WPScan",
                        "phase": "passive",
                        "command": args[0] if args else [],
                        "status": "completed",
                        "returncode": 5,
                        "duration_seconds": 1.0,
                        "stdout_log": "",
                        "stderr_log": "",
                        "output_files": ["wpscan.json"],
                        "primary_output": "wpscan.json",
                        "note": "",
                    }
                )

            with patch("lib.tools._run_tool", side_effect=fake_run_tool):
                result = run_wpscan(
                    "https://example.com",
                    {"wpscan_max_threads": 2, "wpscan_enumerate": "vp,vt,u"},
                    {},
                    scan_dir,
                    False,
                )

            self.assertEqual(captured.get("acceptable_returncodes"), {0, 5})
            self.assertEqual(result["status"], "completed")


if __name__ == "__main__":
    unittest.main()
