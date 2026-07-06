import tempfile
import unittest
from pathlib import Path

import lib.monitoring as monitoring


class MonitoringTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        base = Path(self.tmp.name)
        self.original_paths = {
            "MODULES_FILE": monitoring.MODULES_FILE,
            "MONITORING_ASSETS_FILE": monitoring.MONITORING_ASSETS_FILE,
            "MONITORING_SETTINGS_FILE": monitoring.MONITORING_SETTINGS_FILE,
            "MONITORING_STATE_FILE": monitoring.MONITORING_STATE_FILE,
            "MONITORING_EVENTS_FILE": monitoring.MONITORING_EVENTS_FILE,
            "HEARTBEAT_STATE_FILE": monitoring.HEARTBEAT_STATE_FILE,
        }
        monitoring.MODULES_FILE = base / "modules.json"
        monitoring.MONITORING_ASSETS_FILE = base / "monitoring-assets.json"
        monitoring.MONITORING_SETTINGS_FILE = base / "monitoring-settings.json"
        monitoring.MONITORING_STATE_FILE = base / "monitoring-state.json"
        monitoring.MONITORING_EVENTS_FILE = base / "monitoring-events.json"
        monitoring.HEARTBEAT_STATE_FILE = base / "heartbeat-state.json"

    def tearDown(self):
        for key, value in self.original_paths.items():
            setattr(monitoring, key, value)
        self.tmp.cleanup()

    def test_default_modules_disable_playbook_and_enable_monitoring(self):
        modules = monitoring.get_modules()
        self.assertFalse(modules["assessments"])
        self.assertTrue(modules["monitoring"])

    def test_receive_heartbeat_updates_state_and_summary(self):
        service = monitoring.MonitoringService()
        asset = service.upsert_asset(
            {
                "label": "Office NUC",
                "asset_type": "heartbeat_agent",
                "site_name": "HQ",
                "expected_heartbeat_seconds": 60,
                "metadata": {"agent_id": "office-nuc-01", "agent_secret": "secret-1"},
            }
        )
        heartbeat = service.receive_heartbeat(
            {
                "agent_id": "office-nuc-01",
                "agent_secret": "secret-1",
                "hostname": "office-nuc",
                "site_name": "HQ",
                "local_ip": "192.168.1.10",
                "metrics": {"disk_free_mb": 1000},
            }
        )

        self.assertEqual(heartbeat["agent_id"], "office-nuc-01")
        summary = service.snapshot()
        self.assertEqual(summary["overview"]["healthy_assets"], 1)
        self.assertTrue(summary["status_breakdown"])
        state = next(item["state"] for item in summary["assets"] if item["id"] == asset["id"])
        self.assertEqual(state["status"], "healthy")
        self.assertEqual(state["source"], "heartbeat")
        self.assertIn("next_check_due_at", state)
        self.assertIn("check_interval_seconds", state)
        self.assertIn("uptime_trend", summary)
        self.assertIn("incident_trend", summary)

    def test_asset_validation_rejects_missing_heartbeat_agent_id(self):
        with self.assertRaises(ValueError):
            monitoring.normalize_asset({"label": "Bad Agent", "asset_type": "heartbeat_agent"})


if __name__ == "__main__":
    unittest.main()
