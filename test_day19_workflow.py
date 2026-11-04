
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from day19_workflow import complete_workflow


class TestDay19Workflow(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.base = Path(self.temp.name)
        self.output = self.base / "output"
        self.rules = self.base / "rules.json"

        self.rules.write_text(json.dumps({
            "severities": {
                "monitored_failed_login": "HIGH",
                "failed_login": "MEDIUM",
                "default": "LOW"
            },
            "monitored_ips": ["203.0.113.10"]
        }), encoding="utf-8")

    def run_with_events(self, mock_fetch, events):
        mock_fetch.return_value = events

        return complete_workflow(
            "https://example.invalid/events",
            output_dir=self.output,
            rules_file=self.rules
        )

    @patch("api_pipeline.fetch_security_events")
    def test_full_incident_report(self, mock_fetch):
        events = [
            {
                "id": "E001",
                "source": "windows",
                "EventID": 4625,
                "Account": "admin",
                "IpAddress": "203.0.113.10",
                "timestamp": "2026-11-04T12:00:00Z"
            },
            {
                "id": "E002",
                "source": "aws",
                "eventName": "ConsoleLogin",
                "errorMessage": "Failed authentication",
                "userIdentity": "admin",
                "sourceIPAddress": "203.0.113.10",
                "eventTime": "2026-11-04T12:02:00Z"
            }
        ]

        result = self.run_with_events(mock_fetch, events)

        self.assertEqual(result["incidents"], 1)
        self.assertEqual(result["investigations"], 1)
        self.assertEqual(result["reports"], 1)

        report_path = self.output / "reports" / "INV-0001.md"

        self.assertTrue(report_path.exists())

        report = report_path.read_text(encoding="utf-8")

        self.assertIn("Security Investigation Report", report)
        self.assertIn("E001", report)
        self.assertIn("E002", report)
        self.assertIn("Approval status: REQUIRED", report)
        self.assertIn("Remediation executed: No", report)

    @patch("api_pipeline.fetch_security_events")
    def test_no_incident(self, mock_fetch):
        events = [{
            "id": "E001",
            "source": "windows",
            "EventID": 4625,
            "Account": "admin",
            "IpAddress": "203.0.113.10",
            "timestamp": "2026-11-04T12:00:00Z"
        }]

        result = self.run_with_events(mock_fetch, events)

        self.assertEqual(result["incidents"], 0)
        self.assertEqual(result["investigations"], 0)
        self.assertEqual(result["reports"], 0)

    @patch("api_pipeline.fetch_security_events")
    def test_invalid_timestamp(self, mock_fetch):
        events = [{
            "id": "E001",
            "source": "windows",
            "EventID": 4625,
            "Account": "admin",
            "IpAddress": "203.0.113.10"
        }]

        with self.assertRaises(ValueError):
            self.run_with_events(mock_fetch, events)


if __name__ == "__main__":
    unittest.main()
