
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from integrated_pipeline import run_pipeline


class TestIntegratedPipeline(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

        self.rules = self.folder / "rules.json"
        self.rules.write_text(json.dumps({
            "severities": {
                "monitored_failed_login": "HIGH",
                "failed_login": "MEDIUM",
                "default": "LOW"
            },
            "monitored_ips": ["203.0.113.10"]
        }), encoding="utf-8")

    @patch("api_pipeline.fetch_security_events")
    def test_end_to_end_incident(self, mock_fetch):
        mock_fetch.return_value = [
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

        result = run_pipeline(
            "https://example.invalid/events",
            output_dir=self.folder / "output",
            rules_file=self.rules
        )

        self.assertEqual(result["raw_events"], 2)
        self.assertEqual(result["normalized_events"], 2)
        self.assertEqual(result["alerts"], 2)
        self.assertEqual(result["incidents"], 1)

        incidents = json.loads(
            (self.folder / "output" / "incidents.json")
            .read_text(encoding="utf-8")
        )
        self.assertEqual(incidents[0]["event_count"], 2)
        self.assertEqual(
            incidents[0]["event_ids"], ["E001", "E002"]
        )

    @patch("api_pipeline.fetch_security_events")
    def test_unsupported_events_skipped(self, mock_fetch):
        mock_fetch.return_value = [
            {"source": "linux", "event_type": "login_failed"}
        ]

        result = run_pipeline(
            "https://example.invalid/events",
            output_dir=self.folder / "output",
            rules_file=self.rules
        )

        self.assertEqual(result["normalized_events"], 0)
        self.assertEqual(result["incidents"], 0)

    @patch("api_pipeline.fetch_security_events")
    def test_missing_timestamp_rejected(self, mock_fetch):
        mock_fetch.return_value = [{
            "source": "windows",
            "EventID": 4625,
            "Account": "admin",
            "IpAddress": "203.0.113.10"
        }]

        with self.assertRaises(ValueError):
            run_pipeline(
                "https://example.invalid/events",
                output_dir=self.folder / "output",
                rules_file=self.rules
            )


if __name__ == "__main__":
    unittest.main()
