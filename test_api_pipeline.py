
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from api_pipeline import ingest_and_save, load_events


class TestAPIPipeline(unittest.TestCase):

    @patch("api_pipeline.fetch_security_events")
    def test_ingestion(self, mock_fetch):
        mock_fetch.return_value = [
            {
                "timestamp": "2026-11-04T12:00:00Z",
                "user": "admin",
                "event_type": "login_failed",
                "severity": "HIGH"
            }
        ]

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "api_events.json"

            result = ingest_and_save(
                "https://example.com/api/events",
                output_file=output
            )

            self.assertEqual(result["total_events"], 1)
            self.assertTrue(output.exists())

            saved = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(saved, mock_fetch.return_value)

    def test_load_events(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "events.json"
            output.write_text(
                json.dumps([{"event_type": "login_failed"}]),
                encoding="utf-8"
            )

            events = load_events(output)
            self.assertEqual(len(events), 1)

    def test_invalid_event_format(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "events.json"
            output.write_text(
                json.dumps({"events": []}),
                encoding="utf-8"
            )

            with self.assertRaises(ValueError):
                load_events(output)


if __name__ == "__main__":
    unittest.main()
