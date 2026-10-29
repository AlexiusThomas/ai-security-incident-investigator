
import copy
import json
import tempfile
import unittest
from pathlib import Path

from validate_pipeline import load_json, validate_bundle

BASE = Path(__file__).parent


class TestPipelineValidation(unittest.TestCase):

    def setUp(self):
        self.incidents = load_json(
            BASE / "incidents.json"
        )
        self.investigations = load_json(
            BASE / "investigations.json"
        )
        self.report = (
            BASE / "reports" / "INV-0001.md"
        ).read_text(encoding="utf-8")

    def test_valid_pipeline(self):
        self.assertTrue(
            validate_bundle(
                self.incidents,
                self.investigations,
                self.report
            )
        )

    def test_evidence_id_mismatch(self):
        data = copy.deepcopy(self.investigations)
        data[0]["evidence"]["event_ids"] = ["wrong-id"]

        with self.assertRaises(ValueError):
            validate_bundle(
                self.incidents, data, self.report
            )

    def test_event_count_mismatch(self):
        data = copy.deepcopy(self.incidents)
        data[0]["event_count"] = 3

        with self.assertRaises(ValueError):
            validate_bundle(
                data, self.investigations, self.report
            )

    def test_missing_evidence(self):
        data = copy.deepcopy(self.investigations)
        del data[0]["evidence"]

        with self.assertRaises(ValueError):
            validate_bundle(
                self.incidents, data, self.report
            )

    def test_reversed_timeline(self):
        data = copy.deepcopy(self.incidents)
        data[0]["start_time"] = (
            "2026-10-29T10:15:00+00:00"
        )

        with self.assertRaises(ValueError):
            validate_bundle(
                data, self.investigations, self.report
            )

    def test_approval_bypass(self):
        data = copy.deepcopy(self.investigations)
        data[0]["remediation"]["executed"] = True

        with self.assertRaises(ValueError):
            validate_bundle(
                self.incidents, data, self.report
            )

    def test_report_missing_evidence(self):
        report = self.report.replace(
            "Event IDs: evt-001, evt-002",
            "Event IDs: unavailable"
        )

        with self.assertRaises(ValueError):
            validate_bundle(
                self.incidents,
                self.investigations,
                report
            )

    def test_malformed_json(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "bad.json"
            path.write_text(
                '{"event_id": ',
                encoding="utf-8"
            )

            with self.assertRaises(ValueError):
                load_json(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
