
import unittest
from investigate import create_investigation


def sample_incident():
    return {
        "username": "admin",
        "source_ip": "10.0.1.5",
        "severity": "HIGH",
        "event_count": 2,
        "event_ids": ["evt-001", "evt-002"],
        "start_time": "2026-10-29T10:00:00+00:00",
        "end_time": "2026-10-29T10:02:00+00:00",
        "sources": ["aws", "windows"]
    }


class TestInvestigation(unittest.TestCase):

    def test_investigation_id(self):
        result = create_investigation(
            sample_incident(), 1
        )
        self.assertEqual(
            result["investigation_id"], "INV-0001"
        )

    def test_initial_status(self):
        result = create_investigation(
            sample_incident(), 1
        )
        self.assertEqual(result["status"], "OPEN")

    def test_severity(self):
        result = create_investigation(
            sample_incident(), 1
        )
        self.assertEqual(result["severity"], "HIGH")

    def test_evidence(self):
        result = create_investigation(
            sample_incident(), 1
        )
        self.assertEqual(
            result["evidence"]["event_ids"],
            ["evt-001", "evt-002"]
        )

    def test_approval_required(self):
        result = create_investigation(
            sample_incident(), 1
        )
        self.assertEqual(
            result["remediation"]["approval_status"],
            "REQUIRED"
        )

    def test_not_executed(self):
        result = create_investigation(
            sample_incident(), 1
        )
        self.assertFalse(
            result["remediation"]["executed"]
        )

    def test_missing_evidence(self):
        incident = sample_incident()
        incident["event_ids"] = []
        with self.assertRaises(ValueError):
            create_investigation(incident, 1)

    def test_invalid_event_count(self):
        incident = sample_incident()
        incident["event_count"] = 3
        with self.assertRaises(ValueError):
            create_investigation(incident, 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
