
import copy
import unittest
from report_incident import build_report


def sample_investigation():
    return {
        "investigation_id": "INV-0001",
        "status": "OPEN",
        "severity": "HIGH",
        "summary": "2 correlated events for user admin",
        "evidence": {
            "event_ids": ["evt-001", "evt-002"],
            "sources": ["aws", "windows"],
            "start_time": "2026-10-29T10:00:00+00:00",
            "end_time": "2026-10-29T10:02:00+00:00",
            "username": "admin",
            "source_ip": "10.0.1.5"
        },
        "recommended_steps": [
            "Review the original security events",
            "Confirm timestamps and source identities"
        ],
        "remediation": {
            "approval_status": "REQUIRED",
            "executed": False
        }
    }


class TestReporting(unittest.TestCase):

    def setUp(self):
        self.data = sample_investigation()

    def test_investigation_id(self):
        report = build_report(self.data)
        self.assertIn("INV-0001", report)

    def test_summary(self):
        report = build_report(self.data)
        self.assertIn(
            "2 correlated events for user admin",
            report
        )

    def test_evidence_ids(self):
        report = build_report(self.data)
        self.assertIn("evt-001, evt-002", report)

    def test_timeline(self):
        report = build_report(self.data)
        self.assertIn(
            "2026-10-29T10:00:00+00:00", report
        )
        self.assertIn(
            "2026-10-29T10:02:00+00:00", report
        )

    def test_approval_required(self):
        report = build_report(self.data)
        self.assertIn(
            "Approval status: REQUIRED", report
        )

    def test_not_executed(self):
        report = build_report(self.data)
        self.assertIn(
            "Remediation executed: No", report
        )

    def test_missing_evidence(self):
        data = copy.deepcopy(self.data)
        data["evidence"]["event_ids"] = []
        with self.assertRaises(ValueError):
            build_report(data)

    def test_missing_approval(self):
        data = copy.deepcopy(self.data)
        del data["remediation"]["approval_status"]
        with self.assertRaises(ValueError):
            build_report(data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
