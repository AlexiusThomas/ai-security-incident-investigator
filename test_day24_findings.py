
import json
import tempfile
import unittest
from pathlib import Path

from day24_findings import run_day24


def cloudtrail_event(event_id, minute, outcome, user="admin"):
    return {
        "eventID": event_id,
        "eventTime": f"2026-11-04T12:{minute:02d}:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "userIdentity": {
            "type": "IAMUser",
            "userName": user,
        },
        "sourceIPAddress": "203.0.113.10",
        "responseElements": {
            "ConsoleLogin": outcome,
        },
    }


class TestDay24Findings(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.output = Path(self.temp.name) / "output"

        self.rules = {
            "severities": {
                "monitored_failed_login": "HIGH",
                "failed_login": "MEDIUM",
                "default": "LOW",
            },
            "monitored_ips": ["203.0.113.10"],
        }

        self.events = [
            cloudtrail_event("AWS-001", 0, "Failure"),
            cloudtrail_event("AWS-002", 2, "Failure"),
            cloudtrail_event("AWS-003", 4, "Success"),
        ]

    def test_generates_security_finding(self):
        result = run_day24(
            self.events, self.rules, self.output
        )

        self.assertEqual(result["cloudtrail_events"], 3)
        self.assertEqual(result["sequence_findings"], 1)
        self.assertEqual(result["reports"], 1)

        findings = json.loads(
            (self.output / "findings.json").read_text()
        )
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertFalse(findings[0]["confirmed_compromise"])
        self.assertFalse(
            findings[0]["remediation"]["executed"]
        )

    def test_report_generated(self):
        run_day24(self.events, self.rules, self.output)

        report = self.output / "reports" / "FND-0001.md"
        self.assertTrue(report.exists())

        content = report.read_text()
        self.assertIn("AWS-001", content)
        self.assertIn("AWS-003", content)
        self.assertIn("Approval required: Yes", content)

    def test_no_sequence_no_report(self):
        result = run_day24(
            self.events[:2], self.rules, self.output
        )

        self.assertEqual(result["sequence_findings"], 0)
        self.assertEqual(result["reports"], 0)


if __name__ == "__main__":
    unittest.main()

