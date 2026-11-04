
"""Day 31: Local security agent orchestration tests."""

import json
import tempfile
import unittest
from pathlib import Path

from local_security_agent import (
    LocalSecurityAgent,
    run_security_agent
)


def make_event(event_id, minute, outcome, user="admin"):
    return {
        "eventID": event_id,
        "eventTime": f"2026-11-04T12:{minute:02d}:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "userIdentity": {
            "type": "IAMUser",
            "userName": user
        },
        "sourceIPAddress": "203.0.113.10",
        "responseElements": {
            "ConsoleLogin": outcome
        }
    }


class TestLocalSecurityAgent(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)

        self.events = [
            make_event("AWS-001", 0, "Failure"),
            make_event("AWS-002", 2, "Failure"),
            make_event("AWS-003", 4, "Success"),
        ]

        self.rules = {
            "severities": {
                "monitored_failed_login": "HIGH",
                "failed_login": "MEDIUM",
                "default": "LOW"
            },
            "monitored_ips": ["203.0.113.10"]
        }

    def execute_workflow(self, events=None, **kwargs):
        return run_security_agent(
            self.events if events is None else events,
            self.rules,
            output_dir=self.root,
            **kwargs
        )

    def test_complete_pipeline(self):
        result = self.execute_workflow()

        self.assertEqual(result["status"], "COMPLETE")
        self.assertEqual(result["security_findings"], 1)
        self.assertEqual(result["ai_reports"], 1)

    def test_report_saved(self):
        result = self.execute_workflow()

        report = Path(result["report_files"][0])
        self.assertTrue(report.exists())

        data = json.loads(report.read_text(encoding="utf-8"))

        self.assertEqual(
            data["report"]["evidence_event_ids"],
            ["AWS-001", "AWS-002", "AWS-003"]
        )

    def test_audit_trail(self):
        result = self.execute_workflow()

        tools = [
            item["tool"]
            for item in result["audit_trail"]
        ]

        self.assertEqual(
            tools,
            ["detect", "store_evidence", "summarize"]
        )

        self.assertTrue(all(
            item["status"] == "SUCCESS"
            for item in result["audit_trail"]
        ))

    def test_no_security_finding(self):
        result = self.execute_workflow(
            events=self.events[:1]
        )

        self.assertEqual(result["security_findings"], 0)
        self.assertEqual(result["ai_reports"], 0)

    def test_blocks_unauthorized_tool(self):
        agent = LocalSecurityAgent(self.root)

        with self.assertRaises(PermissionError):
            agent.execute("disable_iam_account")

        self.assertEqual(
            agent.audit[-1]["status"], "DENIED"
        )

    def test_enforces_step_limit(self):
        with self.assertRaises(RuntimeError):
            self.execute_workflow(max_steps=2)

    def test_tampered_evidence_blocked(self):
        agent = LocalSecurityAgent(self.root)

        finding = {
            "finding_id": "FND-0001",
            "severity": "HIGH",
            "username": "admin",
            "source_ip": "203.0.113.10",
            "evidence": {
                "failed_event_ids": ["AWS-001", "AWS-002"],
                "success_event_id": "AWS-003",
                "start_time": "2026-11-04T12:00:00Z",
                "success_time": "2026-11-04T12:04:00Z"
            }
        }

        agent.execute("store_evidence", finding=finding)

        path = (
            self.root / "local_s3"
            / "objects" / "FND-0001.json"
        )

        path.write_text(
            '{"severity": "LOW"}',
            encoding="utf-8"
        )

        with self.assertRaises(ValueError):
            agent.execute(
                "summarize",
                evidence_id="FND-0001"
            )

    def test_remediation_never_executed(self):
        result = self.execute_workflow()

        self.assertFalse(result["remediation_executed"])
        self.assertTrue(result["analyst_review_required"])


if __name__ == "__main__":
    unittest.main()
