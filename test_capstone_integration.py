
"""Day 38: End-to-end local integration tests."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from approval_workflow import (
    get_approval_request,
    verify_audit_history,
)
from capstone_integration import run_integrated_workflow


class TestIntegratedWorkflow(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.output = (
            Path(self.temp.name) / "day38"
        )

        self.rules = {
            "severities": {
                "monitored_failed_login": "HIGH",
                "failed_login": "MEDIUM",
                "default": "LOW",
            },
            "monitored_ips": ["203.0.113.10"],
        }

    @staticmethod
    def case(case_id="case-1"):

        def event(n, minute, outcome):
            return {
                "eventID": f"{case_id}-E{n}",
                "eventTime": (
                    f"2026-11-04T12:{minute:02d}:00Z"
                ),
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "synthetic_admin",
                },
                "sourceIPAddress": "203.0.113.10",
                "responseElements": {
                    "ConsoleLogin": outcome
                },
            }

        return {
            "case_id": case_id,
            "events": [
                event(1, 0, "Failure"),
                event(2, 2, "Failure"),
                event(3, 4, "Success"),
            ],
        }

    def execute(self, decisions=None, cases=None):
        if cases is None:
            cases = [self.case()]

        return run_integrated_workflow(
            cases,
            self.rules,
            decisions=decisions,
            output_dir=self.output,
        )

    def test_pending_is_default(self):
        report = self.execute()

        self.assertEqual(
            report["status"], "COMPLETE"
        )
        self.assertEqual(
            report["pending_requests"], 1
        )
        self.assertEqual(
            report["simulations_completed"], 0
        )

    def test_approved_request_simulates_only(self):
        report = self.execute({
            "case-1/FND-0001": "APPROVED"
        })

        self.assertEqual(
            report["approved_requests"], 1
        )
        self.assertEqual(
            report["simulations_completed"], 1
        )
        self.assertFalse(
            report["real_remediation_executed"]
        )

        item = (
            report["cases"][0]
            ["approval_requests"][0]
        )

        self.assertEqual(
            item["simulation_status"], "SIMULATED"
        )

    def test_denial_blocks_simulation(self):
        report = self.execute({
            "case-1/FND-0001": "DENIED"
        })

        self.assertEqual(
            report["denied_requests"], 1
        )
        self.assertEqual(
            report["simulations_completed"], 0
        )

    def test_independent_case_decisions(self):
        report = self.execute(
            {
                "case-1/FND-0001": "APPROVED",
                "case-2/FND-0001": "DENIED",
            },
            cases=[
                self.case("case-1"),
                self.case("case-2"),
            ],
        )

        self.assertEqual(
            report["cases_completed"], 2
        )
        self.assertEqual(
            report["approval_requests_created"], 2
        )
        self.assertEqual(
            report["simulations_completed"], 1
        )

    def test_invalid_decision_rejected(self):
        with self.assertRaises(ValueError):
            self.execute({
                "case-1/FND-0001": "BYPASS"
            })

    def test_invalid_case_id_rejected(self):
        with self.assertRaises(ValueError):
            self.execute(
                cases=[self.case("../invalid")]
            )

    def test_approval_audit_history_valid(self):
        report = self.execute({
            "case-1/FND-0001": "APPROVED"
        })

        root = (
            Path(report["output_directory"])
            / "agent_runs"
            / "case-1"
        )

        run_dir = next(root.glob("run-*"))

        request_id = (
            report["cases"][0]
            ["approval_requests"][0]
            ["request_id"]
        )

        approval = get_approval_request(
            run_dir,
            request_id,
        )

        self.assertTrue(
            verify_audit_history(approval)
        )
        self.assertEqual(
            len(approval["audit_history"]), 2
        )

    def test_integrated_report_saved(self):
        report = self.execute()

        path = (
            Path(report["output_directory"])
            / "integrated_report.json"
        )

        saved = json.loads(
            path.read_text(encoding="utf-8")
        )

        self.assertEqual(
            saved["approval_requests_created"], 1
        )
        self.assertFalse(
            saved["real_remediation_executed"]
        )

    def test_failed_evaluation_blocks_approval(self):
        with patch(
            "capstone_integration.evaluate_agent_run",
            return_value={"verdict": "FAIL"},
        ):
            report = self.execute({
                "case-1/FND-0001": "APPROVED"
            })

        self.assertEqual(
            report["cases"][0]["status"],
            "BLOCKED",
        )
        self.assertEqual(
            report["simulations_completed"], 0
        )
        self.assertEqual(
            report["approval_requests_created"], 0
        )


if __name__ == "__main__":
    unittest.main()
