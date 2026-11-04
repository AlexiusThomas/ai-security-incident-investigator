
"""Day 33: Local human approval and audit security tests."""

import json
import tempfile
import unittest
from pathlib import Path

from evidence_store import save_evidence
from approval_workflow import (
    create_approval_request,
    decide_approval_request,
    get_approval_request,
    verify_audit_history,
)


class TestApprovalWorkflow(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)
        self.evidence_id = "FND-0001"

        self.finding = {
            "finding_id": self.evidence_id,
            "severity": "HIGH",
            "evidence": {
                "failed_event_ids": ["E001", "E002"]
            },
        }

        save_evidence(
            self.root / "local_s3",
            self.evidence_id,
            self.finding,
        )

    def request(self):
        return create_approval_request(
            self.root,
            self.evidence_id,
            "REVOKE_SESSIONS",
            "analyst1",
            "Investigate simulated suspicious account activity",
        )

    def test_request_starts_pending(self):
        record = self.request()

        self.assertEqual(record["status"], "PENDING")
        self.assertFalse(record["action_executed"])

    def test_approval_recorded_no_execution(self):
        record = self.request()

        result = decide_approval_request(
            self.root,
            record["request_id"],
            "reviewer1",
            "APPROVED",
            "Approved for a future local-only simulation",
        )

        self.assertEqual(result["status"], "APPROVED")
        self.assertFalse(result["action_executed"])
        self.assertTrue(verify_audit_history(result))

    def test_denial_recorded(self):
        record = self.request()

        result = decide_approval_request(
            self.root,
            record["request_id"],
            "reviewer1",
            "DENIED",
            "Evidence requires additional review",
        )

        self.assertEqual(result["status"], "DENIED")

    def test_unauthorized_requester_blocked(self):
        with self.assertRaises(PermissionError):
            create_approval_request(
                self.root,
                self.evidence_id,
                "REVOKE_SESSIONS",
                "observer1",
                "Want to run a simulated action",
            )

    def test_unauthorized_approver_blocked(self):
        record = self.request()

        with self.assertRaises(PermissionError):
            decide_approval_request(
                self.root,
                record["request_id"],
                "analyst1",
                "APPROVED",
                "Trying to approve my own requested action",
            )

    def test_unlisted_action_blocked(self):
        with self.assertRaises(PermissionError):
            create_approval_request(
                self.root,
                self.evidence_id,
                "DELETE_ALL_LOGS",
                "analyst1",
                "Testing forbidden security operations",
            )

    def test_repeated_decision_blocked(self):
        record = self.request()

        decide_approval_request(
            self.root,
            record["request_id"],
            "reviewer1",
            "DENIED",
            "Not enough justification for the action",
        )

        with self.assertRaises(ValueError):
            decide_approval_request(
                self.root,
                record["request_id"],
                "reviewer2",
                "APPROVED",
                "Attempting to reverse a previous decision",
            )

    def test_tampered_audit_detected(self):
        record = self.request()

        path = (
            self.root / "approvals"
            / f"{record['request_id']}.json"
        )

        changed = json.loads(
            path.read_text(encoding="utf-8")
        )

        changed["audit_history"][0]["actor"] = "someone_else"

        path.write_text(
            json.dumps(changed),
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            get_approval_request(
                self.root, record["request_id"]
            )

    def test_tampered_evidence_blocked(self):
        path = (
            self.root / "local_s3"
            / "objects" / "FND-0001.json"
        )

        path.write_text(
            '{"finding_id":"FND-0001","severity":"LOW"}'
        )

        with self.assertRaises(ValueError):
            self.request()

    def test_invalid_request_id_rejected(self):
        with self.assertRaises(ValueError):
            get_approval_request(
                self.root, "../../etc/passwd"
            )


if __name__ == "__main__":
    unittest.main()
