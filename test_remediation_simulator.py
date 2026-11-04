
"""Day 34: Safe remediation authorization tests."""

import json
import tempfile
import unittest
from pathlib import Path

from evidence_store import save_evidence
from approval_workflow import (
    create_approval_request,
    decide_approval_request,
)
from remediation_simulator import simulate_remediation


class TestRemediationSimulator(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)

        self.finding = {
            "finding_id": "FND-0001",
            "severity": "HIGH",
            "evidence": {
                "failed_event_ids": ["E001", "E002"],
                "success_event_id": "E003",
            },
        }

        save_evidence(
            self.root / "local_s3",
            "FND-0001",
            self.finding,
        )

    def create_request(self, action="REVOKE_SESSIONS"):
        return create_approval_request(
            self.root,
            "FND-0001",
            action,
            "analyst1",
            "Investigate simulated suspicious account activity",
        )

    def decide(self, request, decision="APPROVED"):
        return decide_approval_request(
            self.root,
            request["request_id"],
            "reviewer1",
            decision,
            "Reviewed synthetic security evidence for training",
        )

    def approved_request(self, action="REVOKE_SESSIONS"):
        request = self.create_request(action)
        self.decide(request)
        return request

    def test_approved_revocation_simulates(self):
        request = self.approved_request()

        result = simulate_remediation(
            self.root, request["request_id"], "operator1"
        )

        self.assertEqual(result["status"], "SIMULATED")
        self.assertFalse(
            result["after"]["synthetic_sessions_active"]
        )
        self.assertFalse(result["real_remediation_executed"])

    def test_disable_user_simulates(self):
        request = self.approved_request("DISABLE_IAM_USER")

        result = simulate_remediation(
            self.root, request["request_id"], "operator1"
        )

        self.assertFalse(
            result["after"]["synthetic_user_enabled"]
        )

    def test_review_action_changes_nothing(self):
        request = self.approved_request(
            "REVIEW_SIGNIN_ACTIVITY"
        )

        result = simulate_remediation(
            self.root, request["request_id"], "operator1"
        )

        self.assertEqual(result["before"], result["after"])

    def test_pending_request_blocked(self):
        request = self.create_request()

        with self.assertRaises(PermissionError):
            simulate_remediation(
                self.root, request["request_id"], "operator1"
            )

    def test_denied_request_blocked(self):
        request = self.create_request()
        self.decide(request, "DENIED")

        with self.assertRaises(PermissionError):
            simulate_remediation(
                self.root, request["request_id"], "operator1"
            )

    def test_unauthorized_operator_blocked(self):
        request = self.approved_request()

        with self.assertRaises(PermissionError):
            simulate_remediation(
                self.root, request["request_id"], "observer1"
            )

    def test_tampered_approval_blocked(self):
        request = self.create_request()

        path = (
            self.root / "approvals"
            / f"{request['request_id']}.json"
        )

        record = json.loads(path.read_text(encoding="utf-8"))
        record["status"] = "APPROVED"
        path.write_text(json.dumps(record), encoding="utf-8")

        with self.assertRaises(ValueError):
            simulate_remediation(
                self.root, request["request_id"], "operator1"
            )

    def test_tampered_evidence_blocked(self):
        request = self.approved_request()

        path = (
            self.root / "local_s3"
            / "objects" / "FND-0001.json"
        )

        path.write_text(
            '{"finding_id":"FND-0001","severity":"LOW"}',
            encoding="utf-8",
        )

        with self.assertRaises(ValueError):
            simulate_remediation(
                self.root, request["request_id"], "operator1"
            )

    def test_duplicate_simulation_blocked(self):
        request = self.approved_request()

        simulate_remediation(
            self.root, request["request_id"], "operator1"
        )

        with self.assertRaises(FileExistsError):
            simulate_remediation(
                self.root, request["request_id"], "operator1"
            )

    def test_approval_record_not_modified(self):
        request = self.approved_request()

        path = (
            self.root / "approvals"
            / f"{request['request_id']}.json"
        )

        before = path.read_bytes()

        simulate_remediation(
            self.root, request["request_id"], "operator1"
        )

        self.assertEqual(before, path.read_bytes())


if __name__ == "__main__":
    unittest.main()
