
"""Day 29: AI incident summarization tests."""

import json
import tempfile
import unittest
from pathlib import Path

from bedrock_local import LocalBedrockClient
from evidence_store import save_evidence
from ai_summary_pipeline import summarize_verified_finding


class AlteredClient(LocalBedrockClient):
    def __init__(self, changes):
        self.changes = changes

    def converse(self, **kwargs):
        response = super().converse(**kwargs)
        block = response["output"]["message"]["content"][0]

        payload = json.loads(block["text"])
        payload.update(self.changes)
        block["text"] = json.dumps(payload)

        return response


class TestAISummary(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.root = Path(self.temp.name)
        self.store = self.root / "store"
        self.output = self.root / "output"

        self.finding = {
            "finding_id": "FND-0001",
            "severity": "HIGH",
            "username": "admin",
            "source_ip": "203.0.113.10",
            "evidence": {
                "failed_event_ids": ["E001", "E002"],
                "success_event_id": "E003",
                "start_time": "2026-11-04T12:00:00Z",
                "success_time": "2026-11-04T12:04:00Z"
            }
        }

        save_evidence(self.store, "FND-0001", self.finding)

    def summarize(self, client=None):
        return summarize_verified_finding(
            self.store,
            "FND-0001",
            self.output,
            client=client,
        )

    def test_generates_summary(self):
        result = self.summarize()

        self.assertEqual(result["evidence_integrity"], "VERIFIED")
        self.assertIn("admin", result["report"]["summary"])

    def test_preserves_evidence_ids(self):
        result = self.summarize()

        self.assertEqual(
            result["report"]["evidence_event_ids"],
            ["E001", "E002", "E003"]
        )

    def test_requires_analyst_review(self):
        result = self.summarize()

        self.assertTrue(result["analyst_review_required"])
        self.assertFalse(result["report"]["remediation_executed"])

    def test_rejects_tampering(self):
        path = self.store / "objects" / "FND-0001.json"
        path.write_text("tampered", encoding="utf-8")

        with self.assertRaises(ValueError):
            self.summarize()

    def test_rejects_fabricated_event(self):
        client = AlteredClient({
            "evidence_event_ids": ["E001", "FAKE-999"]
        })

        with self.assertRaises(ValueError):
            self.summarize(client)

    def test_rejects_unverified_compromise(self):
        client = AlteredClient({
            "confirmed_compromise": True
        })

        with self.assertRaises(ValueError):
            self.summarize(client)

    def test_json_report_saved(self):
        self.summarize()

        report = self.output / "FND-0001-ai-summary.json"
        self.assertTrue(report.exists())

        saved = json.loads(report.read_text(encoding="utf-8"))
        self.assertEqual(saved["model"], "LOCAL_BEDROCK_SIMULATOR")


if __name__ == "__main__":
    unittest.main()
