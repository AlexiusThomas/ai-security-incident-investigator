
import json
import tempfile
import unittest
from pathlib import Path

from evidence_store import save_evidence, verify_evidence


class TestEvidenceStore(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        self.root = Path(self.tmp.name)
        self.payload = {
            "finding_id": "FND-0001",
            "severity": "HIGH"
        }

    def test_save_and_verify(self):
        metadata = save_evidence(
            self.root, "FND-0001", self.payload
        )

        self.assertEqual(len(metadata["sha256"]), 64)
        self.assertTrue(
            verify_evidence(self.root, "FND-0001")["verified"]
        )

    def test_detect_tampering(self):
        save_evidence(self.root, "FND-0001", self.payload)

        target = self.root / "objects" / "FND-0001.json"

        data = json.loads(target.read_text(encoding="utf-8"))
        data["severity"] = "LOW"

        target.write_text(json.dumps(data), encoding="utf-8")

        result = verify_evidence(self.root, "FND-0001")
        self.assertFalse(result["verified"])

    def test_refuses_overwrite(self):
        save_evidence(self.root, "FND-0001", self.payload)

        with self.assertRaises(FileExistsError):
            save_evidence(self.root, "FND-0001", self.payload)

    def test_rejects_path_traversal(self):
        with self.assertRaises(ValueError):
            save_evidence(self.root, "../escape", self.payload)

    def test_missing_object(self):
        save_evidence(self.root, "FND-0001", self.payload)

        (self.root / "objects" / "FND-0001.json").unlink()

        with self.assertRaises(FileNotFoundError):
            verify_evidence(self.root, "FND-0001")

    def test_missing_manifest(self):
        save_evidence(self.root, "FND-0001", self.payload)

        (self.root / "manifests" / "FND-0001.json").unlink()

        with self.assertRaises(FileNotFoundError):
            verify_evidence(self.root, "FND-0001")

    def test_canonical_checksum(self):
        first = save_evidence(
            self.root / "a",
            "FND-0001",
            {"a": 1, "b": 2}
        )

        second = save_evidence(
            self.root / "b",
            "FND-0001",
            {"b": 2, "a": 1}
        )

        self.assertEqual(first["sha256"], second["sha256"])

    def test_rejects_non_dictionary(self):
        with self.assertRaises(ValueError):
            save_evidence(self.root, "FND-0001", ["invalid"])


if __name__ == "__main__":
    unittest.main()
