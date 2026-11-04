
"""Day 28: Local S3-style evidence storage with SHA-256 verification."""

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from pathlib import Path


def _paths(root, evidence_id):
    """Construct safe evidence and manifest paths."""

    if not isinstance(evidence_id, str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", evidence_id
    ):
        raise ValueError("Invalid evidence ID")

    root = Path(root)

    return (
        root / "objects" / f"{evidence_id}.json",
        root / "manifests" / f"{evidence_id}.json",
    )


def save_evidence(root, evidence_id, evidence):
    """Store evidence and create a SHA-256 integrity manifest."""

    if not isinstance(evidence, dict):
        raise ValueError("Evidence must be a JSON object")

    object_path, manifest_path = _paths(root, evidence_id)

    if object_path.exists() or manifest_path.exists():
        raise FileExistsError("Evidence ID already stored")

    body = json.dumps(
        evidence,
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

    manifest = {
        "evidence_id": evidence_id,
        "sha256": hashlib.sha256(body).hexdigest(),
        "size_bytes": len(body),
        "saved_at_utc": datetime.now(timezone.utc).isoformat(),
        "storage": "LOCAL_SIMULATION",
        "encryption": "NOT_IMPLEMENTED",
    }

    object_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.parent.mkdir(parents=True, exist_ok=True)

    with object_path.open("xb") as file:
        file.write(body)

    try:
        with manifest_path.open("x", encoding="utf-8") as file:
            json.dump(manifest, file, indent=2)
    except Exception:
        object_path.unlink()
        raise

    return manifest


def verify_evidence(root, evidence_id):
    """Verify evidence bytes against the stored SHA-256 checksum."""

    object_path, manifest_path = _paths(root, evidence_id)

    manifest = json.loads(
        manifest_path.read_text(encoding="utf-8")
    )

    body = object_path.read_bytes()
    expected = manifest.get("sha256")

    if (
        manifest.get("evidence_id") != evidence_id
        or not isinstance(expected, str)
        or re.fullmatch(r"[a-f0-9]{64}", expected) is None
    ):
        raise ValueError("Invalid evidence manifest")

    actual = hashlib.sha256(body).hexdigest()

    verified = (
        hmac.compare_digest(expected, actual)
        and manifest.get("size_bytes") == len(body)
    )

    return {
        "evidence_id": evidence_id,
        "verified": verified,
        "expected_sha256": expected,
        "actual_sha256": actual,
    }
