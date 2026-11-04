
"""Day 33: Local approval workflow; no AWS calls or remediation."""

import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from evidence_store import verify_evidence


# Simulated training roles, not authenticated identities.
TRAINING_ROLES = {
    "analyst1": "ANALYST",
    "reviewer1": "APPROVER",
    "reviewer2": "APPROVER",
    "observer1": "VIEWER",
}

ALLOWED_ACTIONS = {
    "REVIEW_SIGNIN_ACTIVITY",
    "REVOKE_SESSIONS",
    "DISABLE_IAM_USER",
}


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def _require_reason(value):
    if not isinstance(value, str) or not 10 <= len(value.strip()) <= 500:
        raise ValueError("Reason must contain 10 to 500 characters")
    return value.strip()


def _request_path(run_dir, request_id):
    if not isinstance(request_id, str) or not re.fullmatch(
        r"REQ-[a-f0-9]{12}", request_id
    ):
        raise ValueError("Invalid request ID")

    return Path(run_dir) / "approvals" / f"{request_id}.json"


def _audit(record, event_type, actor, details):
    """Append a hash-linked local audit record."""

    prior = record["audit_history"]

    entry = {
        "sequence": len(prior) + 1,
        "timestamp_utc": _timestamp(),
        "event_type": event_type,
        "actor": actor,
        "details": details,
        "previous_hash": (
            prior[-1]["hash"] if prior else "GENESIS"
        ),
    }

    canonical = json.dumps(
        entry, sort_keys=True, separators=(",", ":")
    )

    entry["hash"] = hashlib.sha256(
        canonical.encode("utf-8")
    ).hexdigest()

    prior.append(entry)


def verify_audit_history(record):
    """Check audit links and approval state consistency."""

    history = record.get("audit_history")

    if not isinstance(history, list) or len(history) not in (1, 2):
        return False

    previous = "GENESIS"

    for number, event in enumerate(history, 1):
        if not isinstance(event, dict) or set(event) != {
            "sequence",
            "timestamp_utc",
            "event_type",
            "actor",
            "details",
            "previous_hash",
            "hash",
        }:
            return False

        body = {
            key: value
            for key, value in event.items()
            if key != "hash"
        }

        canonical = json.dumps(
            body, sort_keys=True, separators=(",", ":")
        )

        expected = hashlib.sha256(
            canonical.encode("utf-8")
        ).hexdigest()

        if (
            event["sequence"] != number
            or event["previous_hash"] != previous
            or event["hash"] != expected
        ):
            return False

        previous = event["hash"]

    first = history[0]

    if (
        first["event_type"] != "REQUESTED"
        or first["actor"] != record.get("requested_by")
        or first["details"] != {
            "finding_id": record.get("finding_id"),
            "action": record.get("action"),
            "reason": record.get("reason"),
        }
        or record.get("action_executed") is not False
    ):
        return False

    if len(history) == 1:
        return (
            record.get("status") == "PENDING"
            and record.get("decided_by") is None
            and record.get("decision_reason") is None
        )

    last = history[1]

    return (
        last["event_type"] in {"APPROVED", "DENIED"}
        and last["event_type"] == record.get("status")
        and last["actor"] == record.get("decided_by")
        and last["details"] == {
            "reason": record.get("decision_reason")
        }
    )


def create_approval_request(
    run_dir,
    evidence_id,
    action,
    requested_by,
    reason,
):
    """Create an approval request using verified evidence."""

    if TRAINING_ROLES.get(requested_by) != "ANALYST":
        raise PermissionError(
            "Only simulated analysts may request actions"
        )

    if action not in ALLOWED_ACTIONS:
        raise PermissionError(
            "Action is not approved for this lab"
        )

    reason = _require_reason(reason)

    verification = verify_evidence(
        Path(run_dir) / "local_s3",
        evidence_id,
    )

    if verification["verified"] is not True:
        raise ValueError(
            "Evidence integrity verification failed"
        )

    stored = json.loads(
        (
            Path(run_dir)
            / "local_s3"
            / "objects"
            / f"{evidence_id}.json"
        ).read_text(encoding="utf-8")
    )

    if stored.get("finding_id") != evidence_id:
        raise ValueError("Finding ID mismatch")

    request_id = f"REQ-{uuid.uuid4().hex[:12]}"

    record = {
        "request_id": request_id,
        "finding_id": evidence_id,
        "action": action,
        "requested_by": requested_by,
        "reason": reason,
        "status": "PENDING",
        "decided_by": None,
        "decision_reason": None,
        "action_executed": False,
        "audit_history": [],
    }

    _audit(
        record,
        "REQUESTED",
        requested_by,
        {
            "finding_id": evidence_id,
            "action": action,
            "reason": reason,
        },
    )

    path = _request_path(run_dir, request_id)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("x", encoding="utf-8") as file:
        json.dump(record, file, indent=2)

    return record


def get_approval_request(run_dir, request_id):
    """Load and verify an approval request."""

    path = _request_path(run_dir, request_id)

    record = json.loads(
        path.read_text(encoding="utf-8")
    )

    if (
        record.get("request_id") != request_id
        or not verify_audit_history(record)
    ):
        raise ValueError(
            "Approval record integrity check failed"
        )

    return record


def decide_approval_request(
    run_dir,
    request_id,
    approver,
    decision,
    reason,
):
    """Record a simulated decision without executing anything."""

    if TRAINING_ROLES.get(approver) != "APPROVER":
        raise PermissionError("Approver role required")

    if decision not in {"APPROVED", "DENIED"}:
        raise ValueError(
            "Decision must be APPROVED or DENIED"
        )

    reason = _require_reason(reason)

    record = get_approval_request(
        run_dir, request_id
    )

    if approver == record["requested_by"]:
        raise PermissionError(
            "Requester cannot approve their own request"
        )

    if record["status"] != "PENDING":
        raise ValueError(
            "Request has already been decided"
        )

    record["status"] = decision
    record["decided_by"] = approver
    record["decision_reason"] = reason

    _audit(
        record,
        decision,
        approver,
        {"reason": reason},
    )

    path = _request_path(run_dir, request_id)

    temp_path = path.with_name(
        path.name + f".{uuid.uuid4().hex}.tmp"
    )

    try:
        temp_path.write_text(
            json.dumps(record, indent=2),
            encoding="utf-8",
        )
        os.replace(temp_path, path)
    finally:
        temp_path.unlink(missing_ok=True)

    return record
