
"""Day 34: Safe, local-only security remediation simulator."""

import json
from datetime import datetime, timezone
from pathlib import Path

from approval_workflow import (
    ALLOWED_ACTIONS,
    TRAINING_ROLES,
    get_approval_request,
)
from evidence_store import verify_evidence


# Simulated operator identity. Not real authentication.
SIMULATION_OPERATORS = {"operator1"}


def simulate_remediation(run_dir, request_id, operator):
    """Simulate a previously approved security action.

    This function performs no AWS operations.
    """

    root = Path(run_dir)

    # 1. Verify the operator.
    if operator not in SIMULATION_OPERATORS:
        raise PermissionError("Operator not authorized")

    # 2. Verify approval record and audit hash chain.
    request = get_approval_request(root, request_id)

    if request["status"] != "APPROVED":
        raise PermissionError("Human approval required")

    # 3. Check action allowlist.
    action = request["action"]

    if action not in ALLOWED_ACTIONS:
        raise PermissionError("Action not permitted")

    # 4. Validate requester and reviewer roles.
    if TRAINING_ROLES.get(request["requested_by"]) != "ANALYST":
        raise PermissionError("Invalid requester role")

    if TRAINING_ROLES.get(request["decided_by"]) != "APPROVER":
        raise PermissionError("Invalid approver role")

    if operator in {
        request["requested_by"],
        request["decided_by"],
    }:
        raise PermissionError("Separation of duties violation")

    if request["action_executed"] is not False:
        raise ValueError("Unexpected execution state")

    # 5. Recheck stored security evidence.
    finding_id = request["finding_id"]

    verification = verify_evidence(
        root / "local_s3",
        finding_id,
    )

    if verification["verified"] is not True:
        raise ValueError("Evidence integrity failure")

    finding_path = (
        root / "local_s3" / "objects"
        / f"{finding_id}.json"
    )

    finding = json.loads(
        finding_path.read_text(encoding="utf-8")
    )

    if finding.get("finding_id") != finding_id:
        raise ValueError("Evidence identity mismatch")

    # 6. Simulate changes to a fictional account only.
    before = {
        "synthetic_user_enabled": True,
        "synthetic_sessions_active": True,
    }

    after = before.copy()

    if action == "REVOKE_SESSIONS":
        after["synthetic_sessions_active"] = False

    elif action == "DISABLE_IAM_USER":
        after["synthetic_user_enabled"] = False

    elif action == "REVIEW_SIGNIN_ACTIVITY":
        pass

    else:
        raise PermissionError("Unsupported simulation action")

    # 7. Build a local-only simulation receipt.
    receipt = {
        "request_id": request_id,
        "finding_id": finding_id,
        "action": action,
        "operator": operator,
        "approval_status": "APPROVED",
        "mode": "LOCAL_SIMULATION",
        "status": "SIMULATED",
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(),
        "before": before,
        "after": after,
        "evidence_sha256": verification["actual_sha256"],
        "approval_audit_head": (
            request["audit_history"][-1]["hash"]
        ),
        "simulation_executed": True,
        "real_remediation_executed": False,
    }

    # 8. Save receipt; refuse duplicate execution.
    output = root / "simulations"
    output.mkdir(parents=True, exist_ok=True)

    receipt_path = output / f"{request_id}.json"

    with receipt_path.open("x", encoding="utf-8") as file:
        json.dump(receipt, file, indent=2)

    return receipt

