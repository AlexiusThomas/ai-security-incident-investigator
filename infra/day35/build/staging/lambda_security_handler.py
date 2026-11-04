
"""Day 26: EventBridge-triggered AWS security Lambda."""

import json
from pathlib import Path

from cloudtrail_ingest import normalize_cloudtrail
from detection_engine import classify_event


BASE = Path(__file__).resolve().parent


def load_rules():
    """Load our existing security detection rules."""
    with (BASE / "detection_rules.json").open(
        encoding="utf-8-sig"
    ) as file:
        return json.load(file)


def lambda_handler(event, context):
    """Process one EventBridge CloudTrail sign-in event."""

    if not isinstance(event, dict):
        raise ValueError("EventBridge event must be an object")

    # Ignore unrelated EventBridge events.
    if (
        event.get("source") != "aws.signin"
        or event.get("detail-type") not in {
            "AWS API Call via CloudTrail",
            "AWS Console Signin via CloudTrail"
        }
    ):
        return {"status": "IGNORED"}

    detail = event.get("detail")

    if not isinstance(detail, dict):
        raise ValueError("Missing CloudTrail event detail")

    if (
        detail.get("eventSource") != "signin.amazonaws.com"
        or detail.get("eventName") != "ConsoleLogin"
    ):
        return {"status": "IGNORED"}

    # Reuse the CloudTrail normalization module.
    normalized = normalize_cloudtrail([detail])

    if len(normalized) != 1:
        raise ValueError("Expected exactly one login event")

    security_event = normalized[0]

    # Reuse our existing detection engine.
    detection = classify_event(
        security_event,
        load_rules()
    )

    return {
        "status": "PROCESSED",
        "event_id": security_event["event_id"],
        "username": security_event["username"],
        "source_ip": security_event["source_ip"],
        "event_type": security_event["event_type"],
        "severity": detection["severity"],
        "reason": detection["reason"],
        "review_required": (
            detection["severity"] in {"HIGH", "MEDIUM"}
        ),
        "remediation_executed": False
    }
