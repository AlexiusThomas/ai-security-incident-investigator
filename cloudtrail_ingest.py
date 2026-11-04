
"""Day 22: AWS CloudTrail security event integration."""

from correlate import correlate_events, parse_time
from detection_engine import classify_event


def normalize_cloudtrail(payload):
    """Convert CloudTrail ConsoleLogin records to our schema."""

    if isinstance(payload, dict):
        records = payload.get("Records")
    elif isinstance(payload, list):
        records = payload
    else:
        raise ValueError("Invalid CloudTrail payload")

    if not isinstance(records, list):
        raise ValueError("CloudTrail Records must be a list")

    normalized = []

    for event in records:
        if not isinstance(event, dict):
            raise ValueError("CloudTrail record must be an object")

        if (
            event.get("eventSource") != "signin.amazonaws.com"
            or event.get("eventName") != "ConsoleLogin"
        ):
            continue

        response = event.get("responseElements") or {}

        if not isinstance(response, dict):
            raise ValueError("Invalid login response")

        outcome = response.get("ConsoleLogin")

        if outcome not in {"Success", "Failure"}:
            raise ValueError("Unknown login outcome")

        identity = event.get("userIdentity") or {}

        if not isinstance(identity, dict):
            raise ValueError("Invalid user identity")

        username = (
            identity.get("userName")
            or identity.get("arn")
            or identity.get("principalId")
        )

        timestamp = event.get("eventTime")
        parse_time(timestamp)

        source_ip = event.get("sourceIPAddress")
        event_id = event.get("eventID")

        if not all(
            isinstance(value, str) and value.strip()
            for value in (username, source_ip, event_id)
        ):
            raise ValueError("Missing CloudTrail evidence fields")

        additional = event.get("additionalEventData") or {}

        normalized.append({
            "event_id": event_id,
            "timestamp": timestamp,
            "source": "aws",
            "event_type": (
                "failed_login" if outcome == "Failure"
                else "successful_login"
            ),
            "username": username,
            "source_ip": source_ip,
            "login_result": outcome,
            "mfa_used": additional.get("MFAUsed", "Unknown")
        })

    return normalized


def analyze_cloudtrail(payload, rules):
    """Run CloudTrail events through detection and correlation."""

    events = normalize_cloudtrail(payload)

    alerts = [
        {**event, **classify_event(event, rules)}
        for event in events
    ]

    incidents = correlate_events(alerts)

    return {
        "events": events,
        "alerts": alerts,
        "incidents": incidents,
    }

