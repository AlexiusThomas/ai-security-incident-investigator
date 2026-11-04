
"""Day 30: Deterministic security guardrails for AI incident reports."""

import ipaddress
import re

from correlate import parse_time


REPORT_FIELDS = {
    "finding_id",
    "severity",
    "summary",
    "evidence_event_ids",
    "confirmed_compromise",
    "recommended_action",
    "remediation_executed",
}

IDENTIFIER = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
USERNAME = re.compile(r"[A-Za-z0-9_+=,.@:/-]{1,256}")


def validate_facts(facts):
    """Validate evidence before it reaches the model."""

    if not isinstance(facts, dict):
        raise ValueError("Evidence must be a JSON object")

    required = {
        "finding_id", "severity", "username", "source_ip",
        "failed_event_ids", "success_event_id",
        "start_time", "success_time"
    }

    if not required.issubset(facts):
        raise ValueError("Missing required evidence fields")

    if not isinstance(facts["finding_id"], str) or not (
        IDENTIFIER.fullmatch(facts["finding_id"])
    ):
        raise ValueError("Invalid finding ID")

    if not isinstance(facts["username"], str) or not (
        USERNAME.fullmatch(facts["username"])
    ):
        raise ValueError("Invalid username")

    try:
        ipaddress.ip_address(facts["source_ip"])
    except (ValueError, TypeError):
        raise ValueError("Invalid source IP") from None

    if facts["severity"] not in {"HIGH", "MEDIUM", "LOW", "INFO"}:
        raise ValueError("Invalid severity")

    ids = facts["failed_event_ids"]
    success = facts["success_event_id"]

    if not isinstance(ids, list) or not ids:
        raise ValueError("Missing failed event IDs")

    if not all(
        isinstance(item, str) and IDENTIFIER.fullmatch(item)
        for item in ids + [success]
    ):
        raise ValueError("Invalid event ID")

    if len(set(ids + [success])) != len(ids) + 1:
        raise ValueError("Duplicate event IDs")

    start = parse_time(facts["start_time"])
    end = parse_time(facts["success_time"])

    if end < start:
        raise ValueError("Invalid event chronology")


def enforce_guardrails(facts, draft):
    """Validate AI output, then build a safe evidence-based report."""

    validate_facts(facts)

    if not isinstance(draft, dict):
        raise ValueError("AI response must be a JSON object")

    if set(draft) != REPORT_FIELDS:
        raise ValueError("Unexpected AI response fields")

    expected_ids = (
        facts["failed_event_ids"] + [facts["success_event_id"]]
    )

    if (
        draft["finding_id"] != facts["finding_id"]
        or draft["severity"] != facts["severity"]
        or draft["evidence_event_ids"] != expected_ids
    ):
        raise ValueError("AI output contradicts verified evidence")

    if draft["confirmed_compromise"] is not False:
        raise ValueError("Unverified compromise claim")

    if draft["remediation_executed"] is not False:
        raise ValueError("Unauthorized remediation claim")

    for field in ("summary", "recommended_action"):
        if (
            not isinstance(draft[field], str)
            or not draft[field].strip()
            or len(draft[field]) > 3000
        ):
            raise ValueError("Invalid AI narrative")

    # Never publish model-authored free text as verified facts.
    # Build the final narrative from validated evidence instead.
    summary = (
        f"Finding {facts['finding_id']}: "
        f"{len(facts['failed_event_ids'])} failed logins "
        f"for {facts['username']} from {facts['source_ip']} "
        "were followed by a successful login. "
        f"Detection severity: {facts['severity']}. "
        "This activity requires investigation. "
        "Account compromise has not been established."
    )

    return {
        "finding_id": facts["finding_id"],
        "severity": facts["severity"],
        "summary": summary,
        "evidence_event_ids": expected_ids,
        "confirmed_compromise": False,
        "recommended_action": (
            "Review authentication evidence and MFA, "
            "verify account activity, and request "
            "authorized analyst review."
        ),
        "remediation_executed": False,
    }
