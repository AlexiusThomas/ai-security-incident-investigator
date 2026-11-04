
"""Day 38: Full local security architecture demo."""

import json

from capstone_integration import run_integrated_workflow


def event(event_id, minute, outcome):
    return {
        "eventID": event_id,
        "eventTime": (
            f"2026-11-04T12:{minute:02d}:00Z"
        ),
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "synthetic_admin",
        },
        "sourceIPAddress": "203.0.113.10",
        "responseElements": {
            "ConsoleLogin": outcome,
        },
    }


cases = [{
    "case_id": "incident-1",
    "events": [
        event("E001", 0, "Failure"),
        event("E002", 2, "Failure"),
        event("E003", 4, "Success"),
    ],
}]

rules = {
    "severities": {
        "monitored_failed_login": "HIGH",
        "failed_login": "MEDIUM",
        "default": "LOW",
    },
    "monitored_ips": ["203.0.113.10"],
}

choice = input(
    "Enter APPROVED, DENIED, or press Enter for PENDING: "
).strip().upper()

if choice not in {"", "APPROVED", "DENIED"}:
    raise ValueError("Invalid decision")

decisions = {}

if choice:
    decisions["incident-1/FND-0001"] = choice

report = run_integrated_workflow(
    cases,
    rules,
    decisions=decisions,
    output_dir="day38_output",
)

print("\nDAY 38 INTEGRATED SECURITY REPORT")
print(json.dumps(report, indent=2))

assert report["real_remediation_executed"] is False

print("\nDAY 38 INTEGRATION COMPLETED")
