
"""Day 34: End-to-end approved remediation simulation."""

import json

from local_security_agent import run_security_agent
from approval_workflow import (
    create_approval_request,
    decide_approval_request,
)
from remediation_simulator import simulate_remediation


def event(event_id, minute, outcome):
    return {
        "eventID": event_id,
        "eventTime": f"2026-11-04T12:{minute:02d}:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "admin",
        },
        "sourceIPAddress": "203.0.113.10",
        "responseElements": {
            "ConsoleLogin": outcome,
        },
    }


events = [
    event("AWS-001", 0, "Failure"),
    event("AWS-002", 2, "Failure"),
    event("AWS-003", 4, "Success"),
]

rules = {
    "severities": {
        "monitored_failed_login": "HIGH",
        "failed_login": "MEDIUM",
        "default": "LOW",
    },
    "monitored_ips": ["203.0.113.10"],
}

# Generate a verified finding using the existing agent.
run = run_security_agent(
    events,
    rules,
    output_dir="day34_output",
)

run_dir = run["output_directory"]

# Simulated analyst requests remediation.
request = create_approval_request(
    run_dir,
    "FND-0001",
    "REVOKE_SESSIONS",
    "analyst1",
    "Investigate repeated synthetic login failures",
)

# Simulated reviewer approves.
decide_approval_request(
    run_dir,
    request["request_id"],
    "reviewer1",
    "APPROVED",
    "Reviewed synthetic incident and approved simulation",
)

# Separate simulated operator performs the local-only action.
receipt = simulate_remediation(
    run_dir,
    request["request_id"],
    "operator1",
)

print(json.dumps(receipt, indent=2))

assert receipt["simulation_executed"] is True
assert receipt["real_remediation_executed"] is False
assert receipt["after"]["synthetic_sessions_active"] is False

print("\nDAY 34 SAFE REMEDIATION: PASSED")
