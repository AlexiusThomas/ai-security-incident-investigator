
"""Day 33: Simulate analyst request and reviewer decision."""

from local_security_agent import run_security_agent
from approval_workflow import (
    create_approval_request,
    decide_approval_request,
    get_approval_request,
)


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
            "ConsoleLogin": outcome
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

# Run the existing security investigator.
run = run_security_agent(
    events,
    rules,
    output_dir="day33_output",
)

run_dir = run["output_directory"]

# Analyst requests an action.
request = create_approval_request(
    run_dir,
    evidence_id="FND-0001",
    action="REVOKE_SESSIONS",
    requested_by="analyst1",
    reason="Review suspicious synthetic login sequence",
)

print("\nAPPROVAL REQUEST CREATED")
print("Request ID:", request["request_id"])
print("Finding:", request["finding_id"])
print("Action:", request["action"])
print("Status:", request["status"])

# Simulate a separate reviewer making a decision.
choice = input(
    "\nEnter APPROVED, DENIED, or press Enter to leave pending: "
).strip().upper()

if choice:
    if choice not in {"APPROVED", "DENIED"}:
        raise ValueError("Invalid decision")

    decide_approval_request(
        run_dir,
        request["request_id"],
        approver="reviewer1",
        decision=choice,
        reason="Reviewed the synthetic evidence for training",
    )

final = get_approval_request(
    run_dir,
    request["request_id"],
)

print("\nFINAL APPROVAL STATUS")
print("Status:", final["status"])
print("Decided by:", final["decided_by"])
print("Audit entries:", len(final["audit_history"]))
print("Remediation executed:", final["action_executed"])
print("Day 33 demo completed")

