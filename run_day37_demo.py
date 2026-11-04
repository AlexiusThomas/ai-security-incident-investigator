
"""Day 37: End-to-end local reliability demonstration."""

import json

from local_security_agent import run_security_agent
from reliability_monitor import run_reliable_batch


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


def incident(prefix):
    return [
        event(f"{prefix}-001", 0, "Failure"),
        event(f"{prefix}-002", 2, "Failure"),
        event(f"{prefix}-003", 4, "Success"),
    ]


cases = [
    {
        "case_id": "normal-login",
        "events": incident("NORMAL"),
    },
    {
        "case_id": "retry-login",
        "events": incident("RETRY"),
    },
    {
        "case_id": "failed-login",
        "events": incident("FAIL"),
    },
]

rules = {
    "severities": {
        "monitored_failed_login": "HIGH",
        "failed_login": "MEDIUM",
        "default": "LOW",
    },
    "monitored_ips": ["203.0.113.10"],
}

attempt_counts = {}


def demo_runner(events, rules, output_dir):
    marker = events[0]["eventID"]
    attempt_counts[marker] = (
        attempt_counts.get(marker, 0) + 1
    )

    # Inject one synthetic temporary failure.
    if (
        marker.startswith("RETRY")
        and attempt_counts[marker] == 1
    ):
        raise TimeoutError(
            "Simulated transient timeout"
        )

    # Inject one permanent failure.
    if marker.startswith("FAIL"):
        raise ValueError(
            "Simulated invalid case"
        )

    # All other cases use your actual local agent.
    return run_security_agent(
        events,
        rules,
        output_dir=output_dir,
    )


report = run_reliable_batch(
    cases,
    rules,
    output_dir="day37_output",
    max_attempts=3,
    runner=demo_runner,
)

print("\nDAY 37 RELIABILITY REPORT")

print(
    json.dumps(
        {
            "status": report["status"],
            "cases_total": report["cases_total"],
            "cases_completed": report["cases_completed"],
            "cases_failed": report["cases_failed"],
            "attempts_total": report["attempts_total"],
            "alerts_raised": report["alerts_raised"],
            "remediation_executed": (
                report["remediation_executed"]
            ),
        },
        indent=2,
    )
)

print("\nCASE RESULTS")

for case in report["cases"]:
    print(
        f"{case['case_id']}: "
        f"{case['status']} "
        f"(attempts={case['attempts']})"
    )

print(
    "\nReport folder:",
    report["output_directory"],
)
