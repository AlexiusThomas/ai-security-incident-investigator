
"""Day 28: End-to-end evidence storage demonstration."""

import json
from pathlib import Path

from day24_findings import run_day24
from evidence_store import save_evidence, verify_evidence


def cloudtrail_event(event_id, minute, outcome):
    return {
        "eventID": event_id,
        "eventTime": f"2026-11-04T12:{minute:02d}:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "userIdentity": {
            "type": "IAMUser",
            "userName": "admin"
        },
        "sourceIPAddress": "203.0.113.10",
        "responseElements": {
            "ConsoleLogin": outcome
        }
    }


events = [
    cloudtrail_event("AWS-001", 0, "Failure"),
    cloudtrail_event("AWS-002", 2, "Failure"),
    cloudtrail_event("AWS-003", 4, "Success"),
]

rules = {
    "severities": {
        "monitored_failed_login": "HIGH",
        "failed_login": "MEDIUM",
        "default": "LOW"
    },
    "monitored_ips": ["203.0.113.10"]
}

output = Path("day28_output")
findings_dir = output / "generated_findings"
store_dir = output / "local_s3"

# Generate the security finding from existing code.
summary = run_day24(events, rules, findings_dir)

findings = json.loads(
    (findings_dir / "findings.json").read_text(
        encoding="utf-8"
    )
)

if len(findings) != 1:
    raise ValueError("Expected exactly one security finding")

finding = findings[0]
evidence_id = finding["finding_id"]

# Store the original finding and checksum.
manifest = save_evidence(
    store_dir,
    evidence_id,
    finding
)

# Verify stored evidence.
verification = verify_evidence(store_dir, evidence_id)

print("DAY 28 EVIDENCE STORAGE")
print("Findings generated:", summary["sequence_findings"])
print("Evidence ID:", evidence_id)
print("SHA-256:", manifest["sha256"])
print("Integrity verified:", verification["verified"])
print("Storage:", store_dir.resolve())

assert verification["verified"]

print("DAY 28 DEMO: PASSED")
