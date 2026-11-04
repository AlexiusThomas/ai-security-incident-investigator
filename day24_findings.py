
"""Day 24: CloudTrail security findings and incident reports."""

import json
from pathlib import Path

from login_sequence_detector import analyze_login_sequences


def create_finding(sequence, number):
    """Convert a suspicious login sequence into a security finding."""

    return {
        "finding_id": f"FND-{number:04d}",
        "title": "Failed Logins Followed by Successful Login",
        "severity": sequence["severity"],
        "status": "REVIEW_REQUIRED",
        "username": sequence["username"],
        "source_ip": sequence["source_ip"],
        "evidence": {
            "failed_event_ids": sequence["failure_event_ids"],
            "success_event_id": sequence["success_event_id"],
            "start_time": sequence["start_time"],
            "success_time": sequence["success_time"],
        },
        "confirmed_compromise": False,
        "remediation": {
            "approval_status": "REQUIRED",
            "executed": False,
        },
    }


def build_finding_report(finding):
    evidence = finding["evidence"]

    return f"""# AWS Security Investigation Report

## Finding
ID: {finding['finding_id']}
Severity: {finding['severity']}
Status: {finding['status']}

## Authentication Evidence
Username: {finding['username']}
Source IP: {finding['source_ip']}
Failed events: {', '.join(evidence['failed_event_ids'])}
Successful event: {evidence['success_event_id']}

First failure: {evidence['start_time']}
Successful login: {evidence['success_time']}

## Assessment
Multiple failed logins were followed by a successful login.
This pattern warrants investigation.

The available evidence does not confirm account compromise.

## Recommended Actions
1. Review original CloudTrail events.
2. Verify the account owner's activity.
3. Review MFA and authentication context.
4. Investigate other activity by the account.
5. Escalate to an authorized responder if needed.

## Remediation
Approval required: Yes
Remediation executed: No

All events are synthetic training data.
"""


def run_day24(payload, rules, output_dir="day24_output"):
    """Analyze CloudTrail records and save findings and reports."""

    analysis = analyze_login_sequences(payload, rules)

    findings = [
        create_finding(sequence, index)
        for index, sequence in enumerate(
            analysis["sequence_findings"], 1
        )
    ]

    output = Path(output_dir)
    reports_dir = output / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    (output / "findings.json").write_text(
        json.dumps(findings, indent=2),
        encoding="utf-8",
    )

    for finding in findings:
        report = build_finding_report(finding)
        path = reports_dir / f"{finding['finding_id']}.md"
        path.write_text(report, encoding="utf-8")

    return {
        "cloudtrail_events": len(analysis["events"]),
        "alerts": len(analysis["alerts"]),
        "correlated_incidents": len(analysis["incidents"]),
        "sequence_findings": len(findings),
        "reports": len(findings),
    }
