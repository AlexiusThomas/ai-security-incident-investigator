
import json
from pathlib import Path

BASE = Path(__file__).parent


def build_report(investigation):
    required = [
        "investigation_id",
        "status",
        "severity",
        "summary",
        "evidence",
        "recommended_steps",
        "remediation"
    ]

    for field in required:
        if field not in investigation:
            raise ValueError(f"Missing field: {field}")

    evidence = investigation["evidence"]
    remediation = investigation["remediation"]

    for field in [
        "event_ids", "sources", "start_time",
        "end_time", "username", "source_ip"
    ]:
        if field not in evidence:
            raise ValueError(f"Missing evidence: {field}")

    if not isinstance(evidence["event_ids"], list):
        raise ValueError("event_ids must be a list")

    if not evidence["event_ids"]:
        raise ValueError("Evidence references are empty")

    if not isinstance(
        investigation["recommended_steps"], list
    ):
        raise ValueError("recommended_steps must be a list")

    if "approval_status" not in remediation:
        raise ValueError("Missing approval status")

    if "executed" not in remediation:
        raise ValueError("Missing execution status")

    event_ids = ", ".join(evidence["event_ids"])
    sources = ", ".join(evidence["sources"])

    steps = "\n".join(
        f"{index}. {step}"
        for index, step in enumerate(
            investigation["recommended_steps"], 1
        )
    )

    approval = remediation["approval_status"]
    executed = remediation["executed"]

    if not isinstance(executed, bool):
        raise ValueError("executed must be a boolean")

    execution_text = "Yes" if executed else "No"

    report = f"""# Security Investigation Report

## Executive Summary

Investigation: {investigation['investigation_id']}
Status: {investigation['status']}
Severity: {investigation['severity']}

{investigation['summary']}

This report describes a potential security incident
identified by a training correlation rule.
The available records do not establish compromise.

## Evidence References

Event IDs: {event_ids}
Sources: {sources}
Username: {evidence['username']}
Source IP: {evidence['source_ip']}

## Timeline

First observed: {evidence['start_time']}
Last observed: {evidence['end_time']}

These timestamps describe the correlated event window.
They do not provide individual event-level timestamps.

## Findings

Observed:
- The investigation references the listed events.
- Events share a username and source IP.
- The rule assigned the recorded severity.

Not yet verified:
- Whether the activity was authorized.
- Whether an account was compromised.
- Whether containment is necessary.

## Recommended Investigation Steps

{steps}

## Remediation and Approval

Approval status: {approval}
Remediation executed: {execution_text}

No remediation is performed by this reporting script.

## Evidence Limitations

This report was generated from investigations.json.
Original source logs were not independently verified.
All events in this exercise are synthetic training data.
"""

    return report


def main():
    with (BASE / "investigations.json").open(
        encoding="utf-8-sig"
    ) as file:
        investigations = json.load(file)

    if not isinstance(investigations, list):
        raise ValueError("Expected a list of investigations")

    output_dir = BASE / "reports"
    output_dir.mkdir(exist_ok=True)

    for investigation in investigations:
        report = build_report(investigation)
        investigation_id = investigation["investigation_id"]

        # Permit only safe characters in filenames.
        if (
            not isinstance(investigation_id, str)
            or not investigation_id
            or not all(
                c.isascii() and (
                    c.isalnum() or c in "-_"
                )
                for c in investigation_id
            )
        ):
            raise ValueError("Invalid investigation ID")

        output = output_dir / f"{investigation_id}.md"
        output.write_text(report, encoding="utf-8")

        print(f"Generated: {output.name}")

    print(f"Reports generated: {len(investigations)}")


if __name__ == "__main__":
    main()
