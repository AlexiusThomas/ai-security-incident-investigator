
import json
import sys
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).parent


def load_json(path):
    try:
        with path.open(encoding="utf-8-sig") as file:
            return json.load(file)
    except FileNotFoundError as error:
        raise ValueError(
            f"Missing file: {path.name}"
        ) from error
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON in {path.name}: "
            f"line {error.lineno}"
        ) from error


def parse_timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Timestamp must be a string")

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError as error:
        raise ValueError(
            f"Invalid timestamp: {value}"
        ) from error

    if parsed.tzinfo is None:
        raise ValueError("Timestamp missing timezone")

    return parsed


def validate_bundle(incidents, investigations, report):
    if not isinstance(incidents, list):
        raise ValueError("Incidents must be a list")

    if not isinstance(investigations, list):
        raise ValueError("Investigations must be a list")

    if len(incidents) != 1 or len(investigations) != 1:
        raise ValueError(
            "Day 13 fixture expects one incident "
            "and one investigation"
        )

    incident = incidents[0]
    investigation = investigations[0]

    if not isinstance(incident, dict):
        raise ValueError("Incident must be an object")

    if not isinstance(investigation, dict):
        raise ValueError("Investigation must be an object")

    evidence = investigation.get("evidence")
    remediation = investigation.get("remediation")

    if not isinstance(evidence, dict):
        raise ValueError("Missing evidence object")

    if not isinstance(remediation, dict):
        raise ValueError("Missing remediation object")

    event_ids = incident.get("event_ids")
    evidence_ids = evidence.get("event_ids")

    if (
        not isinstance(event_ids, list)
        or not event_ids
        or not all(
            isinstance(item, str) and item
            for item in event_ids
        )
    ):
        raise ValueError("Invalid incident event IDs")

    if evidence_ids != event_ids:
        raise ValueError("Evidence IDs do not match incident")

    if (
        type(incident.get("event_count")) is not int
        or incident["event_count"] != len(event_ids)
    ):
        raise ValueError("Incident event count mismatch")

    for field in ("username", "source_ip", "severity"):
        if not isinstance(incident.get(field), str):
            raise ValueError(f"Invalid incident field: {field}")

    for field in ("username", "source_ip"):
        if evidence.get(field) != incident.get(field):
            raise ValueError(f"Evidence mismatch: {field}")

    if investigation.get("severity") != incident["severity"]:
        raise ValueError("Investigation severity mismatch")

    start = parse_timestamp(incident.get("start_time"))
    end = parse_timestamp(incident.get("end_time"))

    if end < start:
        raise ValueError("End time precedes start time")

    for field in ("start_time", "end_time", "sources"):
        if evidence.get(field) != incident.get(field):
            raise ValueError(f"Evidence mismatch: {field}")

    investigation_id = investigation.get("investigation_id")
    if investigation_id != "INV-0001":
        raise ValueError("Unexpected training investigation ID")

    if investigation.get("status") != "OPEN":
        raise ValueError("Unexpected investigation status")

    if remediation.get("approval_status") != "REQUIRED":
        raise ValueError("Approval requirement missing")

    if remediation.get("approved_by") is not None:
        raise ValueError("Unexpected approver")

    if remediation.get("executed") is not False:
        raise ValueError("Remediation must be unexecuted")

    if not isinstance(report, str):
        raise ValueError("Report must be text")

    required_text = [
        f"Investigation: {investigation_id}",
        f"Severity: {incident['severity']}",
        f"Event IDs: {', '.join(event_ids)}",
        f"First observed: {incident['start_time']}",
        f"Last observed: {incident['end_time']}",
        "Approval status: REQUIRED",
        "Remediation executed: No",
        "Original source logs were not independently verified."
    ]

    for text in required_text:
        if text not in report:
            raise ValueError(
                f"Report missing expected content: {text}"
            )

    return True


def main():
    try:
        incidents = load_json(BASE / "incidents.json")
        investigations = load_json(
            BASE / "investigations.json"
        )

        report_path = BASE / "reports" / "INV-0001.md"

        try:
            report = report_path.read_text(
                encoding="utf-8"
            )
        except OSError as error:
            raise ValueError(
                f"Cannot read report: {report_path.name}"
            ) from error

        validate_bundle(
            incidents, investigations, report
        )

        print("PASS: JSON files loaded")
        print("PASS: Incident and evidence references match")
        print("PASS: Timestamps and severity checked")
        print("PASS: Approval requirements checked")
        print("PASS: Report content checked")
        print("VALIDATION PASSED")

    except ValueError as error:
        print(f"VALIDATION FAILED: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
