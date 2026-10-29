
import json
from pathlib import Path

BASE = Path(__file__).parent


def create_investigation(incident, number):
    required = [
        "username",
        "source_ip",
        "severity",
        "event_count",
        "event_ids",
        "start_time",
        "end_time",
        "sources"
    ]

    for field in required:
        if field not in incident:
            raise ValueError(f"Missing required field: {field}")

    if not isinstance(incident["event_ids"], list):
        raise ValueError("event_ids must be a list")

    if not incident["event_ids"]:
        raise ValueError("No event evidence supplied")

    if incident["event_count"] != len(incident["event_ids"]):
        raise ValueError("Event count does not match IDs")

    if incident["severity"] not in {"HIGH", "MEDIUM", "INFO"}:
        raise ValueError("Unknown severity")

    evidence = {
        "event_ids": incident["event_ids"].copy(),
        "sources": incident["sources"],
        "start_time": incident["start_time"],
        "end_time": incident["end_time"],
        "source_ip": incident["source_ip"],
        "username": incident["username"]
    }

    steps = [
        "Review the original security events",
        "Confirm timestamps and source identities",
        "Check whether the activity was authorized",
        "Document findings and evidence",
        "Escalate to an authorized responder if needed"
    ]

    return {
        "investigation_id": f"INV-{number:04d}",
        "status": "OPEN",
        "severity": incident["severity"],
        "summary": (
            f"{incident['event_count']} correlated events "
            f"for user {incident['username']}"
        ),
        "evidence": evidence,
        "recommended_steps": steps,
        "remediation": {
            "suggested_action": (
                "Review account activity and access"
            ),
            "approval_status": "REQUIRED",
            "approved_by": None,
            "executed": False
        }
    }


def main():
    with (BASE / "incidents.json").open(
        encoding="utf-8-sig"
    ) as file:
        incidents = json.load(file)

    if not isinstance(incidents, list):
        raise ValueError("Expected a list of incidents")

    investigations = [
        create_investigation(incident, index)
        for index, incident in enumerate(incidents, 1)
    ]

    output = BASE / "investigations.json"

    with output.open("w", encoding="utf-8") as file:
        json.dump(investigations, file, indent=2)

    for investigation in investigations:
        print(
            f"{investigation['investigation_id']} | "
            f"{investigation['severity']} | "
            f"{investigation['status']}"
        )

    print(f"Saved {len(investigations)} investigations")


if __name__ == "__main__":
    main()

