
"""Day 18: Integrate API ingestion with the security pipeline."""

import json
from pathlib import Path

from api_ingest import fetch_security_events


def ingest_and_save(url, output_file="api_events.json"):
    """Retrieve API events and save them for processing."""

    events = fetch_security_events(url)

    output = Path(output_file)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open("w", encoding="utf-8") as file:
        json.dump(events, file, indent=2)

    return {
        "total_events": len(events),
        "output_file": str(output),
        "events": events,
    }


def load_events(filename="api_events.json"):
    """Load previously ingested security events."""

    with open(filename, "r", encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError("Expected a list of security events")

    if not all(isinstance(event, dict) for event in events):
        raise ValueError("Every event must be a JSON object")

    return events
