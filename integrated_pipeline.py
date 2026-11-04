
"""Day 18: API ingestion, normalization, detection and correlation."""

import json
from pathlib import Path

from api_pipeline import ingest_and_save, load_events
from detection_engine import classify_event
from correlate import correlate_events, parse_time


BASE = Path(__file__).resolve().parent


def normalize_api_events(events):
    """Convert API events to the detection engine's schema."""
    normalized = []

    for index, event in enumerate(events, start=1):
        source = event.get("source")

        if source == "windows" and event.get("EventID") == 4625:
            username = event.get("Account")
            source_ip = event.get("IpAddress")

        elif (
            source == "aws"
            and event.get("eventName") == "ConsoleLogin"
            and event.get("errorMessage")
        ):
            username = event.get("userIdentity")
            if isinstance(username, dict):
                username = (
                    username.get("userName")
                    or username.get("arn")
                    or username.get("principalId")
                )
            source_ip = event.get("sourceIPAddress")

        else:
            continue

        timestamp = (
            event.get("timestamp")
            or event.get("eventTime")
            or event.get("TimeCreated")
        )

        # Correlation needs a valid timezone-aware timestamp.
        parse_time(timestamp)

        if not username or not source_ip:
            raise ValueError(
                "Failed-login event missing username or source IP"
            )

        normalized.append({
            "event_id": (
                event.get("event_id")
                or event.get("id")
                or f"API-{index:04d}"
            ),
            "timestamp": timestamp,
            "source": source,
            "event_type": "failed_login",
            "username": username,
            "source_ip": source_ip,
        })

    return normalized


def save_json(path, data):
    with Path(path).open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def run_pipeline(url, output_dir="day18_output", rules_file=None):
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    # 1. Retrieve and save incoming API events.
    raw_path = output / "api_events.json"
    ingest_and_save(url, output_file=raw_path)
    raw_events = load_events(raw_path)

    # 2. Normalize supported security events.
    normalized = normalize_api_events(raw_events)
    save_json(output / "normalized_events.json", normalized)

    # 3. Apply existing detection rules.
    rules_path = (
        Path(rules_file)
        if rules_file is not None
        else BASE / "detection_rules.json"
    )

    with rules_path.open(encoding="utf-8-sig") as file:
        rules = json.load(file)

    alerts = [
        {**event, **classify_event(event, rules)}
        for event in normalized
    ]
    save_json(output / "alerts.json", alerts)

    # 4. Correlate related alerts into incidents.
    incidents = correlate_events(alerts)
    save_json(output / "incidents.json", incidents)

    return {
        "raw_events": len(raw_events),
        "normalized_events": len(normalized),
        "alerts": len(alerts),
        "incidents": len(incidents),
    }

