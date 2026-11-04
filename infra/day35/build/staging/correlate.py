
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path(__file__).parent
WINDOW = timedelta(minutes=5)
MIN_ALERTS = 2
ELIGIBLE = {"HIGH", "MEDIUM"}


def parse_time(value):
    if not isinstance(value, str):
        raise ValueError("Timestamp must be a string")

    dt = datetime.fromisoformat(
        value.replace("Z", "+00:00")
    )

    if dt.tzinfo is None:
        raise ValueError("Timestamp needs timezone")

    return dt.astimezone(timezone.utc)


def correlate_events(events):
    groups = defaultdict(list)

    for event in events:
        if event.get("severity") not in ELIGIBLE:
            continue

        username = event.get("username")
        source_ip = event.get("source_ip")

        if not username or not source_ip:
            raise ValueError(
                "Eligible alert missing username or source_ip"
            )

        timestamp = parse_time(event.get("timestamp"))

        groups[(username, source_ip)].append(
            (timestamp, event)
        )

    incidents = []

    for (username, source_ip), records in groups.items():
        records.sort(key=lambda item: item[0])

        clusters = []
        cluster = []

        for timestamp, event in records:
            if cluster and timestamp - cluster[0][0] > WINDOW:
                clusters.append(cluster)
                cluster = []

            cluster.append((timestamp, event))

        if cluster:
            clusters.append(cluster)

        for cluster in clusters:
            if len(cluster) < MIN_ALERTS:
                continue

            severities = {
                e["severity"] for _, e in cluster
            }

            severity = (
                "HIGH" if "HIGH" in severities else "MEDIUM"
            )

            incidents.append({
                "username": username,
                "source_ip": source_ip,
                "event_count": len(cluster),
                "severity": severity,
                "start_time": cluster[0][0].isoformat(),
                "end_time": cluster[-1][0].isoformat(),
                "event_ids": [
                    e["event_id"] for _, e in cluster
                ],
                "sources": sorted({
                    e["source"] for _, e in cluster
                }),
                "reason": (
                    "Related alerts within five minutes"
                )
            })

    return sorted(
        incidents,
        key=lambda item: item["start_time"]
    )


def main():
    with (BASE / "correlation_events.json").open(
        encoding="utf-8-sig"
    ) as file:
        events = json.load(file)

    incidents = correlate_events(events)

    with (BASE / "incidents.json").open(
        "w", encoding="utf-8"
    ) as file:
        json.dump(incidents, file, indent=2)

    for index, incident in enumerate(incidents, 1):
        print(f"Incident {index}")
        print(f"  User: {incident['username']}")
        print(f"  IP: {incident['source_ip']}")
        print(f"  Severity: {incident['severity']}")
        print(f"  Events: {incident['event_count']}")
        print(f"  IDs: {incident['event_ids']}")

    print(f"Saved {len(incidents)} incidents")


if __name__ == "__main__":
    main()
