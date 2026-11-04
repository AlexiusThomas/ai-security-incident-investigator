
"""Day 23: Detect failed logins followed by success."""

from collections import defaultdict, deque
from datetime import timedelta

from correlate import parse_time
from cloudtrail_ingest import analyze_cloudtrail


def detect_login_sequences(events, threshold=2, window_minutes=5):
    """Detect repeated failures followed by successful login."""

    if threshold < 1 or window_minutes <= 0:
        raise ValueError("Invalid detection settings")

    window = timedelta(minutes=window_minutes)
    groups = defaultdict(list)

    for event in events:
        event_type = event.get("event_type")

        if event_type not in {"failed_login", "successful_login"}:
            continue

        username = event.get("username")
        source_ip = event.get("source_ip")
        event_id = event.get("event_id")

        if not all(
            isinstance(value, str) and value.strip()
            for value in (username, source_ip, event_id)
        ):
            raise ValueError("Missing authentication evidence")

        timestamp = parse_time(event.get("timestamp"))

        groups[(username, source_ip)].append(
            (timestamp, event)
        )

    findings = []

    for (username, source_ip), records in groups.items():
        records.sort(key=lambda item: item[0])
        failures = deque()

        for timestamp, event in records:

            while (
                failures
                and timestamp - failures[0][0] > window
            ):
                failures.popleft()

            if event["event_type"] == "failed_login":
                failures.append((timestamp, event))
                continue

            # Only count distinct, earlier failed events.
            matching = []
            seen_ids = set()

            for failed_at, failed_event in failures:
                failed_id = failed_event["event_id"]

                if failed_at >= timestamp:
                    continue

                if failed_id not in seen_ids:
                    matching.append((failed_at, failed_event))
                    seen_ids.add(failed_id)

            if len(matching) < threshold:
                continue

            findings.append({
                "username": username,
                "source_ip": source_ip,
                "severity": "HIGH",
                "status": "REVIEW_REQUIRED",
                "failure_count": len(matching),
                "failure_event_ids": [
                    failed["event_id"] for _, failed in matching
                ],
                "success_event_id": event["event_id"],
                "start_time": matching[0][0].isoformat(),
                "success_time": timestamp.isoformat(),
                "reason": (
                    "Repeated failed logins followed by success"
                ),
                "confirmed_compromise": False,
                "remediation_executed": False
            })

    return findings


def analyze_login_sequences(payload, rules):
    """Extend the existing CloudTrail analysis."""

    result = analyze_cloudtrail(payload, rules)

    result["sequence_findings"] = detect_login_sequences(
        result["events"]
    )

    return result
