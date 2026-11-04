
import json
from pathlib import Path

BASE = Path(__file__).parent


def classify_event(event, rules):
    event_type = event.get("event_type")
    source_ip = event.get("source_ip")

    severities = rules["severities"]
    monitored_ips = rules["monitored_ips"]

    if (
        event_type == "failed_login"
        and source_ip in monitored_ips
    ):
        return {
            "severity": severities["monitored_failed_login"],
            "reason": "Failed login from monitored IP"
        }

    if event_type == "failed_login":
        return {
            "severity": severities["failed_login"],
            "reason": "Failed login detected"
        }

    return {
        "severity": severities["default"],
        "reason": "No detection rule matched"
    }


def main():
    with (BASE / "normalized_events.json").open(
        encoding="utf-8-sig"
    ) as file:
        events = json.load(file)

    with (BASE / "detection_rules.json").open(
        encoding="utf-8-sig"
    ) as file:
        rules = json.load(file)

    alerts = []

    for event in events:
        result = classify_event(event, rules)

        alert = {
            "source": event.get("source"),
            "event_type": event.get("event_type"),
            "username": event.get("username"),
            "source_ip": event.get("source_ip"),
            **result
        }

        alerts.append(alert)

        print(
            f"{alert['severity']}: "
            f"{alert['event_type']} "
            f"from {alert['source_ip']} "
            f"({alert['reason']})"
        )

    with (BASE / "alerts.json").open(
        "w", encoding="utf-8"
    ) as file:
        json.dump(alerts, file, indent=2)

    print(f"Saved {len(alerts)} alerts to alerts.json")


if __name__ == "__main__":
    main()

