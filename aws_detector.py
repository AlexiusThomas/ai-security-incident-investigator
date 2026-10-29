
import json
from pathlib import Path

file_path = Path(__file__).with_name("aws-events.json")

with file_path.open(encoding="utf-8") as file:
    events = json.load(file)

high_risk_actions = {
    "StopLogging",
    "DeleteTrail",
    "DeleteBucket"
}

for event in events:
    name = event.get("eventName", "Unknown")
    ip = event.get("sourceIPAddress", "Unknown")
    event_id = event.get("eventID", "Unknown")

    if name in high_risk_actions:
        severity = "HIGH"
        reason = "Sensitive administrative action"
    elif event.get("errorMessage"):
        severity = "MEDIUM"
        reason = "API or authentication error"
    else:
        severity = "INFO"
        reason = "No training rule matched"

    print(f"Event: {event_id}")
    print(f"Action: {name}")
    print(f"Source IP: {ip}")
    print(f"Severity: {severity}")
    print(f"Reason: {reason}")
    print("-" * 35)
