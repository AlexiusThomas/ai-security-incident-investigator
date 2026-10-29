
import json
from pathlib import Path

base = Path(__file__).parent

with (base / "raw_events.json").open(encoding="utf-8-sig") as file:
    events = json.load(file)

normalized = []

for event in events:
    source = event.get("source")

    if source == "windows":
        if event.get("EventID") != 4625:
            continue

        result = {
            "source": "windows",
            "event_type": "failed_login",
            "username": event.get("Account"),
            "source_ip": event.get("IpAddress")
        }

    elif source == "aws":
        if (
            event.get("eventName") != "ConsoleLogin"
            or not event.get("errorMessage")
        ):
            continue

        result = {
            "source": "aws",
            "event_type": "failed_login",
            "username": event.get("userIdentity"),
            "source_ip": event.get("sourceIPAddress")
        }

    else:
        print(f"Skipping unsupported source: {source}")
        continue

    normalized.append(result)

output = base / "normalized_events.json"

with output.open("w", encoding="utf-8") as file:
    json.dump(normalized, file, indent=2)

print(f"Normalized {len(normalized)} events")
print(f"Saved to {output.name}")
