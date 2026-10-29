
import json
from pathlib import Path

event_path = Path(__file__).with_name("event.json")

with event_path.open(encoding="utf-8") as file:
    event = json.load(file)

username = event["username"]
attempts = event["failed_attempts"]
status = event["status"]

print(f"User: {username}")
print(f"Failed attempts: {attempts}")

if status == "failed" and attempts >= 3:
    print("ALERT: Suspicious login activity detected")
else:
    print("No alert triggered")
