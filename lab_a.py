
import json

with open("event.json", encoding="utf-8") as file:
    event = json.load(file)

print(event["username"])
print(event["failed_attempts"])
