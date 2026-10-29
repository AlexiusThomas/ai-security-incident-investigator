
import json
from pathlib import Path

policy_file = Path(__file__).with_name("iam-policy.json")

with policy_file.open(encoding="utf-8") as file:
    policy = json.load(file)

for statement in policy["Statement"]:
    if statement["Effect"] != "Allow":
        continue

    actions = statement["Action"]
    resources = statement["Resource"]

    if isinstance(actions, str):
        actions = [actions]

    if isinstance(resources, str):
        resources = [resources]

    if "*" in actions and "*" in resources:
        print("HIGH RISK: Broad administrative permissions")
    elif "*" in actions:
        print("WARNING: All actions allowed")
    elif "*" in resources:
        print("REVIEW: Permissions apply to all resources")
    else:
        print("No broad wildcard permissions detected")
