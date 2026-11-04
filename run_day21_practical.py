
"""Day 21: Security incident practical assessment."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from day19_workflow import complete_workflow

# Four simulated authentication events
events = [
    {
        "id": "E001",
        "source": "windows",
        "EventID": 4625,
        "Account": "admin",
        "IpAddress": "203.0.113.10",
        "timestamp": "2026-11-04T12:00:00Z"
    },
    {
        "id": "E002",
        "source": "aws",
        "eventName": "ConsoleLogin",
        "errorMessage": "Failed authentication",
        "userIdentity": "admin",
        "sourceIPAddress": "203.0.113.10",
        "eventTime": "2026-11-04T12:03:00Z"
    },
    {
        "id": "E003",
        "source": "windows",
        "EventID": 4625,
        "Account": "admin",
        "IpAddress": "203.0.113.10",
        "timestamp": "2026-11-04T12:11:00Z"
    },
    {
        "id": "E004",
        "source": "windows",
        "EventID": 4624,
        "Account": "admin",
        "IpAddress": "203.0.113.10",
        "timestamp": "2026-11-04T12:02:00Z"
    }
]

rules = {
    "severities": {
        "monitored_failed_login": "HIGH",
        "failed_login": "MEDIUM",
        "default": "LOW"
    },
    "monitored_ips": ["203.0.113.10"]
}

with tempfile.TemporaryDirectory() as temp:
    rules_path = Path(temp) / "rules.json"
    rules_path.write_text(
        json.dumps(rules),
        encoding="utf-8"
    )

    with patch(
        "api_pipeline.fetch_security_events",
        return_value=events
    ):
        result = complete_workflow(
            "https://example.invalid/events",
            output_dir="day21_output",
            rules_file=rules_path
        )

print("\nDAY 21 PRACTICAL RESULTS")
print(json.dumps(result, indent=2))

incidents = json.loads(
    Path("day21_output/incidents.json").read_text(
        encoding="utf-8"
    )
)

assert result["raw_events"] == 4
assert result["normalized_events"] == 3
assert result["alerts"] == 3
assert result["incidents"] == 1
assert result["investigations"] == 1
assert result["reports"] == 1

assert len(incidents) == 1
assert incidents[0]["event_ids"] == ["E001", "E002"]
assert incidents[0]["severity"] == "HIGH"

report = Path("day21_output/reports/INV-0001.md")
assert report.exists()

print("\nDAY 21 PRACTICAL: PASSED")
print("Report:", report.resolve())
