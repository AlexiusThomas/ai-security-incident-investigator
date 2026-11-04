
"""Day 27: Local AWS EventBridge and Lambda simulator."""

import json
from pathlib import Path

from lambda_security_handler import lambda_handler


BASE = Path(__file__).resolve().parent


def matches_pattern(event, pattern):
    """Match basic EventBridge fields and nested JSON objects."""

    if not isinstance(event, dict):
        return False

    for key, expected in pattern.items():
        if key not in event:
            return False

        actual = event[key]

        if isinstance(expected, dict):
            if not matches_pattern(actual, expected):
                return False

        elif isinstance(expected, list):
            if not any(
                value == actual for value in expected
            ):
                return False

        else:
            raise ValueError("Unsupported event pattern")

    return True


def route_event(event, pattern_file=None):
    """Route matching security events to a local Lambda handler."""

    if pattern_file is None:
        pattern_file = (
            BASE / "event_patterns" / "signin.json"
        )

    with Path(pattern_file).open(encoding="utf-8") as file:
        pattern = json.load(file)

    if not matches_pattern(event, pattern):
        return {
            "routed": False,
            "lambda_invoked": False,
            "result": None,
        }

    result = lambda_handler(event, None)

    return {
        "routed": True,
        "lambda_invoked": True,
        "result": result,
    }


if __name__ == "__main__":

    synthetic_event = {
        "source": "aws.signin",
        "detail-type": "AWS Console Signin via CloudTrail",
        "detail": {
            "eventID": "LAB-001",
            "eventTime": "2026-11-04T12:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "admin"
            },
            "sourceIPAddress": "203.0.113.10",
            "responseElements": {
                "ConsoleLogin": "Failure"
            }
        }
    }

    output = route_event(synthetic_event)

    output_dir = BASE / "day27_output"
    output_dir.mkdir(exist_ok=True)

    (output_dir / "local_result.json").write_text(
        json.dumps(output, indent=2),
        encoding="utf-8"
    )

    print(json.dumps(output, indent=2))
