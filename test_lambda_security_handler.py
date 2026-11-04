
"""Day 26: EventBridge Lambda tests."""

import json
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from lambda_security_handler import lambda_handler


class TestSecurityLambda(unittest.TestCase):

    def setUp(self):
        self.rules = {
            "severities": {
                "monitored_failed_login": "HIGH",
                "failed_login": "MEDIUM",
                "default": "LOW"
            },
            "monitored_ips": ["203.0.113.10"]
        }

        self.event = {
            "source": "aws.signin",
            "detail-type": "AWS API Call via CloudTrail",
            "detail": {
                "eventID": "AWS-001",
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

    def invoke(self, event):
        with patch(
            "lambda_security_handler.load_rules",
            return_value=self.rules
        ):
            return lambda_handler(event, None)

    def test_failed_login(self):
        result = self.invoke(self.event)
        self.assertEqual(result["status"], "PROCESSED")
        self.assertEqual(result["severity"], "HIGH")
        self.assertTrue(result["review_required"])

    def test_successful_login(self):
        event = deepcopy(self.event)
        event["detail"]["responseElements"]["ConsoleLogin"] = "Success"

        result = self.invoke(event)

        self.assertEqual(result["event_type"], "successful_login")
        self.assertEqual(result["severity"], "LOW")

    def test_unrelated_source(self):
        event = deepcopy(self.event)
        event["source"] = "aws.ec2"

        self.assertEqual(
            self.invoke(event)["status"], "IGNORED"
        )

    def test_wrong_event_type(self):
        event = deepcopy(self.event)
        event["detail-type"] = "Other Event"

        self.assertEqual(
            self.invoke(event)["status"], "IGNORED"
        )

    def test_non_login_event(self):
        event = deepcopy(self.event)
        event["detail"]["eventName"] = "CreateUser"

        self.assertEqual(
            self.invoke(event)["status"], "IGNORED"
        )

    def test_missing_detail(self):
        event = deepcopy(self.event)
        del event["detail"]

        with self.assertRaises(ValueError):
            self.invoke(event)

    def test_no_automatic_remediation(self):
        result = self.invoke(self.event)

        self.assertFalse(result["remediation_executed"])

    def test_eventbridge_pattern(self):
        path = (
            Path(__file__).resolve().parent
            / "event_patterns" / "signin.json"
        )

        pattern = json.loads(
            path.read_text(encoding="utf-8")
        )

        self.assertEqual(
            pattern["source"], ["aws.signin"]
        )
        self.assertEqual(
            pattern["detail"]["eventName"],
            ["ConsoleLogin"]
        )


if __name__ == "__main__":
    unittest.main()
