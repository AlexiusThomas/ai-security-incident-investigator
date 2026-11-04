
import unittest
from copy import deepcopy
from unittest.mock import patch

from eventbridge_local import route_event


class TestLocalEventBridge(unittest.TestCase):

    def setUp(self):
        self.event = {
            "source": "aws.signin",
            "detail-type": "AWS Console Signin via CloudTrail",
            "detail": {
                "eventID": "LAB-001",
                "eventTime": "2026-11-04T12:00:00Z",
                "eventSource": "signin.amazonaws.com",
                "eventName": "ConsoleLogin",
                "userIdentity": {
                    "userName": "admin"
                },
                "sourceIPAddress": "203.0.113.10",
                "responseElements": {
                    "ConsoleLogin": "Failure"
                }
            }
        }

        self.rules = {
            "severities": {
                "monitored_failed_login": "HIGH",
                "failed_login": "MEDIUM",
                "default": "LOW"
            },
            "monitored_ips": ["203.0.113.10"]
        }

    def invoke(self, event):
        with patch(
            "lambda_security_handler.load_rules",
            return_value=self.rules
        ):
            return route_event(event)

    def test_event_routes_to_lambda(self):
        result = self.invoke(self.event)
        self.assertTrue(result["routed"])
        self.assertTrue(result["lambda_invoked"])

    def test_high_severity_detection(self):
        result = self.invoke(self.event)
        self.assertEqual(
            result["result"]["severity"], "HIGH"
        )

    def test_unrelated_event_ignored(self):
        event = deepcopy(self.event)
        event["source"] = "aws.ec2"

        result = self.invoke(event)

        self.assertFalse(result["routed"])
        self.assertFalse(result["lambda_invoked"])

    def test_successful_login(self):
        event = deepcopy(self.event)
        event["detail"]["responseElements"][
            "ConsoleLogin"
        ] = "Success"

        result = self.invoke(event)

        self.assertEqual(
            result["result"]["event_type"],
            "successful_login"
        )

    def test_no_automatic_remediation(self):
        result = self.invoke(self.event)

        self.assertFalse(
            result["result"]["remediation_executed"]
        )

    def test_invalid_timestamp(self):
        event = deepcopy(self.event)
        del event["detail"]["eventTime"]

        with self.assertRaises(ValueError):
            self.invoke(event)


if __name__ == "__main__":
    unittest.main()
