
"""Day 22: AWS CloudTrail unit and integration tests."""

import unittest
from copy import deepcopy

from cloudtrail_ingest import (
    normalize_cloudtrail,
    analyze_cloudtrail,
)


class TestCloudTrail(unittest.TestCase):

    def setUp(self):
        self.rules = {
            "severities": {
                "monitored_failed_login": "HIGH",
                "failed_login": "MEDIUM",
                "default": "LOW",
            },
            "monitored_ips": ["203.0.113.10"],
        }

        self.event = {
            "eventID": "AWS-001",
            "eventTime": "2026-11-04T12:00:00Z",
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "admin",
            },
            "sourceIPAddress": "203.0.113.10",
            "responseElements": {
                "ConsoleLogin": "Failure",
            },
            "additionalEventData": {"MFAUsed": "No"},
        }

    def test_failed_login(self):
        events = normalize_cloudtrail([self.event])
        self.assertEqual(events[0]["event_type"], "failed_login")

    def test_successful_login(self):
        event = deepcopy(self.event)
        event["responseElements"]["ConsoleLogin"] = "Success"

        events = normalize_cloudtrail([event])
        self.assertEqual(events[0]["event_type"], "successful_login")

    def test_monitored_ip_detection(self):
        result = analyze_cloudtrail([self.event], self.rules)
        self.assertEqual(result["alerts"][0]["severity"], "HIGH")

    def test_correlation(self):
        second = deepcopy(self.event)
        second["eventID"] = "AWS-002"
        second["eventTime"] = "2026-11-04T12:03:00Z"

        result = analyze_cloudtrail(
            [self.event, second],
            self.rules,
        )

        self.assertEqual(len(result["incidents"]), 1)
        self.assertEqual(
            result["incidents"][0]["event_count"], 2
        )

    def test_success_retained_but_not_correlated(self):
        success = deepcopy(self.event)
        success["eventID"] = "AWS-003"
        success["eventTime"] = "2026-11-04T12:04:00Z"
        success["responseElements"]["ConsoleLogin"] = "Success"

        result = analyze_cloudtrail(
            [self.event, success],
            self.rules,
        )

        self.assertEqual(len(result["events"]), 2)
        self.assertEqual(result["alerts"][1]["severity"], "LOW")
        self.assertEqual(len(result["incidents"]), 0)

    def test_invalid_timestamp(self):
        event = deepcopy(self.event)
        event.pop("eventTime")

        with self.assertRaises(ValueError):
            normalize_cloudtrail([event])


if __name__ == "__main__":
    unittest.main()
