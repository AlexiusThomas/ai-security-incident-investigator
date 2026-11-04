
"""Day 23: Login sequence detection tests."""

import unittest

from login_sequence_detector import (
    detect_login_sequences,
    analyze_login_sequences
)


def event(event_id, minute, outcome, user="admin", ip="203.0.113.10"):
    return {
        "event_id": event_id,
        "timestamp": f"2026-11-04T12:{minute:02d}:00Z",
        "source": "aws",
        "event_type": outcome,
        "username": user,
        "source_ip": ip,
    }


class TestLoginSequences(unittest.TestCase):

    def setUp(self):
        self.events = [
            event("E001", 0, "failed_login"),
            event("E002", 2, "failed_login"),
            event("E003", 4, "successful_login"),
        ]

    def test_detects_suspicious_success(self):
        findings = detect_login_sequences(self.events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_evidence_ids(self):
        findings = detect_login_sequences(self.events)
        self.assertEqual(
            findings[0]["failure_event_ids"],
            ["E001", "E002"]
        )
        self.assertEqual(
            findings[0]["success_event_id"], "E003"
        )

    def test_one_failure_not_enough(self):
        findings = detect_login_sequences([
            self.events[0], self.events[2]
        ])
        self.assertEqual(len(findings), 0)

    def test_outside_window(self):
        events = [
            event("E001", 0, "failed_login"),
            event("E002", 2, "failed_login"),
            event("E003", 10, "successful_login"),
        ]
        self.assertEqual(len(detect_login_sequences(events)), 0)

    def test_different_user(self):
        events = [
            self.events[0],
            self.events[1],
            event("E003", 4, "successful_login", user="other"),
        ]
        self.assertEqual(len(detect_login_sequences(events)), 0)

    def test_different_ip(self):
        events = [
            self.events[0],
            self.events[1],
            event(
                "E003", 4, "successful_login",
                ip="198.51.100.20"
            ),
        ]
        self.assertEqual(len(detect_login_sequences(events)), 0)

    def test_unsorted_events(self):
        findings = detect_login_sequences(
            list(reversed(self.events))
        )
        self.assertEqual(len(findings), 1)

    def test_duplicate_failure_id(self):
        events = [
            event("E001", 0, "failed_login"),
            event("E001", 2, "failed_login"),
            event("E003", 4, "successful_login"),
        ]
        self.assertEqual(len(detect_login_sequences(events)), 0)


if __name__ == "__main__":
    unittest.main()

