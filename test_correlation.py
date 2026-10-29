
import unittest
from correlate import correlate_events


def make_event(event_id, minute, user="admin",
               ip="10.0.1.5", severity="HIGH"):
    return {
        "event_id": event_id,
        "timestamp": f"2026-10-29T10:{minute:02d}:00Z",
        "source": "windows",
        "event_type": "failed_login",
        "username": user,
        "source_ip": ip,
        "severity": severity
    }


class TestCorrelation(unittest.TestCase):

    def test_related_events(self):
        events = [
            make_event("a", 0),
            make_event("b", 2)
        ]
        result = correlate_events(events)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["event_count"], 2)

    def test_outside_window(self):
        events = [
            make_event("a", 0),
            make_event("b", 12)
        ]
        self.assertEqual(len(correlate_events(events)), 0)

    def test_different_users(self):
        events = [
            make_event("a", 0, user="admin"),
            make_event("b", 2, user="guest")
        ]
        self.assertEqual(len(correlate_events(events)), 0)

    def test_unsorted_events(self):
        events = [
            make_event("b", 2),
            make_event("a", 0)
        ]
        result = correlate_events(events)
        self.assertEqual(result[0]["event_ids"], ["a", "b"])

    def test_exact_window_boundary(self):
        events = [
            make_event("a", 0),
            make_event("b", 5)
        ]
        self.assertEqual(len(correlate_events(events)), 1)

    def test_info_ignored(self):
        events = [
            make_event("a", 0),
            make_event("b", 2, severity="INFO")
        ]
        self.assertEqual(len(correlate_events(events)), 0)

    def test_missing_timestamp(self):
        event = make_event("a", 0)
        event.pop("timestamp")
        with self.assertRaises(ValueError):
            correlate_events([event])

    def test_medium_severity(self):
        events = [
            make_event("a", 0, severity="MEDIUM"),
            make_event("b", 2, severity="MEDIUM")
        ]
        result = correlate_events(events)
        self.assertEqual(result[0]["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main(verbosity=2)
