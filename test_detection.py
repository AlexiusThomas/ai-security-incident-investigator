
import unittest
from detection_engine import classify_event

RULES = {
    "monitored_ips": ["10.0.1.5"],
    "severities": {
        "monitored_failed_login": "HIGH",
        "failed_login": "MEDIUM",
        "default": "INFO"
    }
}


class TestDetection(unittest.TestCase):

    def test_high(self):
        event = {
            "event_type": "failed_login",
            "source_ip": "10.0.1.5"
        }
        result = classify_event(event, RULES)
        self.assertEqual(result["severity"], "HIGH")

    def test_medium(self):
        event = {
            "event_type": "failed_login",
            "source_ip": "192.0.2.20"
        }
        result = classify_event(event, RULES)
        self.assertEqual(result["severity"], "MEDIUM")

    def test_info(self):
        event = {
            "event_type": "file_access",
            "source_ip": "192.0.2.20"
        }
        result = classify_event(event, RULES)
        self.assertEqual(result["severity"], "INFO")


if __name__ == "__main__":
    unittest.main(verbosity=2)
