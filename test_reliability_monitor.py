
"""Day 37: Tests for incident reliability monitoring."""

import json
import tempfile
import unittest
from pathlib import Path

from reliability_monitor import run_reliable_batch


class TestReliabilityMonitor(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        self.output_dir = (
            Path(self.temp.name) / "output"
        )

        self.calls = []

    @staticmethod
    def case(case_id="case-1", marker="synthetic"):
        return {
            "case_id": case_id,
            "events": [{"marker": marker}],
        }

    def runner(self, events, rules, output_dir):
        self.calls.append(
            events[0]["marker"]
        )

        return {
            "status": "COMPLETE",
            "mode": "LOCAL_SIMULATION",
            "remediation_executed": False,
            "output_directory": output_dir,
            "security_findings": 1,
        }

    @staticmethod
    def evaluator(run_dir):
        return {"verdict": "PASS"}

    def execute(
        self,
        cases,
        runner=None,
        evaluator=None,
        max_attempts=3,
    ):
        return run_reliable_batch(
            cases,
            {},
            self.output_dir,
            max_attempts,
            runner=(
                runner if runner is not None
                else self.runner
            ),
            evaluator=(
                evaluator if evaluator is not None
                else self.evaluator
            ),
        )

    def test_successful_case(self):
        report = self.execute([
            self.case()
        ])

        self.assertEqual(
            report["cases_completed"], 1
        )
        self.assertEqual(
            report["attempts_total"], 1
        )
        self.assertEqual(
            report["alerts_raised"], 0
        )

    def test_transient_failure_recovers(self):
        state = {"n": 0}

        def flaky(*args, **kwargs):
            state["n"] += 1

            if state["n"] == 1:
                raise TimeoutError(
                    "temporary synthetic timeout"
                )

            return self.runner(*args, **kwargs)

        report = self.execute(
            [self.case()],
            runner=flaky,
        )

        self.assertEqual(
            report["cases_completed"], 1
        )
        self.assertEqual(
            report["attempts_total"], 2
        )
        self.assertEqual(
            report["cases"][0]["attempts"], 2
        )

    def test_bounded_retries_raise_alert(self):
        def offline(*args, **kwargs):
            raise ConnectionError(
                "simulated offline"
            )

        report = self.execute(
            [self.case()],
            runner=offline,
        )

        self.assertEqual(
            report["attempts_total"], 3
        )
        self.assertEqual(
            report["cases_failed"], 1
        )
        self.assertEqual(
            report["alerts_raised"], 1
        )

    def test_terminal_failure_not_retried(self):
        def invalid(*args, **kwargs):
            raise ValueError("bad event data")

        report = self.execute(
            [self.case()],
            runner=invalid,
        )

        self.assertEqual(
            report["attempts_total"], 1
        )
        self.assertEqual(
            report["cases_failed"], 1
        )

    def test_failure_isolation(self):
        def sometimes_fails(
            events, rules, output_dir
        ):
            if events[0]["marker"] == "bad":
                raise ValueError("bad case")

            return self.runner(
                events, rules, output_dir
            )

        report = self.execute(
            [
                self.case("first", "bad"),
                self.case("second", "good"),
            ],
            runner=sometimes_fails,
        )

        self.assertEqual(
            report["cases_completed"], 1
        )
        self.assertEqual(
            report["cases_failed"], 1
        )
        self.assertEqual(
            report["cases_total"], 2
        )

    def test_failing_evaluation_blocks_result(self):
        report = self.execute(
            [self.case()],
            evaluator=lambda _: {
                "verdict": "FAIL"
            },
        )

        self.assertEqual(
            report["cases_failed"], 1
        )
        self.assertEqual(
            report["attempts_total"], 1
        )

    def test_unsafe_remediation_flag_rejected(self):
        def unsafe(*args, **kwargs):
            result = self.runner(
                *args, **kwargs
            )

            result[
                "remediation_executed"
            ] = True

            return result

        report = self.execute(
            [self.case()],
            runner=unsafe,
        )

        self.assertEqual(
            report["cases_failed"], 1
        )
        self.assertEqual(
            report["attempts_total"], 1
        )

    def test_duplicate_case_ids_rejected(self):
        with self.assertRaises(ValueError):
            self.execute([
                self.case("dup"),
                self.case("dup"),
            ])

    def test_invalid_case_id_rejected(self):
        with self.assertRaises(ValueError):
            self.execute([
                self.case("../invalid")
            ])

    def test_monitoring_log_excludes_event_payload(self):
        secret = "DO-NOT-LOG-THIS-PAYLOAD"

        report = self.execute([
            self.case(marker=secret)
        ])

        path = (
            Path(report["output_directory"])
            / "monitor_events.jsonl"
        )

        self.assertNotIn(
            secret,
            path.read_text(encoding="utf-8"),
        )

    def test_summary_and_jsonl_persisted(self):
        report = self.execute([
            self.case()
        ])

        root = Path(
            report["output_directory"]
        )

        on_disk = json.loads(
            (
                root / "reliability_report.json"
            ).read_text(encoding="utf-8")
        )

        self.assertEqual(
            on_disk["batch_id"],
            report["batch_id"],
        )

        events = [
            json.loads(line)
            for line in (
                root / "monitor_events.jsonl"
            ).read_text(
                encoding="utf-8"
            ).splitlines()
        ]

        self.assertIn(
            "BATCH_COMPLETED",
            [
                event["event"]
                for event in events
            ],
        )

    def test_no_remediation_even_on_success(self):
        report = self.execute([
            self.case()
        ])

        self.assertIs(
            report["remediation_executed"],
            False,
        )
        self.assertEqual(
            report["mode"],
            "LOCAL_SIMULATION",
        )


if __name__ == "__main__":
    unittest.main()
