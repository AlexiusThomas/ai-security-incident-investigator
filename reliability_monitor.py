
"""Day 37: Local reliability monitoring for the security investigator.

No AWS access, real remediation, or background jobs.
"""

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from agent_evaluator import evaluate_agent_run
from local_security_agent import run_security_agent


RETRYABLE_ERRORS = (TimeoutError, ConnectionError)

CASE_ID_PATTERN = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}\Z"
)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _log_event(
    path,
    event,
    case_id=None,
    attempt=None,
    error_type=None,
):
    """Log metadata only, never incident event payloads."""

    record = {
        "timestamp_utc": _now(),
        "event": event,
        "case_id": case_id,
        "attempt": attempt,
    }

    if error_type is not None:
        record["error_type"] = error_type

    with path.open("a", encoding="utf-8") as stream:
        stream.write(
            json.dumps(record, sort_keys=True) + "\n"
        )


def run_reliable_batch(
    cases,
    rules,
    output_dir="day37_output",
    max_attempts=3,
    runner=None,
    evaluator=None,
):
    """Process independent synthetic cases with bounded retries."""

    if (
        type(max_attempts) is not int
        or not 1 <= max_attempts <= 5
    ):
        raise ValueError(
            "max_attempts must be an integer from 1 to 5"
        )

    if not isinstance(cases, list) or not cases:
        raise ValueError("cases must be a nonempty list")

    if not isinstance(rules, dict):
        raise ValueError("rules must be a dictionary")

    seen = set()

    for case in cases:
        if not isinstance(case, dict):
            raise ValueError(
                "each case must be a dictionary"
            )

        case_id = case.get("case_id")

        if (
            not isinstance(case_id, str)
            or not CASE_ID_PATTERN.fullmatch(case_id)
        ):
            raise ValueError("invalid case_id")

        if case_id in seen:
            raise ValueError("duplicate case_id")

        seen.add(case_id)

        if not isinstance(case.get("events"), list):
            raise ValueError(
                "case events must be a list"
            )

    if runner is None:
        runner = run_security_agent

    if evaluator is None:
        evaluator = evaluate_agent_run

    if not callable(runner) or not callable(evaluator):
        raise ValueError(
            "runner and evaluator must be callable"
        )

    batch_dir = (
        Path(output_dir)
        / f"batch-{uuid.uuid4().hex[:12]}"
    )

    batch_dir.mkdir(
        parents=True,
        exist_ok=False,
    )

    log_path = batch_dir / "monitor_events.jsonl"

    summaries = []
    alerts = []
    attempts_total = 0

    for case in cases:
        case_id = case["case_id"]

        case_summary = {
            "case_id": case_id,
            "status": "FAILED",
            "attempts": 0,
            "security_findings": None,
            "evaluation": None,
            "error_type": None,
        }

        for attempt in range(1, max_attempts + 1):
            attempts_total += 1
            case_summary["attempts"] = attempt

            _log_event(
                log_path,
                "ATTEMPT_STARTED",
                case_id,
                attempt,
            )

            try:
                result = runner(
                    case["events"],
                    rules,
                    output_dir=str(
                        batch_dir
                        / "agent_runs"
                        / case_id
                    ),
                )

                if not isinstance(result, dict):
                    raise ValueError(
                        "invalid agent result"
                    )

                if (
                    result.get("status") != "COMPLETE"
                    or result.get("mode")
                    != "LOCAL_SIMULATION"
                    or result.get("remediation_executed")
                    is not False
                    or not isinstance(
                        result.get("output_directory"),
                        str,
                    )
                ):
                    raise ValueError(
                        "unsafe or incomplete agent result"
                    )

                # Day 32 evaluation gate.
                evaluation = evaluator(
                    result["output_directory"]
                )

                if (
                    not isinstance(evaluation, dict)
                    or evaluation.get("verdict") != "PASS"
                ):
                    raise ValueError(
                        "agent evaluation failed"
                    )

                case_summary["status"] = "COMPLETE"
                case_summary["security_findings"] = (
                    result.get("security_findings", 0)
                )
                case_summary["evaluation"] = "PASS"

                _log_event(
                    log_path,
                    "CASE_COMPLETED",
                    case_id,
                    attempt,
                )

                break

            except Exception as error:
                # Do not log exception messages.
                # They may contain sensitive event data.
                error_type = type(error).__name__

                case_summary["error_type"] = error_type

                _log_event(
                    log_path,
                    "ATTEMPT_FAILED",
                    case_id,
                    attempt,
                    error_type,
                )

                # Retry only known transient errors.
                if (
                    isinstance(error, RETRYABLE_ERRORS)
                    and attempt < max_attempts
                ):
                    _log_event(
                        log_path,
                        "RETRY_SCHEDULED",
                        case_id,
                        attempt,
                    )
                    continue

                # Terminal failure: alert and move on.
                alerts.append({
                    "case_id": case_id,
                    "severity": "HIGH",
                    "reason": "INVESTIGATION_FAILED",
                    "error_type": error_type,
                })

                _log_event(
                    log_path,
                    "ALERT_RAISED",
                    case_id,
                    attempt,
                    error_type,
                )

                break

        summaries.append(case_summary)

    completed = sum(
        item["status"] == "COMPLETE"
        for item in summaries
    )

    report = {
        "batch_id": batch_dir.name,
        "timestamp_utc": _now(),
        "mode": "LOCAL_SIMULATION",
        "status": (
            "COMPLETE"
            if completed == len(cases)
            else "PARTIAL_FAILURE"
        ),
        "cases_total": len(cases),
        "cases_completed": completed,
        "cases_failed": len(cases) - completed,
        "attempts_total": attempts_total,
        "alerts_raised": len(alerts),
        "cases": summaries,
        "alerts": alerts,
        "remediation_executed": False,
        "output_directory": str(batch_dir),
    }

    report_path = (
        batch_dir / "reliability_report.json"
    )

    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    _log_event(
        log_path,
        "BATCH_COMPLETED",
    )

    return report
