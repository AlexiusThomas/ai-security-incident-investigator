
"""Day 39: Strict input gate for the LOCAL security lab.

Input validation and sanitization, not authentication.
No AWS access or real remediation.
"""

import ipaddress
import re
from datetime import datetime

from capstone_integration import run_integrated_workflow


MAX_CASES = 20
MAX_EVENTS_PER_CASE = 100

CASE_ID_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_-]{0,47}\Z"
)

EVENT_ID_RE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z"
)

USERNAME_RE = re.compile(
    r"[A-Za-z0-9_+=,.@-]{1,64}\Z"
)

FINDING_ID_RE = re.compile(
    r"FND-[0-9]{4,8}\Z"
)

TIME_RE = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
)

SEVERITIES = {
    "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
}


class SecurityGateError(ValueError):
    """Reject invalid input without logging its contents."""


def _ip(value):
    if not isinstance(value, str):
        raise SecurityGateError("Invalid IP address")

    try:
        return str(ipaddress.ip_address(value))
    except ValueError as exc:
        raise SecurityGateError(
            "Invalid IP address"
        ) from exc


def _safe_rules(rules):
    if (
        not isinstance(rules, dict)
        or set(rules) != {
            "severities", "monitored_ips"
        }
    ):
        raise SecurityGateError(
            "Invalid detection rules"
        )

    severities = rules["severities"]
    ips = rules["monitored_ips"]

    if (
        not isinstance(severities, dict)
        or not 1 <= len(severities) <= 20
        or not isinstance(ips, list)
        or len(ips) > 100
    ):
        raise SecurityGateError(
            "Invalid detection rules"
        )

    cleaned = {}

    for key, value in severities.items():
        if (
            not isinstance(key, str)
            or not re.fullmatch(
                r"[a-z][a-z0-9_]{0,63}", key
            )
            or not isinstance(value, str)
            or value not in SEVERITIES
        ):
            raise SecurityGateError(
                "Invalid severity rule"
            )

        cleaned[key] = value

    return {
        "severities": cleaned,
        "monitored_ips": [
            _ip(ip) for ip in ips
        ],
    }


def _safe_event(event):
    if not isinstance(event, dict):
        raise SecurityGateError(
            "Invalid event shape"
        )

    event_id = event.get("eventID")

    if (
        not isinstance(event_id, str)
        or not EVENT_ID_RE.fullmatch(event_id)
    ):
        raise SecurityGateError(
            "Invalid event ID"
        )

    timestamp = event.get("eventTime")

    if (
        not isinstance(timestamp, str)
        or not TIME_RE.fullmatch(timestamp)
    ):
        raise SecurityGateError(
            "Invalid event timestamp"
        )

    try:
        datetime.strptime(
            timestamp,
            "%Y-%m-%dT%H:%M:%SZ",
        )
    except ValueError as exc:
        raise SecurityGateError(
            "Invalid event timestamp"
        ) from exc

    if (
        event.get("eventSource")
        != "signin.amazonaws.com"
        or event.get("eventName")
        != "ConsoleLogin"
    ):
        raise SecurityGateError(
            "Unsupported event source or name"
        )

    identity = event.get("userIdentity")

    if (
        not isinstance(identity, dict)
        or identity.get("type") != "IAMUser"
    ):
        raise SecurityGateError(
            "Unsupported identity type"
        )

    username = identity.get("userName")

    if (
        not isinstance(username, str)
        or not USERNAME_RE.fullmatch(username)
    ):
        raise SecurityGateError(
            "Invalid username"
        )

    elements = event.get("responseElements")

    if not isinstance(elements, dict):
        raise SecurityGateError(
            "Invalid login response"
        )

    outcome = elements.get("ConsoleLogin")

    if outcome not in ("Success", "Failure"):
        raise SecurityGateError(
            "Invalid login outcome"
        )

    # Drop extra, untrusted metadata before the
    # event reaches the AI security investigator.
    return {
        "eventID": event_id,
        "eventTime": timestamp,
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "userIdentity": {
            "type": "IAMUser",
            "userName": username,
        },
        "sourceIPAddress": _ip(
            event.get("sourceIPAddress")
        ),
        "responseElements": {
            "ConsoleLogin": outcome
        },
    }


def validate_and_sanitize(
    cases,
    rules,
    decisions=None,
):
    """Validate the entire batch before running the agent."""

    if (
        not isinstance(cases, list)
        or not 1 <= len(cases) <= MAX_CASES
    ):
        raise SecurityGateError(
            "Invalid number of cases"
        )

    safe_cases = []
    case_ids = set()

    for case in cases:
        if not isinstance(case, dict):
            raise SecurityGateError("Invalid case")

        case_id = case.get("case_id")

        if (
            not isinstance(case_id, str)
            or not CASE_ID_RE.fullmatch(case_id)
        ):
            raise SecurityGateError(
                "Invalid case ID"
            )

        if case_id in case_ids:
            raise SecurityGateError(
                "Duplicate case ID"
            )

        case_ids.add(case_id)

        events = case.get("events")

        if (
            not isinstance(events, list)
            or not 1 <= len(events)
            <= MAX_EVENTS_PER_CASE
        ):
            raise SecurityGateError(
                "Invalid number of events"
            )

        cleaned_events = []
        seen_ids = set()

        for event in events:
            cleaned = _safe_event(event)

            if cleaned["eventID"] in seen_ids:
                raise SecurityGateError(
                    "Duplicate event ID"
                )

            seen_ids.add(
                cleaned["eventID"]
            )

            cleaned_events.append(cleaned)

        safe_cases.append({
            "case_id": case_id,
            "events": cleaned_events,
        })

    clean_rules = _safe_rules(rules)

    if decisions is None:
        decisions = {}

    if (
        not isinstance(decisions, dict)
        or len(decisions) > MAX_CASES * 10
    ):
        raise SecurityGateError(
            "Invalid decision mapping"
        )

    clean_decisions = {}

    for key, decision in decisions.items():
        if (
            not isinstance(key, str)
            or key.count("/") != 1
        ):
            raise SecurityGateError(
                "Invalid decision key"
            )

        case_id, finding_id = key.split("/")

        if (
            case_id not in case_ids
            or not FINDING_ID_RE.fullmatch(
                finding_id
            )
        ):
            raise SecurityGateError(
                "Decision does not match a valid case"
            )

        if decision not in (
            "APPROVED", "DENIED"
        ):
            raise SecurityGateError(
                "Invalid decision value"
            )

        clean_decisions[key] = decision

    return (
        safe_cases,
        clean_rules,
        clean_decisions,
    )


def run_secure_capstone(
    cases,
    rules,
    decisions=None,
    output_dir="day39_output",
):
    """Security preflight followed by Day 38 integration."""

    safe_cases, safe_rules, safe_decisions = (
        validate_and_sanitize(
            cases, rules, decisions
        )
    )

    return run_integrated_workflow(
        safe_cases,
        safe_rules,
        decisions=safe_decisions,
        output_dir=output_dir,
    )
