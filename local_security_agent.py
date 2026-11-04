
"""Day 31: Controlled local AI security agent orchestration."""

import json
import uuid
from pathlib import Path

from day24_findings import run_day24
from evidence_store import save_evidence
from ai_summary_pipeline import summarize_verified_finding


class LocalSecurityAgent:
    """Run approved security tools with a step limit and audit trail."""

    def __init__(self, output_dir, max_steps=12):
        if type(max_steps) is not int or max_steps < 1:
            raise ValueError("max_steps must be a positive integer")

        self.output = Path(output_dir)
        self.max_steps = max_steps
        self.steps = 0
        self.audit = []

        # Explicit allowlist: no shell, AWS mutations or remediation.
        self.allowed_tools = {
            "detect": self._detect,
            "store_evidence": self._store_evidence,
            "summarize": self._summarize,
        }

    def execute(self, tool_name, **kwargs):
        """Execute only an approved tool."""

        if tool_name not in self.allowed_tools:
            self.audit.append({
                "tool": tool_name,
                "status": "DENIED"
            })
            raise PermissionError(
                f"Unauthorized agent tool: {tool_name}"
            )

        if self.steps >= self.max_steps:
            self.audit.append({
                "tool": tool_name,
                "status": "BLOCKED_STEP_LIMIT"
            })
            raise RuntimeError("Agent step limit reached")

        self.steps += 1

        try:
            result = self.allowed_tools[tool_name](**kwargs)
        except Exception as exc:
            self.audit.append({
                "step": self.steps,
                "tool": tool_name,
                "status": "FAILED",
                "error_type": type(exc).__name__,
            })
            raise

        self.audit.append({
            "step": self.steps,
            "tool": tool_name,
            "status": "SUCCESS",
        })

        return result

    def _detect(self, events, rules):
        return run_day24(
            events,
            rules,
            self.output / "findings"
        )

    def _store_evidence(self, finding):
        return save_evidence(
            self.output / "local_s3",
            finding["finding_id"],
            finding
        )

    def _summarize(self, evidence_id):
        return summarize_verified_finding(
            self.output / "local_s3",
            evidence_id,
            self.output / "ai_reports"
        )


def run_security_agent(
    events,
    rules,
    output_dir="day31_output",
    max_steps=12
):
    """Run the controlled local security investigation workflow."""

    run_id = f"run-{uuid.uuid4().hex[:12]}"
    run_dir = Path(output_dir) / run_id

    # Never overwrite an earlier run.
    run_dir.mkdir(parents=True, exist_ok=False)

    agent = LocalSecurityAgent(
        output_dir=run_dir,
        max_steps=max_steps
    )

    # Step 1: Detect suspicious login sequences.
    detection = agent.execute(
        "detect",
        events=events,
        rules=rules
    )

    findings_path = run_dir / "findings" / "findings.json"

    findings = json.loads(
        findings_path.read_text(encoding="utf-8")
    )

    # Check the budget before processing evidence.
    required_steps = len(findings) * 2

    if agent.steps + required_steps > max_steps:
        raise RuntimeError(
            "Insufficient approved steps for all findings"
        )

    report_files = []

    # Step 2: Process each detected finding.
    for finding in findings:
        evidence_id = finding["finding_id"]

        # Store immutable-by-convention local evidence.
        agent.execute(
            "store_evidence",
            finding=finding
        )

        # Verify evidence and produce a guarded summary.
        summary = agent.execute(
            "summarize",
            evidence_id=evidence_id
        )

        if (
            summary["evidence_integrity"] != "VERIFIED"
            or summary["report"]["remediation_executed"] is not False
        ):
            raise ValueError(
                "Agent safety verification failed"
            )

        report_files.append(str(
            run_dir / "ai_reports"
            / f"{evidence_id}-ai-summary.json"
        ))

    # Step 3: Save a complete workflow audit record.
    result = {
        "run_id": run_id,
        "mode": "LOCAL_SIMULATION",
        "status": "COMPLETE",
        "events_processed": detection["cloudtrail_events"],
        "security_findings": len(findings),
        "ai_reports": len(report_files),
        "finding_ids": [
            finding["finding_id"]
            for finding in findings
        ],
        "report_files": report_files,
        "tools_executed": agent.steps,
        "audit_trail": agent.audit,
        "analyst_review_required": bool(findings),
        "remediation_executed": False,
        "output_directory": str(run_dir)
    }

    (run_dir / "agent_run.json").write_text(
        json.dumps(result, indent=2),
        encoding="utf-8"
    )

    return result


if __name__ == "__main__":

    def event(event_id, minute, outcome):
        return {
            "eventID": event_id,
            "eventTime": (
                f"2026-11-04T12:{minute:02d}:00Z"
            ),
            "eventSource": "signin.amazonaws.com",
            "eventName": "ConsoleLogin",
            "userIdentity": {
                "type": "IAMUser",
                "userName": "admin"
            },
            "sourceIPAddress": "203.0.113.10",
            "responseElements": {
                "ConsoleLogin": outcome
            }
        }

    events = [
        event("AWS-001", 0, "Failure"),
        event("AWS-002", 2, "Failure"),
        event("AWS-003", 4, "Success"),
    ]

    rules = {
        "severities": {
            "monitored_failed_login": "HIGH",
            "failed_login": "MEDIUM",
            "default": "LOW"
        },
        "monitored_ips": ["203.0.113.10"]
    }

    result = run_security_agent(events, rules)

    print(json.dumps(result, indent=2))
    print("DAY 31 AGENT ORCHESTRATION: PASSED")
