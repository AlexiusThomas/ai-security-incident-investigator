
"""Day 38: End-to-end local security integration.

Uses the existing reliability monitor, evaluator,
approval workflow, and remediation simulator.

No live AWS calls or real remediation.
"""

import json
from pathlib import Path

from agent_evaluator import evaluate_agent_run
from approval_workflow import (
    create_approval_request,
    decide_approval_request,
)
from remediation_simulator import simulate_remediation
from reliability_monitor import run_reliable_batch


VALID_DECISIONS = {"APPROVED", "DENIED"}


def run_integrated_workflow(
    cases,
    rules,
    decisions=None,
    output_dir="day38_output",
):
    """Investigate synthetic incidents and process review decisions.

    Decision keys use the format 'case-1/FND-0001'.
    Missing decisions remain PENDING.
    All identities are simulated training roles.
    """

    if decisions is None:
        decisions = {}

    if not isinstance(decisions, dict):
        raise ValueError("decisions must be a dictionary")

    for key, value in decisions.items():
        if (
            not isinstance(key, str)
            or key.count("/") != 1
            or not all(key.split("/"))
            or not isinstance(value, str)
            or value not in VALID_DECISIONS
        ):
            raise ValueError("Invalid decision mapping")

    # 1. Run detection, AI evaluation, and monitoring.
    reliability = run_reliable_batch(
        cases,
        rules,
        output_dir=output_dir,
    )

    batch_dir = Path(reliability["output_directory"])

    outcomes = []

    requested = 0
    approved = 0
    denied = 0
    pending = 0
    simulated = 0

    # 2. Review each completed investigation.
    for case in reliability["cases"]:
        case_id = case["case_id"]

        outcome = {
            "case_id": case_id,
            "status": case["status"],
            "evaluation": case["evaluation"],
            "approval_requests": [],
            "error_type": case["error_type"],
        }

        if case["status"] != "COMPLETE":
            outcomes.append(outcome)
            continue

        try:
            # Refuse ambiguous or missing agent runs.
            agent_root = (
                batch_dir / "agent_runs" / case_id
            )

            run_dirs = sorted(
                path
                for path in agent_root.glob("run-*")
                if path.is_dir()
            )

            if len(run_dirs) != 1:
                raise ValueError(
                    "Ambiguous or missing agent run"
                )

            run_dir = run_dirs[0]

            # 3. Repeat the Day 32 evaluation gate.
            evaluation = evaluate_agent_run(run_dir)

            if evaluation.get("verdict") != "PASS":
                raise ValueError(
                    "Investigation failed evaluation"
                )

            # 4. Load only verified local findings.
            findings_path = (
                run_dir / "findings" / "findings.json"
            )

            findings = json.loads(
                findings_path.read_text(
                    encoding="utf-8"
                )
            )

            if (
                not isinstance(findings, list)
                or len(findings)
                != case["security_findings"]
            ):
                raise ValueError(
                    "Finding count inconsistent"
                )

            # 5. Create one request per finding.
            for finding in findings:
                finding_id = finding["finding_id"]

                request = create_approval_request(
                    run_dir,
                    finding_id,
                    "REVOKE_SESSIONS",
                    "analyst1",
                    "Review suspicious synthetic login activity",
                )

                requested += 1

                decision_key = (
                    f"{case_id}/{finding_id}"
                )

                decision = decisions.get(decision_key)

                item = {
                    "finding_id": finding_id,
                    "request_id": request["request_id"],
                    "status": "PENDING",
                    "simulation_status": None,
                    "real_remediation_executed": False,
                }

                # 6. Only explicit simulated decisions
                # can change the pending approval.
                if decision in VALID_DECISIONS:
                    decided = decide_approval_request(
                        run_dir,
                        request["request_id"],
                        "reviewer1",
                        decision,
                        "Reviewed synthetic evidence for training",
                    )

                    item["status"] = decided["status"]

                    if decision == "APPROVED":
                        # 7. Execute only the Day 34
                        # local simulation.
                        receipt = simulate_remediation(
                            run_dir,
                            request["request_id"],
                            "operator1",
                        )

                        if (
                            receipt["real_remediation_executed"]
                            is not False
                        ):
                            raise ValueError(
                                "Unsafe remediation state"
                            )

                        item["simulation_status"] = (
                            receipt["status"]
                        )

                        simulated += 1
                        approved += 1

                    else:
                        denied += 1

                else:
                    pending += 1

                outcome["approval_requests"].append(
                    item
                )

        except Exception as error:
            # Block this case on any integration error.
            # Do not execute any real remediation.
            outcome["status"] = "BLOCKED"
            outcome["error_type"] = (
                type(error).__name__
            )

        outcomes.append(outcome)

    # 8. Produce the final combined report.
    report = {
        "mode": "LOCAL_SIMULATION",
        "status": (
            "COMPLETE"
            if all(
                item["status"] == "COMPLETE"
                for item in outcomes
            )
            else "PARTIAL_FAILURE"
        ),
        "cases_total": len(outcomes),
        "cases_completed": sum(
            item["status"] == "COMPLETE"
            for item in outcomes
        ),
        "approval_requests_created": requested,
        "approved_requests": approved,
        "denied_requests": denied,
        "pending_requests": pending,
        "simulations_completed": simulated,
        "real_remediation_executed": False,
        "cases": outcomes,
        "output_directory": str(batch_dir),
    }

    report_path = (
        batch_dir / "integrated_report.json"
    )

    report_path.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    return report
