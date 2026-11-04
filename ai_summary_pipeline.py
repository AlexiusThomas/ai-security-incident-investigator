
"""Day 30: Evidence-grounded AI incident summarization with security guardrails."""

import json
from pathlib import Path

from bedrock_local import LocalBedrockClient
from evidence_store import verify_evidence
from ai_guardrails import validate_facts, enforce_guardrails


def summarize_verified_finding(
    evidence_root,
    evidence_id,
    output_dir="day29_output",
    client=None
):
    """Verify evidence and produce a protected AI incident summary."""

    root = Path(evidence_root)

    # STEP 1: Verify evidence integrity.
    verification = verify_evidence(root, evidence_id)

    if not verification["verified"]:
        raise ValueError("Evidence integrity verification failed")

    # STEP 2: Load verified security evidence.
    object_path = root / "objects" / f"{evidence_id}.json"

    finding = json.loads(
        object_path.read_text(encoding="utf-8")
    )

    if finding.get("finding_id") != evidence_id:
        raise ValueError("Evidence ID mismatch")

    evidence = finding["evidence"]
    failed_ids = evidence["failed_event_ids"]
    success_id = evidence["success_event_id"]

    if (
        not isinstance(failed_ids, list)
        or not failed_ids
        or not all(
            isinstance(item, str) and item
            for item in failed_ids
        )
        or not isinstance(success_id, str)
        or not success_id
    ):
        raise ValueError("Invalid evidence references")

    # STEP 3: Extract only approved evidence fields.
    facts = {
        "finding_id": evidence_id,
        "severity": finding["severity"],
        "username": finding["username"],
        "source_ip": finding["source_ip"],
        "failed_event_ids": failed_ids,
        "success_event_id": success_id,
        "start_time": evidence["start_time"],
        "success_time": evidence["success_time"],
    }

    # STEP 4: Validate evidence before sending it to the model.
    # Reject malformed IDs, suspicious usernames,
    # invalid IP addresses and inconsistent timestamps.
    validate_facts(facts)

    # STEP 5: Initialize local Bedrock simulator.
    if client is None:
        client = LocalBedrockClient()

    # STEP 6: Request an incident summary.
    # Only validated facts are passed to the simulator.
    response = client.converse(
        modelId="local-security-simulator",
        messages=[{
            "role": "user",
            "content": [{
                "text": json.dumps(facts)
            }]
        }]
    )

    # STEP 7: Parse the simulated AI response.
    draft = json.loads(
        response["output"]["message"]["content"][0]["text"]
    )

    # STEP 8: Reject factual contradictions.
    if (
        not isinstance(draft, dict)
        or draft.get("finding_id") != evidence_id
        or draft.get("severity") != facts["severity"]
        or draft.get("evidence_event_ids")
        != failed_ids + [success_id]
        or draft.get("confirmed_compromise") is not False
        or draft.get("remediation_executed") is not False
        or not isinstance(draft.get("summary"), str)
        or not draft["summary"].strip()
    ):
        raise ValueError("Model output failed evidence validation")

    # STEP 9: Enforce Day 30 security guardrails.
    # Reject unauthorized fields and unverified claims.
    # Reconstruct the report using validated evidence.
    draft = enforce_guardrails(facts, draft)

    # STEP 10: Build the protected report.
    result = {
        "model": "LOCAL_BEDROCK_SIMULATOR",
        "evidence_integrity": "VERIFIED",
        "analyst_review_required": True,
        "report": draft,
    }

    # STEP 11: Save the protected report.
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)

    report_path = output / f"{evidence_id}-ai-summary.json"

    report_path.write_text(
        json.dumps(result, indent=2),
        encoding="utf-8"
    )

    return result


if __name__ == "__main__":
    result = summarize_verified_finding(
        "day28_output/local_s3",
        "FND-0001",
    )

    print(json.dumps(result, indent=2))
    print("DAY 30 PROTECTED AI SUMMARY: PASSED")
