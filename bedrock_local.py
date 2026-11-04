
"""Day 29: Local Amazon Bedrock Converse API simulator."""

import json


class LocalBedrockClient:
    """Deterministic mock; no AWS calls or real LLM inference."""

    def converse(self, *, modelId, messages):
        if modelId != "local-security-simulator":
            raise ValueError("Unsupported simulation model")

        request = json.loads(
            messages[-1]["content"][0]["text"]
        )

        failed_ids = request["failed_event_ids"]
        success_id = request["success_event_id"]

        summary = (
            f"Finding {request['finding_id']}: "
            f"{len(failed_ids)} failed login events for "
            f"user {request['username']} from "
            f"{request['source_ip']} were followed by "
            f"a successful login. "
            f"The detection severity is {request['severity']}. "
            "This activity requires investigation but "
            "does not establish account compromise."
        )

        result = {
            "finding_id": request["finding_id"],
            "severity": request["severity"],
            "summary": summary,
            "evidence_event_ids": failed_ids + [success_id],
            "confirmed_compromise": False,
            "recommended_action": (
                "Review authentication events, verify "
                "account activity and MFA, and escalate "
                "to an authorized responder if needed."
            ),
            "remediation_executed": False,
        }

        return {
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {"text": json.dumps(result)}
                    ],
                }
            },
            "stopReason": "end_turn",
        }
