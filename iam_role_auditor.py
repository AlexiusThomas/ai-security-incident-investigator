
"""Day 25: Read-only AWS IAM policy security auditor."""

import argparse
import json
from pathlib import Path
from urllib.parse import unquote


def parse_document(document):
    """Accept decoded or URL-encoded IAM policy documents."""
    if isinstance(document, str):
        document = json.loads(unquote(document))

    if not isinstance(document, dict):
        raise ValueError("Invalid IAM policy document")

    return document


def as_list(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(
        isinstance(item, str) for item in value
    ):
        return value
    raise ValueError("Expected a string or list of strings")


def audit_policy(document, policy_name="Unknown"):
    """Identify potentially excessive IAM permissions."""

    document = parse_document(document)
    statements = document.get("Statement", [])

    if isinstance(statements, dict):
        statements = [statements]

    if not isinstance(statements, list):
        raise ValueError("Invalid policy statements")

    findings = []

    for number, statement in enumerate(statements, 1):
        if not isinstance(statement, dict):
            raise ValueError("Invalid policy statement")

        if statement.get("Effect") != "Allow":
            continue

        def flag(severity, issue):
            findings.append({
                "policy": policy_name,
                "statement": number,
                "severity": severity,
                "issue": issue,
            })

        if "NotAction" in statement:
            flag("HIGH", "NotAction requires careful review")

        if "NotResource" in statement:
            flag("HIGH", "NotResource requires careful review")

        actions = as_list(statement.get("Action", []))
        resources = as_list(statement.get("Resource", []))

        if "*" in actions:
            flag("HIGH", "Wildcard allows all AWS actions")
        elif any(a.lower() == "iam:*" for a in actions):
            flag("HIGH", "All IAM actions allowed")
        elif any(a.endswith(":*") for a in actions):
            flag("MEDIUM", "Entire AWS service action family allowed")

        if "*" in resources:
            flag(
                "REVIEW",
                "Wildcard resource; verify action and conditions"
            )

    return findings


def audit_role(iam_client, role_name):
    """Read attached and inline policies from an IAM role."""

    policies = []

    attached = iam_client.get_paginator(
        "list_attached_role_policies"
    )

    for page in attached.paginate(RoleName=role_name):
        for policy in page.get("AttachedPolicies", []):
            arn = policy["PolicyArn"]

            details = iam_client.get_policy(PolicyArn=arn)
            version = details["Policy"]["DefaultVersionId"]

            response = iam_client.get_policy_version(
                PolicyArn=arn,
                VersionId=version,
            )

            policies.append((
                policy["PolicyName"],
                response["PolicyVersion"]["Document"]
            ))

    inline = iam_client.get_paginator("list_role_policies")

    for page in inline.paginate(RoleName=role_name):
        for name in page.get("PolicyNames", []):
            response = iam_client.get_role_policy(
                RoleName=role_name,
                PolicyName=name,
            )

            policies.append((
                name,
                response["PolicyDocument"]
            ))

    findings = []

    for name, document in policies:
        findings.extend(audit_policy(document, name))

    return {
        "role": role_name,
        "policies_checked": len(policies),
        "findings": findings,
        "remediation_executed": False,
    }


def main():
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--policy-file")
    source.add_argument("--role")
    parser.add_argument(
        "--output", default="day25_output/iam_audit.json"
    )
    args = parser.parse_args()

    if args.policy_file:
        policy = json.loads(
            Path(args.policy_file).read_text(encoding="utf-8")
        )
        result = {
            "policy": args.policy_file,
            "findings": audit_policy(policy, args.policy_file),
            "remediation_executed": False,
        }
    else:
        import boto3
        result = audit_role(boto3.client("iam"), args.role)

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(result, indent=2), encoding="utf-8"
    )

    print(json.dumps(result, indent=2))
    print(f"Saved: {output}")


if __name__ == "__main__":
    main()

