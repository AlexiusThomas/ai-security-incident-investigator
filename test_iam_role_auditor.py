
import json
import unittest
from unittest.mock import Mock
from urllib.parse import quote

from iam_role_auditor import audit_policy, audit_role


class TestIAMAuditor(unittest.TestCase):

    def test_admin_wildcard(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }
        findings = audit_policy(policy)
        self.assertTrue(any(
            f["severity"] == "HIGH" for f in findings
        ))

    def test_least_privilege(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::example-bucket/incidents/*"
            }]
        }
        self.assertEqual(audit_policy(policy), [])

    def test_wildcard_resource(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }
        findings = audit_policy(policy)
        self.assertTrue(any(
            f["severity"] == "REVIEW" for f in findings
        ))

    def test_not_action(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "NotAction": "iam:DeleteRole",
                "Resource": "*"
            }]
        }
        self.assertTrue(any(
            f["severity"] == "HIGH"
            for f in audit_policy(policy)
        ))

    def test_explicit_deny_not_flagged(self):
        policy = {
            "Statement": [{
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*"
            }]
        }
        self.assertEqual(audit_policy(policy), [])

    def test_url_encoded_document(self):
        policy = {
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }
        encoded = quote(json.dumps(policy))
        self.assertTrue(audit_policy(encoded))

    def test_mocked_boto3_role(self):
        client = Mock()

        attached = Mock()
        attached.paginate.return_value = [{
            "AttachedPolicies": [{
                "PolicyName": "BroadPolicy",
                "PolicyArn": "arn:aws:iam::123456789012:policy/Broad"
            }]
        }]

        inline = Mock()
        inline.paginate.return_value = [{
            "PolicyNames": ["LimitedPolicy"]
        }]

        client.get_paginator.side_effect = lambda name: {
            "list_attached_role_policies": attached,
            "list_role_policies": inline,
        }[name]

        client.get_policy.return_value = {
            "Policy": {"DefaultVersionId": "v1"}
        }

        client.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": "*",
                        "Resource": "*"
                    }]
                }
            }
        }

        client.get_role_policy.return_value = {
            "PolicyDocument": {
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::example-bucket/incidents/*"
                }]
            }
        }

        result = audit_role(client, "TestRole")

        self.assertEqual(result["policies_checked"], 2)
        self.assertTrue(result["findings"])
        self.assertFalse(result["remediation_executed"])


if __name__ == "__main__":
    unittest.main()
