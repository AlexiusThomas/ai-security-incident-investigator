
"""Day 36: Security CI workflow configuration smoke tests."""

import unittest
from pathlib import Path


class TestSecurityCI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        root = Path(__file__).resolve().parent

        cls.workflow = (
            root / ".github" / "workflows" / "security-checks.yml"
        ).read_text(encoding="utf-8")

    def test_read_only_github_permissions(self):
        self.assertIn("contents: read", self.workflow)

    def test_bandit_scan_configured(self):
        self.assertIn(
            "python -m bandit -q -ll -ii",
            self.workflow
        )

    def test_dependency_audit_configured(self):
        self.assertIn(
            "python -m pip_audit -r requirements.txt",
            self.workflow
        )

    def test_terraform_validation_configured(self):
        self.assertIn(
            "terraform -chdir=infra/day35 validate",
            self.workflow
        )

    def test_lambda_package_built_before_validation(self):
        build = self.workflow.index(
            "zip -q -j infra/day35/build/security-handler.zip"
        )

        validate = self.workflow.index(
            "terraform -chdir=infra/day35 validate"
        )

        self.assertLess(build, validate)

    def test_no_aws_deployment(self):
        self.assertNotIn("terraform apply", self.workflow)
        self.assertNotIn(
            "aws-actions/configure-aws-credentials",
            self.workflow
        )


if __name__ == "__main__":
    unittest.main()

