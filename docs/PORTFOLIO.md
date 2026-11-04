

\# AI Security Incident Investigator



\## Project Summary



Built a Python-based AI security incident investigation

prototype to demonstrate cloud security automation,

AI guardrails, incident detection, and DevSecOps.



The system processes synthetic AWS CloudTrail-style

events, correlates suspicious login activity, preserves

verifiable evidence, produces grounded investigation

summaries, and evaluates results before a simulated

approval and remediation workflow.



\## Technologies



Python 3.13, JSON, unittest, GitHub Actions,

Terraform, Bandit, pip-audit, and AWS-style

EventBridge, Lambda, CloudTrail, IAM, S3, CloudWatch,

and Bedrock architecture patterns.



\## Engineering Highlights



\- Implemented detection and correlation rules for

&#x20; repeated login failures followed by success.

\- Created a local evidence store with SHA-256 integrity

&#x20; verification.

\- Integrated deterministic Bedrock-style AI summaries

&#x20; with evidence-grounding guardrails.

\- Built a security agent using an allowlisted set of tools.

\- Added agent evaluation, audit logging, and simulated

&#x20; role-based approval controls.

\- Implemented approved remediation simulations without

&#x20; changing real cloud resources.

\- Added reliability monitoring, bounded retries,

&#x20; structured logs, and failure isolation.

\- Built adversarial tests for malicious input, duplicate

&#x20; events, forged event fields, and evidence tampering.

\- Created and locally validated a Terraform AWS

&#x20; infrastructure blueprint.

\- Added automated Python and infrastructure security

&#x20; checks through GitHub Actions.



\## Demonstration



Run:



&#x20;   py capstone\_final.py



The final acceptance test exercises:



1\. Pending approval: no simulation.

2\. Approved request: local simulation only.

3\. Denied request: no simulation.

4\. Invalid approval override: rejected.

5\. Untrusted event metadata: removed.

6\. Path traversal attempt: rejected.



\## Verification



Run all Python regression tests:



&#x20;   py -m unittest discover -s . -p "test\_\*.py" -q



Validate the Terraform configuration after building

the local Lambda ZIP and initializing the provider:



&#x20;   terraform -chdir=infra/day35 validate



\## Security Scope



All incident data is synthetic. AI model responses,

approval users, S3 storage, and remediation actions

are simulated. The Terraform configuration represents

an infrastructure blueprint only.



This project demonstrates engineering concepts and

defensive testing, not a deployed security product.

```





