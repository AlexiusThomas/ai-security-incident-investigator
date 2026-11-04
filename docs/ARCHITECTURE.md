

\# AI Security Incident Investigator — Architecture



\## Project Overview



A Python-based AI security automation prototype that

investigates synthetic AWS-style security events.



The project is designed for local execution and does

not require AWS credentials or cloud deployment.



\## Architecture



```mermaid

flowchart TD

&#x20;   A\[Synthetic CloudTrail Events] --> B\[Input Security Gate]

&#x20;   B --> C\[Detection and Correlation]

&#x20;   C --> D\[Investigation Agent]

&#x20;   D --> E\[Local Evidence Store]

&#x20;   E --> F\[Simulated Bedrock AI Summary]

&#x20;   F --> G\[AI Guardrails and Evaluation]

&#x20;   G --> H\[Simulated Human Approval]



&#x20;   H -->|Pending| I\[No Action]

&#x20;   H -->|Denied| J\[Action Blocked]

&#x20;   H -->|Approved| K\[Local Remediation Simulator]



&#x20;   K --> L\[Simulation Receipt]

&#x20;   D --> M\[Reliability Monitor]

&#x20;   M --> N\[JSONL Logs and Alerts]

```



\## Component Map



| Component | Implementation |

|---|---|

| Threat detection | `detection\_engine.py` |

| CloudTrail parsing | `cloudtrail\_ingest.py` |

| Event correlation | `login\_sequence\_detector.py` |

| Findings | `day24\_findings.py` |

| Evidence integrity | `evidence\_store.py` |

| Simulated Bedrock | `bedrock\_local.py` |

| AI output safeguards | `ai\_guardrails.py` |

| Security agent | `local\_security\_agent.py` |

| Agent evaluation | `agent\_evaluator.py` |

| Approval workflow | `approval\_workflow.py` |

| Remediation simulation | `remediation\_simulator.py` |

| Reliability monitoring | `reliability\_monitor.py` |

| Integrated workflow | `capstone\_integration.py` |

| Adversarial input gate | `adversarial\_gate.py` |

| Final acceptance test | `capstone\_final.py` |

| Terraform blueprint | `infra/day35/main.tf` |



\## Security Controls



1\. Validate synthetic event fields before processing.

2\. Strip unsupported metadata from incoming events.

3\. Detect suspicious login sequences.

4\. Verify stored evidence with SHA-256 checksums.

5\. Ground AI summaries in verified evidence.

6\. Reject untrusted AI output.

7\. Evaluate investigation results before proceeding.

8\. Require a simulated approval decision.

9\. Enforce a local action allowlist and role separation.

10\. Never execute real AWS remediation.

11\. Retry only selected transient errors.

12\. Record investigation and reliability results.



\## Execution Environment



\- Windows PowerShell

\- Python 3.13

\- Python unittest

\- Local filesystem for evidence

\- Simulated AWS EventBridge and Lambda events

\- Simulated Bedrock responses

\- Terraform configuration validated locally

\- GitHub Actions for CI and security checks



\## Important Limitations



This project is a portfolio and training prototype.



\- It does not connect to production AWS resources.

\- It does not invoke a real Bedrock foundation model.

\- Its S3 evidence store is a local filesystem simulation.

\- Its approval identities are simulated, not authenticated.

\- Local hash-linked audit records are not tamper-proof

&#x20; against an attacker with full write access.

\- The Terraform blueprint has not been deployed.

\- It is not a production-ready incident response system.



\## Future Production Requirements



An authorized production implementation would need

federated identity, protected audit storage, formal

change approval, observability, secrets management,

network restrictions, stronger IAM policies, verified

data provenance, deployment tests, and threat modeling.



All cloud deployment and remediation work would

require separate authorization.

```



