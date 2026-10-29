# AI Security Incident Investigator

A local-first Python security investigation pipeline.

## Features
- Windows and AWS-style event normalization
- Rule-based security detection and severity classification
- Time-window event correlation
- Structured investigation records
- Evidence-based Markdown reports
- Validation and regression testing

## Technology
Python 3.13, JSON, PowerShell, unittest

## Testing
Run:
py -m unittest discover -s . -p "test_*.py" -v

35 automated tests passed in the Day 13 checkpoint.

## Security
Uses synthetic training data only.
No live AWS access or automatic remediation.
Requires human review before remediation.

## Roadmap
- Week 2: Security investigation pipeline
- Week 3+: Automation and AI-assisted investigation
