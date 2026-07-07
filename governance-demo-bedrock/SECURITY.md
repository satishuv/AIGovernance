# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: satishuv@amazon.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive an acknowledgment within 48 hours and a detailed response within 7 days.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| main    | Yes                |
| < main  | No                 |

## Security Measures

This project implements defense-in-depth security:

- **Preventive**: OPA policy engine, input sanitization, Bedrock Guardrails, scope enforcement, per-tool authorization
- **Detective**: Runtime drift detection, continuous monitoring, anomaly detection, CloudWatch metrics
- **Proactive**: Policy contradiction detection, dead rule identification, coverage gap analysis

## Known Limitations

- The demo deployment uses `RemovalPolicy.DESTROY` for ease of cleanup. Production deployments should use `RemovalPolicy.RETAIN`.
- Object Lock retention in demo mode is set to 365 days. Production should use 2555 days (7 years).
- The `cloudwatch:PutMetricData` permission uses `Resource: "*"` because AWS does not support resource-level permissions for this action.
