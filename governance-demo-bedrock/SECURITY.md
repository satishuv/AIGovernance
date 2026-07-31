# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, use the GitHub private security advisory feature for this repository (Security > Advisories > New draft security advisory).

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

## IAM Permissions: Broad Access Exceptions

All IAM policies in this project follow least-privilege. The following exceptions use `Resource: "*"` with documented justification:

| Permission | Resource | Justification | Mitigation |
|-----------|----------|---------------|------------|
| `cloudwatch:PutMetricData` | `*` | AWS does not support resource-level permissions for this action ([docs](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudwatch.html)) | Restricted via IAM condition `cloudwatch:namespace = "AGCP/Governance"` |
| `bedrock:InvokeAgent` | `*` | Agent ARNs are dynamically generated and not known at deploy time; cross-account model invocation requires wildcard | Restricted to Scope Enforcer Lambda only (not granted to other Lambdas) |
| `logs:CreateLogGroup` (Scope 4 boundary) | `arn:aws:logs:*:*:log-group:/governance-demo-bedrock/*` | Scoped to governance log groups only, not all logs | ARN pattern restricts to `/governance-demo-bedrock/` prefix |

All other IAM permissions use specific resource ARNs (table ARNs, bucket ARNs, function ARNs, topic ARNs).

## Demo vs Production Differences

| Setting | Demo | Production | How to Switch |
|---------|------|-----------|---------------|
| Object Lock retention | 365 days | 2555 days (7 years) | `-c environment=production` |
| RemovalPolicy | DESTROY | RETAIN | Change in config |
| CloudTrail | Skippable | Always enabled | Remove `-c skip_cloudtrail=true` |
| Guardrail version | DRAFT | Numbered version | Update `BEDROCK_GUARDRAIL_VERSION` |

## Known Limitations

- The demo deployment uses `RemovalPolicy.DESTROY` for ease of cleanup. Production deployments should use `RemovalPolicy.RETAIN`.
- Object Lock retention is configurable: 365 days (demo) or 2555 days (production) via CDK context.
- Bedrock Guardrail ID is hardcoded to demo account. Production requires its own guardrail.
