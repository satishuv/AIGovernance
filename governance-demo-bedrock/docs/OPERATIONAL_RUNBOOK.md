# Operational Runbook

Response procedures for each CloudWatch alarm the framework deploys (SAS review
P3 #12). Alarms are defined in `governance_constructs/monitoring.py`; all publish
to the operator SNS topic. For each: what it means, who responds, first steps,
and the blast radius of inaction.

## AGCP-KillSwitchActivationAlarm

- **Fires when:** the kill switch is activated (metric `KillSwitchActivationCount`).
- **Severity:** highest. Every agent action is now denied org-wide.
- **Meaning:** either an operator activated it intentionally (incident response)
  or automated denial-pattern escalation tripped it.
- **Respond:** on-call operator (governance owner).
- **First steps:**
  1. Confirm whether activation was intentional (check CloudTrail for the
     `SetKillSwitch` / DynamoDB write on `__kill_switch__`, and the operator SNS
     message).
  2. If an attack: keep it active, investigate the triggering agent via the
     signed decision traces (`GET /decisions/{id}/trace`).
  3. If accidental / resolved: deactivate via the kill-switch API
     (`POST /kill-switch/deactivate`, IAM-authorized).
  4. Validate recovery: `python test_datasets/run_demo_validation.py` (expect 21/21).
- **Blast radius of inaction:** all governed agents remain blocked. This is
  fail-safe (nothing bad executes) but halts legitimate work, so resolve fast.

## AGCP-EvidenceWriteFailureAlarm

- **Fires when:** evidence writes to S3 fail (metric `EvidenceWriteFailureCount`).
- **Severity:** high. Decisions still execute correctly (evidence is audit, not
  authorization, it never blocks the verdict), but the tamper-evident audit
  trail is developing gaps.
- **Respond:** governance owner + whoever owns the evidence/compliance function.
- **First steps:**
  1. Check the immutable evidence bucket: exists, not full, Object Lock intact,
     IAM `s3:PutObject` still granted to the engine role.
  2. Check for S3 throttling / 5xx in the Lambda logs (`evidence_pipeline_write_failed`).
  3. Confirm KMS signing key is enabled (a disabled key degrades to unsigned,
     logged as `record_signing_failed`, not a hard write failure).
  4. Backfill: decisions are also in DynamoDB decision history; reconcile against
     S3 to identify missing evidence for the affected window.
- **Blast radius of inaction:** compliance/audit gap. For a governance product
  whose value is provable evidence, sustained failure undermines the core claim,
  treat as compliance-impacting even though runtime governance keeps working.

## AGCP-PolicyEvalLatencyAlarm

- **Fires when:** policy evaluation latency exceeds threshold (metric `PolicyEvalLatency`).
- **Severity:** medium. Governance still correct, but slow.
- **Respond:** engineering on-call.
- **First steps:**
  1. Check whether the OPA policy cache is cold (first request per warm
     container pays ~0.5s S3 load; see runtime-flow.md). Sustained high latency
     across warm invocations is the real signal.
  2. Check S3 policy-bucket latency / throttling and DynamoDB read throttling
     (`ProvisionedThroughputExceededException`).
  3. If load-driven, consider Step Functions mode (parallel path) or provisioned
     concurrency. Note: cold start is ~90ms and is NOT the usual cause (measured);
     the evidence write and policy load dominate.
- **Blast radius of inaction:** degraded latency for governed calls; at extreme
  values, Step Functions/Lambda timeouts which fail closed (deny), so it
  degrades safely but harms availability of legitimate actions.

## Dashboard metrics (no alarm, watch during incidents)

`DecisionCount` (allow/deny/escalate split), `RiskScore` distribution,
`SecurityBlock` by category, `AgentHealthScore`, `PipelineLatency`. Use these to
scope an incident: a spike in `SecurityBlock` or `deny` `DecisionCount` for one
agent points at the agent to investigate via its decision traces.

## General incident flow

1. Alarm → operator SNS.
2. Scope with the dashboard (which agent, which category).
3. Pull the signed decision trace(s) for the affected decisions,
   `GET /decisions/{id}/trace` (verify signature) or
   `scripts/decision_trace_report.py <decision_id>`.
4. Contain: kill switch (all agents) or graduated scope reduction (one agent).
5. Recover and validate with the 21-scenario demo run.
