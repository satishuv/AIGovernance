#!/usr/bin/env python3
"""Quick check that Phase 3 CDK resources are present."""
import sys, os
sys.path.insert(0, ".")
os.environ.setdefault("CDK_DEFAULT_ACCOUNT", "123456789012")
os.environ.setdefault("CDK_DEFAULT_REGION", "us-east-1")

from aws_cdk import App
from governance_bedrock_stack import GovernanceBedrockStack

app = App(context={"skip_cloudtrail": True})
stack = GovernanceBedrockStack(app, "TestStack")

checks = [
    "denial_pattern_table",
    "exfiltration_allowlist_table",
    "scope_reduction_history_table",
    "multi_agent_config_table",
    "metrics_threshold_table",
    "policy_eval_latency_alarm",
    "evidence_write_failure_alarm",
    "kill_switch_activation_alarm",
    "monthly_report_rule",
]
for attr in checks:
    assert hasattr(stack, attr), f"Missing {attr}"

print("PASS: Phase 3 CDK stack synthesizes with all resources")
