"""Verify all 7 Phase 3 modules import correctly and have required methods."""
import sys
sys.path.insert(0, "lambdas")

from governance_engine.measure_manage import MeasureManageEngine
from governance_engine.cloudwatch_metrics import CloudWatchMetricsPublisher
from governance_engine.extended_validation import ExtendedValidationSuite
from governance_engine.privilege_escalation import PrivilegeEscalationDetector
from governance_engine.exfiltration_detector import ExfiltrationDetector
from governance_engine.graduated_scope_reduction import GraduatedScopeReduction
from governance_engine.multi_agent import MultiAgentManager

print("All 7 modules imported successfully")

checks = [
    ("57.1 MeasureManageEngine", MeasureManageEngine(), [
        "compute_aggregate_metrics", "generate_measure_report",
        "generate_manage_report", "check_thresholds", "export_reports"]),
    ("58.1 CloudWatchMetricsPublisher", CloudWatchMetricsPublisher(), [
        "publish_decision_metric", "publish_latency_metric",
        "publish_risk_score_metric", "publish_kill_switch_metric",
        "publish_evidence_failure_metric"]),
    ("60.1 ExtendedValidationSuite", ExtendedValidationSuite(), [
        "test_control_mapping_completeness", "test_evidence_hash_chain_integrity",
        "test_approval_workflow_correctness", "test_measure_manage_report_generation",
        "verify_control_trace_references", "generate_compliance_report", "detect_gaps"]),
    ("62.1 PrivilegeEscalationDetector", PrivilegeEscalationDetector(), [
        "is_self_modification", "is_policy_modification", "deny_and_log",
        "track_denial_pattern", "auto_reduce_scope"]),
    ("63.1 ExfiltrationDetector", ExfiltrationDetector(), [
        "evaluate_output", "check_output_size", "detect_encoded_blocks",
        "check_external_endpoints", "block_and_log", "load_allowlist"]),
    ("65.1 GraduatedScopeReduction", GraduatedScopeReduction(), [
        "compute_rolling_avg_risk", "check_sustained_threshold",
        "check_cooldown", "execute_reduction", "get_reduction_mode"]),
    ("67.1 MultiAgentManager", MultiAgentManager(), [
        "get_agent_config", "get_agent_policy_bindings",
        "enforce_cross_agent_rules", "get_evidence_partition",
        "generate_aggregate_report"]),
]

for label, obj, methods in checks:
    for m in methods:
        assert hasattr(obj, m), f"{label}: missing {m}"
    print(f"{label}: all {len(methods)} methods present")

print("\nALL VERIFICATIONS PASSED")
