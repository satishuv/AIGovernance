"""Quick validation that all models import and round-trip correctly."""
import sys
sys.path.insert(0, ".")
from lambdas.governance_engine.models import (
    PolicyDefinition, PolicyEvaluationResult, RiskAssessment,
    GovernanceDecision, LatencyMetric
)

pd = PolicyDefinition(
    policy_id="pol-001", version=1, name="test", description="desc",
    priority=10, conditions={"scope_level": 2, "action_group": "read"},
    outcome="allow", owner="admin", approval_status="approved",
    created_at="2024-01-01T00:00:00Z", updated_at="2024-01-01T00:00:00Z"
)
assert PolicyDefinition.from_dict(pd.to_dict()) == pd

per = PolicyEvaluationResult(
    policy_id="pol-001", outcome="allow",
    matching_conditions={"scope_level": 2}, evaluation_timestamp="2024-01-01T00:00:00Z"
)
assert PolicyEvaluationResult.from_dict(per.to_dict()) == per

ra = RiskAssessment(
    risk_score=45, risk_category="data_access",
    factors_applied={"scope_weight": 0.3}, escalation_flagged=False,
    assessment_timestamp="2024-01-01T00:00:00Z"
)
assert RiskAssessment.from_dict(ra.to_dict()) == ra

gd = GovernanceDecision(
    decision_id="dec-001", agent_id="agent-1", action_requested="read_data",
    policy_result={"policy_id": "pol-001", "outcome": "allow"},
    risk_score=45, verdict="allow", explanation="Low risk action allowed",
    framework_mapping=["ISO42001-A.2.1", "GOVERN-1.1"],
    timestamp="2024-01-01T00:00:00Z",
    latency_breakdown={"policy_evaluation": 10.5, "risk_scoring": 5.2}
)
assert GovernanceDecision.from_dict(gd.to_dict()) == gd

lm = LatencyMetric(
    decision_id="dec-001", total_elapsed_ms=150.3,
    component_latencies={"policy_evaluation": 10.5, "risk_scoring": 5.2},
    budget_exceeded=False, timestamp="2024-01-01T00:00:00Z"
)
assert LatencyMetric.from_dict(lm.to_dict()) == lm

print("All 5 models: import OK, round-trip serialization OK")
