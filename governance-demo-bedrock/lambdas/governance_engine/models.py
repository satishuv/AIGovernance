"""Core data models for the Governance Engine.

Defines dataclasses for policy definitions, evaluation results, risk assessments,
governance decisions, and latency metrics. Each model supports JSON round-trip
serialization via to_dict() and from_dict() class methods.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PolicyConditions:
    """Conditions under which a policy applies to an action request."""

    scope_level: Optional[int] = None
    action_group: Optional[str] = None
    target_resource: Optional[str] = None
    time_of_day: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        if self.scope_level is not None:
            result["scope_level"] = self.scope_level
        if self.action_group is not None:
            result["action_group"] = self.action_group
        if self.target_resource is not None:
            result["target_resource"] = self.target_resource
        if self.time_of_day is not None:
            result["time_of_day"] = dict(self.time_of_day)
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyConditions":
        return cls(
            scope_level=data.get("scope_level"),
            action_group=data.get("action_group"),
            target_resource=data.get("target_resource"),
            time_of_day=data.get("time_of_day"),
        )


@dataclass
class PolicyDefinition:
    """A policy-as-code definition for governance evaluation.

    Attributes:
        policy_id: Unique identifier for the policy.
        version: Monotonically increasing version number.
        name: Human-readable policy name.
        description: Detailed description of the policy.
        priority: Lower numeric value = higher priority for conflict resolution.
        conditions: PolicyConditions or dict specifying when this policy applies.
        outcome: One of 'allow', 'deny', or 'escalate'.
        owner: Identity of the policy owner.
        approval_status: Current approval status (e.g., 'approved', 'pending').
        created_at: ISO 8601 timestamp of creation.
        updated_at: ISO 8601 timestamp of last update.
    """

    policy_id: str
    version: int
    name: str
    description: str
    priority: int
    conditions: Any  # PolicyConditions or dict
    outcome: str
    owner: str
    approval_status: str
    created_at: str
    updated_at: str

    def to_dict(self) -> Dict[str, Any]:
        conditions_dict = (
            self.conditions.to_dict()
            if isinstance(self.conditions, PolicyConditions)
            else dict(self.conditions) if self.conditions else {}
        )
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "name": self.name,
            "description": self.description,
            "priority": self.priority,
            "conditions": conditions_dict,
            "outcome": self.outcome,
            "owner": self.owner,
            "approval_status": self.approval_status,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyDefinition":
        raw_conditions = data.get("conditions", {})
        if isinstance(raw_conditions, PolicyConditions):
            conditions = raw_conditions
        else:
            conditions = PolicyConditions.from_dict(raw_conditions)
        return cls(
            policy_id=data["policy_id"],
            version=data["version"],
            name=data["name"],
            description=data["description"],
            priority=data["priority"],
            conditions=conditions,
            outcome=data["outcome"],
            owner=data["owner"],
            approval_status=data["approval_status"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )


@dataclass
class PolicyEvaluationResult:
    """Result of evaluating an action request against a policy.

    Attributes:
        policy_id: Identifier of the matched policy.
        outcome: Evaluation outcome — 'allow', 'deny', or 'escalate'.
        matching_conditions: Dict of conditions that matched the request.
        evaluation_timestamp: ISO 8601 timestamp of the evaluation.
    """

    policy_id: str
    outcome: str
    matching_conditions: Dict[str, Any] = field(default_factory=dict)
    evaluation_timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "outcome": self.outcome,
            "matching_conditions": dict(self.matching_conditions),
            "evaluation_timestamp": self.evaluation_timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyEvaluationResult":
        return cls(
            policy_id=data["policy_id"],
            outcome=data["outcome"],
            matching_conditions=data.get("matching_conditions", {}),
            evaluation_timestamp=data.get("evaluation_timestamp", ""),
        )


@dataclass
class RiskAssessment:
    """Risk assessment result for an agent action.

    Attributes:
        risk_score: Numeric score between 0 and 100.
        risk_category: One of 'data_access', 'data_modification', 'deployment',
                       'configuration_change', or 'emergency_action'.
        factors_applied: Dict of risk factor names to their applied weights.
        escalation_flagged: True if risk_score >= escalation threshold.
        assessment_timestamp: ISO 8601 timestamp of the assessment.
    """

    risk_score: float
    risk_category: str
    factors_applied: Dict[str, Any] = field(default_factory=dict)
    escalation_flagged: bool = False
    assessment_timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_category": self.risk_category,
            "factors_applied": dict(self.factors_applied),
            "escalation_flagged": self.escalation_flagged,
            "assessment_timestamp": self.assessment_timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RiskAssessment":
        return cls(
            risk_score=data["risk_score"],
            risk_category=data["risk_category"],
            factors_applied=data.get("factors_applied", {}),
            escalation_flagged=data.get("escalation_flagged", False),
            assessment_timestamp=data.get("assessment_timestamp", ""),
        )


@dataclass
class GovernanceDecision:
    """Final governance decision combining policy evaluation and risk scoring.

    Attributes:
        decision_id: Unique identifier (UUID) for this decision.
        agent_id: Identifier of the agent whose action was evaluated.
        action_requested: Description of the action the agent requested.
        policy_result: Dict summary of the policy evaluation outcome.
        risk_score: Numeric risk score (0–100) from the risk assessment.
        verdict: Final decision — 'allow', 'deny', or 'escalate'.
        explanation: Human-readable explanation of the decision rationale.
        framework_mapping: List of ISO 42001 control IDs and NIST AI RMF function IDs.
        timestamp: ISO 8601 timestamp of the decision.
        latency_breakdown: Dict of component names to elapsed milliseconds.
    """

    decision_id: str
    agent_id: str
    action_requested: str
    policy_result: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    verdict: str = "deny"
    explanation: str = ""
    framework_mapping: List[str] = field(default_factory=list)
    timestamp: str = ""
    latency_breakdown: Dict[str, float] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "agent_id": self.agent_id,
            "action_requested": self.action_requested,
            "policy_result": dict(self.policy_result),
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "explanation": self.explanation,
            "framework_mapping": list(self.framework_mapping),
            "timestamp": self.timestamp,
            "latency_breakdown": dict(self.latency_breakdown),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GovernanceDecision":
        return cls(
            decision_id=data["decision_id"],
            agent_id=data["agent_id"],
            action_requested=data["action_requested"],
            policy_result=data.get("policy_result", {}),
            risk_score=data.get("risk_score", 0.0),
            verdict=data.get("verdict", "deny"),
            explanation=data.get("explanation", ""),
            framework_mapping=data.get("framework_mapping", []),
            timestamp=data.get("timestamp", ""),
            latency_breakdown=data.get("latency_breakdown", {}),
        )


@dataclass
class LatencyMetric:
    """Latency tracking for a governance decision pipeline execution.

    Attributes:
        decision_id: Identifier of the associated governance decision.
        total_elapsed_ms: Total elapsed time in milliseconds.
        component_latencies: Dict of component names to elapsed milliseconds.
        budget_exceeded: True if total_elapsed_ms exceeds the 200ms budget.
        timestamp: ISO 8601 timestamp of the metric recording.
    """

    decision_id: str
    total_elapsed_ms: float
    component_latencies: Dict[str, float] = field(default_factory=dict)
    budget_exceeded: bool = False
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "total_elapsed_ms": self.total_elapsed_ms,
            "component_latencies": dict(self.component_latencies),
            "budget_exceeded": self.budget_exceeded,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LatencyMetric":
        return cls(
            decision_id=data["decision_id"],
            total_elapsed_ms=data["total_elapsed_ms"],
            component_latencies=data.get("component_latencies", {}),
            budget_exceeded=data.get("budget_exceeded", False),
            timestamp=data.get("timestamp", ""),
        )
