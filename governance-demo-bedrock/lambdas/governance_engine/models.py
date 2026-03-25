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


@dataclass
class AgentIdentity:
    """Identity record for a governed agent.

    Attributes:
        agent_id: Unique identifier for the agent.
        display_name: Human-readable name for the agent.
        scope_level: Current autonomy level (0–4). Defaults to 1.
        creation_timestamp: ISO 8601 timestamp of agent creation.
        status: Agent status — "active" or "suspended". Defaults to "active".
        environment: Deployment environment — "dev", "staging", or "prod".
    """

    agent_id: str
    display_name: str
    scope_level: int = 1
    creation_timestamp: str = ""
    status: str = "active"
    environment: str = "dev"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "display_name": self.display_name,
            "scope_level": self.scope_level,
            "creation_timestamp": self.creation_timestamp,
            "status": self.status,
            "environment": self.environment,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentIdentity":
        return cls(
            agent_id=data["agent_id"],
            display_name=data["display_name"],
            scope_level=data.get("scope_level", 1),
            creation_timestamp=data.get("creation_timestamp", ""),
            status=data.get("status", "active"),
            environment=data["environment"],
        )


@dataclass
class AgentRegistryEntry:
    """Registry entry describing a governed agent's purpose and permissions.

    Attributes:
        agent_id: Unique identifier for the agent.
        purpose: Description of the agent's purpose.
        owner: Identity of the agent owner.
        data_classes: List of data classes the agent is declared to access.
        tools: List of tools the agent is declared to use.
        approved_scope: Maximum approved scope level for the agent.
        environment: Deployment environment — "dev", "staging", or "prod".
    """

    agent_id: str
    purpose: str
    owner: str
    data_classes: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    approved_scope: int = 1
    environment: str = "dev"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "purpose": self.purpose,
            "owner": self.owner,
            "data_classes": list(self.data_classes),
            "tools": list(self.tools),
            "approved_scope": self.approved_scope,
            "environment": self.environment,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentRegistryEntry":
        return cls(
            agent_id=data["agent_id"],
            purpose=data["purpose"],
            owner=data["owner"],
            data_classes=data.get("data_classes", []),
            tools=data.get("tools", []),
            approved_scope=data.get("approved_scope", 1),
            environment=data["environment"],
        )


@dataclass
class ToolModelRegistryEntry:
    """Registry entry for an approved model, tool connector, or data source.

    Attributes:
        entry_id: Unique identifier for the registry entry.
        category: One of "model", "tool_connector", or "data_source".
        name: Human-readable name of the entry.
        version: Version string of the entry.
        approval_status: Current approval status (e.g., "approved", "pending", "revoked").
        approver: Identity of the approver.
        approval_timestamp: ISO 8601 timestamp of approval.
    """

    entry_id: str
    category: str
    name: str
    version: str
    approval_status: str = ""
    approver: str = ""
    approval_timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entry_id": self.entry_id,
            "category": self.category,
            "name": self.name,
            "version": self.version,
            "approval_status": self.approval_status,
            "approver": self.approver,
            "approval_timestamp": self.approval_timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolModelRegistryEntry":
        return cls(
            entry_id=data["entry_id"],
            category=data["category"],
            name=data["name"],
            version=data["version"],
            approval_status=data.get("approval_status", ""),
            approver=data.get("approver", ""),
            approval_timestamp=data.get("approval_timestamp", ""),
        )


@dataclass
class GovernanceRoleAssignment:
    """Assignment of a governance role to a user for separation of duties.

    Attributes:
        user_id: Identifier of the user.
        role: One of "policy_author", "policy_approver", "operator",
              "auditor", or "agent_owner".
        scope: Scope to which the role assignment applies.
        assigned_by: Identity of the assigner.
        assigned_at: ISO 8601 timestamp of the assignment.
    """

    user_id: str
    role: str
    scope: str
    assigned_by: str
    assigned_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "user_id": self.user_id,
            "role": self.role,
            "scope": self.scope,
            "assigned_by": self.assigned_by,
            "assigned_at": self.assigned_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GovernanceRoleAssignment":
        return cls(
            user_id=data["user_id"],
            role=data["role"],
            scope=data["scope"],
            assigned_by=data["assigned_by"],
            assigned_at=data["assigned_at"],
        )


@dataclass
class EvidenceRecord:
    """Structured evidence record for a governance decision.

    Attributes:
        evidence_id: Unique identifier for the evidence record.
        decision_id: Identifier of the associated governance decision.
        agent_id: Identifier of the agent whose action was evaluated.
        action_requested: Description of the action the agent requested.
        policy_result: Summary of the policy evaluation outcome.
        risk_score: Numeric risk score (0–100) from the risk assessment.
        verdict: Final decision — 'allow', 'deny', or 'escalate'.
        timestamp: ISO 8601 timestamp of the evidence record.
        framework_mapping: List of ISO 42001 control IDs and NIST AI RMF function IDs.
        environment: Deployment environment — "dev", "staging", or "prod".
        previous_hash: SHA-256 hash of the preceding evidence record for hash chain.
        record_hash: SHA-256 hash of this evidence record.
        retention_class: Retention class — "standard" or "extended".
    """

    evidence_id: str
    decision_id: str
    agent_id: str
    action_requested: str
    policy_result: str
    risk_score: float
    verdict: str
    timestamp: str
    framework_mapping: List[str] = field(default_factory=list)
    environment: str = ""
    previous_hash: str = ""
    record_hash: str = ""
    retention_class: str = "standard"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "decision_id": self.decision_id,
            "agent_id": self.agent_id,
            "action_requested": self.action_requested,
            "policy_result": self.policy_result,
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "timestamp": self.timestamp,
            "framework_mapping": list(self.framework_mapping),
            "environment": self.environment,
            "previous_hash": self.previous_hash,
            "record_hash": self.record_hash,
            "retention_class": self.retention_class,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceRecord":
        return cls(
            evidence_id=data["evidence_id"],
            decision_id=data["decision_id"],
            agent_id=data["agent_id"],
            action_requested=data["action_requested"],
            policy_result=data["policy_result"],
            risk_score=data["risk_score"],
            verdict=data["verdict"],
            timestamp=data["timestamp"],
            framework_mapping=data.get("framework_mapping", []),
            environment=data.get("environment", ""),
            previous_hash=data.get("previous_hash", ""),
            record_hash=data.get("record_hash", ""),
            retention_class=data.get("retention_class", "standard"),
        )


@dataclass
class ControlTrace:
    """Trace linking a framework control to an evidence record and decision.

    Attributes:
        control_id: Identifier of the framework control (e.g., ISO 42001 or NIST AI RMF).
        implementation_component: Name of the component implementing the control.
        evidence_record_id: Identifier of the associated evidence record.
        decision_id: Identifier of the associated governance decision.
        timestamp: ISO 8601 timestamp of the trace.
    """

    control_id: str
    implementation_component: str
    evidence_record_id: str
    decision_id: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "implementation_component": self.implementation_component,
            "evidence_record_id": self.evidence_record_id,
            "decision_id": self.decision_id,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ControlTrace":
        return cls(
            control_id=data["control_id"],
            implementation_component=data["implementation_component"],
            evidence_record_id=data["evidence_record_id"],
            decision_id=data["decision_id"],
            timestamp=data["timestamp"],
        )


@dataclass
class PolicyVersion:
    """Version metadata for a policy definition in the lifecycle.

    Attributes:
        policy_id: Identifier of the policy.
        version: Monotonically increasing version number.
        author: Identity of the policy author.
        approval_status: Current approval status (e.g., "pending", "approved").
        approver: Identity of the approver (empty if not yet approved).
        timestamp: ISO 8601 timestamp of the version creation.
        s3_key: S3 key where this policy version is stored.
    """

    policy_id: str
    version: int
    author: str
    approval_status: str
    approver: str
    timestamp: str
    s3_key: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "author": self.author,
            "approval_status": self.approval_status,
            "approver": self.approver,
            "timestamp": self.timestamp,
            "s3_key": self.s3_key,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PolicyVersion":
        return cls(
            policy_id=data["policy_id"],
            version=data["version"],
            author=data["author"],
            approval_status=data["approval_status"],
            approver=data["approver"],
            timestamp=data["timestamp"],
            s3_key=data["s3_key"],
        )


@dataclass
class ThreatPattern:
    """Pattern definition for input validation heuristics (threat detection).

    Attributes:
        pattern_id: Unique identifier for the threat pattern.
        category: Pattern category — "known_bad" or "suspicious".
        pattern: The pattern string to match against input.
        description: Human-readable description of the threat pattern.
        risk_weight: Numeric weight applied to risk score on match.
        updated_at: ISO 8601 timestamp of the last update.
    """

    pattern_id: str
    category: str
    pattern: str
    description: str
    risk_weight: int
    updated_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pattern_id": self.pattern_id,
            "category": self.category,
            "pattern": self.pattern,
            "description": self.description,
            "risk_weight": self.risk_weight,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatPattern":
        return cls(
            pattern_id=data["pattern_id"],
            category=data["category"],
            pattern=data["pattern"],
            description=data["description"],
            risk_weight=data["risk_weight"],
            updated_at=data["updated_at"],
        )


@dataclass
class ValidationResult:
    """Result of a validation suite test execution.

    Attributes:
        test_name: Name of the validation test.
        passed: Whether the test passed.
        evidence_record_ids: List of evidence record IDs generated during the test.
        control_trace_ids: List of control trace IDs generated during the test.
        timestamp: ISO 8601 timestamp of the test execution.
        details: Human-readable details or error message from the test.
    """

    test_name: str
    passed: bool
    evidence_record_ids: List[str] = field(default_factory=list)
    control_trace_ids: List[str] = field(default_factory=list)
    timestamp: str = ""
    details: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "test_name": self.test_name,
            "passed": self.passed,
            "evidence_record_ids": list(self.evidence_record_ids),
            "control_trace_ids": list(self.control_trace_ids),
            "timestamp": self.timestamp,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ValidationResult":
        return cls(
            test_name=data["test_name"],
            passed=data["passed"],
            evidence_record_ids=data.get("evidence_record_ids", []),
            control_trace_ids=data.get("control_trace_ids", []),
            timestamp=data.get("timestamp", ""),
            details=data.get("details", ""),
        )


@dataclass
class PendingApproval:
    """A pending human-in-the-loop approval record for an escalated governance decision.

    Attributes:
        approval_id: Unique identifier for the approval request.
        decision_id: Identifier of the governance decision that triggered escalation.
        agent_id: Identifier of the agent whose action requires approval.
        action_requested: Description of the action requiring approval.
        risk_score: Numeric risk score (0–100) from the risk assessment.
        escalation_reason: Human-readable reason for escalation.
        status: Approval status — "pending", "approved", "denied", or "timeout".
        approver_id: Identifier of the approver (empty if not yet resolved).
        approval_conditions: Conditions attached to the approval (empty if none).
        denial_reason: Reason for denial (empty if not denied).
        created_at: ISO 8601 timestamp of creation.
        resolved_at: ISO 8601 timestamp of resolution (empty if not yet resolved).
        timeout_seconds: Seconds before the approval times out. Defaults to 3600.
    """

    approval_id: str
    decision_id: str
    agent_id: str
    action_requested: str
    risk_score: float
    escalation_reason: str
    status: str = "pending"
    approver_id: Optional[str] = ""
    approval_conditions: Optional[str] = ""
    denial_reason: Optional[str] = ""
    created_at: str = ""
    resolved_at: Optional[str] = ""
    timeout_seconds: int = 3600

    def to_dict(self) -> Dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "decision_id": self.decision_id,
            "agent_id": self.agent_id,
            "action_requested": self.action_requested,
            "risk_score": self.risk_score,
            "escalation_reason": self.escalation_reason,
            "status": self.status,
            "approver_id": self.approver_id,
            "approval_conditions": self.approval_conditions,
            "denial_reason": self.denial_reason,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
            "timeout_seconds": self.timeout_seconds,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PendingApproval":
        return cls(
            approval_id=data["approval_id"],
            decision_id=data["decision_id"],
            agent_id=data["agent_id"],
            action_requested=data["action_requested"],
            risk_score=data["risk_score"],
            escalation_reason=data["escalation_reason"],
            status=data.get("status", "pending"),
            approver_id=data.get("approver_id", ""),
            approval_conditions=data.get("approval_conditions", ""),
            denial_reason=data.get("denial_reason", ""),
            created_at=data.get("created_at", ""),
            resolved_at=data.get("resolved_at", ""),
            timeout_seconds=data.get("timeout_seconds", 3600),
        )


@dataclass
class ChangeRecord:
    """Record of a scope or policy change for audit and compliance logging.

    Attributes:
        record_id: Unique identifier for the change record.
        change_type: Type of change — "scope_change" or "policy_change".
        agent_id: Identifier of the agent affected (empty if not applicable).
        policy_id: Identifier of the policy affected (empty if not applicable).
        previous_value: Previous value before the change.
        new_value: New value after the change.
        requester_id: Identifier of the person who requested the change.
        authorization_method: Method used to authorize the change.
        timestamp: ISO 8601 timestamp of the change.
        retention_days: Number of days to retain the record. Defaults to 2555 (7 years).
    """

    record_id: str
    change_type: str
    agent_id: Optional[str] = ""
    policy_id: Optional[str] = ""
    previous_value: str = ""
    new_value: str = ""
    requester_id: str = ""
    authorization_method: str = ""
    timestamp: str = ""
    retention_days: int = 2555

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "change_type": self.change_type,
            "agent_id": self.agent_id,
            "policy_id": self.policy_id,
            "previous_value": self.previous_value,
            "new_value": self.new_value,
            "requester_id": self.requester_id,
            "authorization_method": self.authorization_method,
            "timestamp": self.timestamp,
            "retention_days": self.retention_days,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ChangeRecord":
        return cls(
            record_id=data["record_id"],
            change_type=data["change_type"],
            agent_id=data.get("agent_id", ""),
            policy_id=data.get("policy_id", ""),
            previous_value=data.get("previous_value", ""),
            new_value=data.get("new_value", ""),
            requester_id=data.get("requester_id", ""),
            authorization_method=data.get("authorization_method", ""),
            timestamp=data.get("timestamp", ""),
            retention_days=data.get("retention_days", 2555),
        )


@dataclass
class DecisionHistoryEntry:
    """Indexed entry for queryable governance decision history.

    Attributes:
        agent_id: Identifier of the agent whose action was evaluated.
        timestamp: ISO 8601 timestamp of the decision.
        decision_id: Unique identifier of the governance decision.
        action_requested: Description of the action the agent requested.
        verdict: Final decision — "allow", "deny", or "escalate".
        risk_score: Numeric risk score (0–100) from the risk assessment.
        control_ids: List of framework control IDs associated with the decision.
        policy_id: Identifier of the matched policy.
        environment: Deployment environment — "dev", "staging", or "prod".
    """

    agent_id: str
    timestamp: str
    decision_id: str
    action_requested: str
    verdict: str
    risk_score: float
    control_ids: List[str] = field(default_factory=list)
    policy_id: str = ""
    environment: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "decision_id": self.decision_id,
            "action_requested": self.action_requested,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "control_ids": list(self.control_ids),
            "policy_id": self.policy_id,
            "environment": self.environment,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DecisionHistoryEntry":
        return cls(
            agent_id=data["agent_id"],
            timestamp=data["timestamp"],
            decision_id=data["decision_id"],
            action_requested=data["action_requested"],
            verdict=data["verdict"],
            risk_score=data["risk_score"],
            control_ids=data.get("control_ids", []),
            policy_id=data.get("policy_id", ""),
            environment=data.get("environment", ""),
        )


@dataclass
class ComplianceMappingEntry:
    """Entry mapping a framework control to an implementation component for compliance reporting.

    Attributes:
        control_id: Identifier of the framework control (e.g., "A.2" for ISO 42001).
        control_name: Human-readable name of the control.
        framework: Framework identifier — "iso_42001" or "nist_ai_rmf".
        function_name: NIST AI RMF function name (empty if not applicable).
        category: NIST AI RMF category (empty if not applicable).
        subcategory: NIST AI RMF subcategory (empty if not applicable).
        implementation_component: Name of the component implementing the control.
        evidence_generated: Description of evidence generated for the control.
        compliance_status: Current compliance status — "implemented", "partial", or "planned".
    """

    control_id: str
    control_name: str
    framework: str
    function_name: Optional[str] = ""
    category: Optional[str] = ""
    subcategory: Optional[str] = ""
    implementation_component: str = ""
    evidence_generated: str = ""
    compliance_status: str = "planned"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "control_id": self.control_id,
            "control_name": self.control_name,
            "framework": self.framework,
            "function_name": self.function_name,
            "category": self.category,
            "subcategory": self.subcategory,
            "implementation_component": self.implementation_component,
            "evidence_generated": self.evidence_generated,
            "compliance_status": self.compliance_status,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComplianceMappingEntry":
        return cls(
            control_id=data["control_id"],
            control_name=data["control_name"],
            framework=data["framework"],
            function_name=data.get("function_name", ""),
            category=data.get("category", ""),
            subcategory=data.get("subcategory", ""),
            implementation_component=data.get("implementation_component", ""),
            evidence_generated=data.get("evidence_generated", ""),
            compliance_status=data.get("compliance_status", "planned"),
        )
