"""Delegated authority control plane.

Agent asks to perform an action -> governance evaluates the exact action ->
deny, allow, or require human approval -> a short-lived, narrowly scoped,
signed Delegated Authority Grant ("hall pass") -> exchanged for a
target-specific credential -> execute -> consume/revoke -> signed evidence.

Humans do not approve every low-risk action. Humans approve the BOUNDARIES
(agent registry, operation catalog, spend policy, policy bundle). Every
request is evaluated against those boundaries; authority is issued only
inside them. Leaving the boundary means denial or human escalation,
whichever model, cloud or API executes the action.

Planes:
  agent plane     request_authority, mint_after_approval, execute
  approval plane  human approvers, through ApprovalWorkflow and the approval API
  admin plane     admin_set_scope, revoke_grant, activate_kill_switch (humans)

All dependencies are injected, so the same code runs in Lambda against real
DynamoDB/KMS/S3/STS and offline against moto for the customer demo.
"""

import fnmatch
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Callable, Dict, List, Optional, Tuple

from agent_role_boundaries import evaluate_role_boundary
from authority_identity import ADMIN_ROLES, REVOKER_ROLES, AuthenticatedCaller, check_admin
from budget_governance import NOT_APPLICABLE, STEP_UP, SpendPolicy, evaluate_budget
from budget_governance import DENY as BUDGET_DENY
from credential_broker import BrokerRefusal
from decision_engine import DecisionEngine
from models import PolicyEvaluationResult, RiskAssessment
from operation_registry import validate_against_schema
from request_canonicalization import (
    CanonicalizationError,
    canonical_json,
    canonicalize_action_request,
    compute_action_request_digest,
    compute_policy_version_hash,
    sha256_hex,
    to_json_safe,
)
from tool_execution_auth import ToolExecutionAuthManager

logger = logging.getLogger(__name__)

DATA_CLASS_ORDER = ("Public", "Internal", "Protected-A", "Protected-B", "Protected-C")
REQUIRED_REQUEST_FIELDS = ("agent_id", "session_id", "provider", "operation_id",
                           "target_resource", "environment", "tool_parameters")
AUTHORITY_FIELDS = frozenset({
    "new_scope", "approved_scope", "scope_level", "current_scope", "new_permissions",
    "permissions", "new_role", "role", "new_policy", "human_authorized", "approved",
    "approval_status", "approver_id", "grant", "grant_id", "signature",
})

RISK_BASE = {"read": 8, "oversight": 8, "write": 20, "financial": 15, "identity_admin": 45,
             "authority_change": 90}
RISK_DATA_CLASS = {"Public": 0, "Internal": 2, "Protected-A": 8, "Protected-B": 15, "Protected-C": 25}
RISK_TIER = {"low": 0, "medium": 5, "high": 15, "critical": 25}

PASS, FAIL, FLAG, STEP, NA = "pass", "fail", "flag", "step_up", "na"
AARM = {"allow": "ALLOW", "escalate": "STEP_UP", "deny": "DENY"}


@dataclass
class Stage:
    name: str
    result: str
    detail: str

    def to_dict(self) -> Dict[str, str]:
        return {"stage": self.name, "result": self.result, "detail": self.detail}


@dataclass
class Evaluation:
    verdict: str
    stages: List[Stage]
    canonical: Dict[str, Any]
    agent: Any = None
    spec: Any = None
    scope_level: int = 0
    effective_data_class: str = ""
    risk_score: float = 0.0
    risk_factors: Dict[str, Any] = field(default_factory=dict)
    budget: Any = None
    policy_version_hash: str = ""
    policy_rule: str = ""

    @property
    def hard_failures(self) -> List[Stage]:
        return [s for s in self.stages if s.result == FAIL]

    @property
    def step_ups(self) -> List[Stage]:
        return [s for s in self.stages if s.result == STEP]


@dataclass
class ControlPlaneConfig:
    escalation_threshold: float = 70.0
    approval_timeout_seconds: int = 3600
    tool_auth_enabled: bool = True


def _transaction_cancelled(exc: Exception) -> bool:
    """True when DynamoDB cancelled a transaction because a condition failed."""
    response = getattr(exc, "response", None) or {}
    return response.get("Error", {}).get("Code") == "TransactionCanceledException"


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _data_class_rank(label: str) -> int:
    return DATA_CLASS_ORDER.index(label) if label in DATA_CLASS_ORDER else len(DATA_CLASS_ORDER)


class DelegatedAuthorityControlPlane:
    def __init__(self, *, registry, scope_table, approvals, tool_auth_table, grants, ledger,
                 operations, catalog, broker, evidence, opa, decision_table=None,
                 config: Optional[ControlPlaneConfig] = None,
                 on_event: Optional[Callable[[str, Dict[str, Any]], None]] = None):
        self.registry = registry
        self.scope_table = scope_table
        self.approvals = approvals
        self.tool_auth_table = tool_auth_table
        self.grants = grants
        self.ledger = ledger
        self.operations = operations
        self.catalog = catalog
        self.broker = broker
        self.evidence = evidence
        self.opa = opa
        self.decision_table = decision_table
        self.config = config or ControlPlaneConfig()
        self._on_event = on_event

    # ================================================================ helpers
    def _scope_of(self, agent_id: str) -> int:
        item = self.scope_table.get_item(Key={"agent_id": agent_id}, ConsistentRead=True).get("Item") or {}
        return int(item.get("scope_level", 0) or 0)

    def policy_version_hash(self, agent) -> str:
        """Every input that can change an outcome for this agent."""
        relevant = {k: getattr(agent, k) for k in (
            "approved_scope", "environment", "data_classes", "agent_type", "allowed_providers",
            "allowed_operations", "allowed_resource_patterns", "spend_policy", "requires_human_for",
            "risk_tier", "policy_bundle", "credential_ttl_seconds")} if agent else {}
        return compute_policy_version_hash([
            self.operations.fingerprint(), self.opa.policy_fingerprint(),
            to_json_safe(relevant), self.catalog.to_policy_input(),
            {"escalation_threshold": self.config.escalation_threshold},
        ])

    def _record(self, agent_id: str, chain_id: str, event_type: str, **fields) -> Dict[str, Any]:
        rec = self.evidence.record(agent_id=agent_id or "unknown", chain_id=chain_id,
                                   event_type=event_type, **fields)
        if self._on_event:
            self._on_event(event_type, rec)
        return rec

    def _store_decision(self, decision, evaluation: Evaluation) -> None:
        if self.decision_table is None:
            return
        body = {"decision_id": decision.decision_id, "agent_id": decision.agent_id,
                "operation_id": evaluation.canonical.get("operation_id", ""),
                "target_resource": evaluation.canonical.get("target_resource", ""),
                "verdict": decision.verdict, "risk_score": evaluation.risk_score,
                "timestamp": decision.timestamp, "request_digest": decision.request_digest,
                "policy_version_hash": decision.policy_version_hash,
                "decisive_stage": (evaluation.hard_failures or evaluation.step_ups or [Stage("opa_policy", PASS, "")])[0].name,
                "stages": [s.to_dict() for s in evaluation.stages]}
        canonical = canonical_json(to_json_safe(body))
        trace_hash = sha256_hex(canonical)
        signer = self.evidence.signer
        self.decision_table.put_item(Item={
            "decision_id": decision.decision_id, "agent_id": decision.agent_id,
            "verdict": decision.verdict, "timestamp": decision.timestamp,
            "canonical_body": canonical, "trace_hash": trace_hash,
            "signature": signer.sign(trace_hash), "signing_key_id": signer.key_id,
            "signing_algorithm": signer.algorithm, "trace_type": "delegated_authority"})

    def decision_summaries(self, agent_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """Signed decision traces for one agent (guardian inspection)."""
        if self.decision_table is None:
            return []
        from boto3.dynamodb.conditions import Attr
        # The trace table is shared with the governance engine, whose traces
        # have a different body; read only delegated-authority traces.
        flt = Attr("agent_id").eq(agent_id) & Attr("trace_type").eq("delegated_authority")
        resp = self.decision_table.scan(FilterExpression=flt)
        items = list(resp.get("Items", []))
        while "LastEvaluatedKey" in resp:
            resp = self.decision_table.scan(FilterExpression=flt, ExclusiveStartKey=resp["LastEvaluatedKey"])
            items.extend(resp.get("Items", []))
        rows = []
        for item in items:
            body = json.loads(item["canonical_body"])
            rows.append({"decision_id": body["decision_id"], "operation_id": body["operation_id"],
                         "verdict": body["verdict"], "risk_score": body["risk_score"],
                         "decisive_stage": body["decisive_stage"], "timestamp": body["timestamp"],
                         "signature_verified": self.evidence.signer.verify(item["trace_hash"], item["signature"])
                         and sha256_hex(item["canonical_body"]) == item["trace_hash"]})
        return sorted(rows, key=lambda r: r["timestamp"], reverse=True)[:limit]

    # ============================================================= evaluation
    def evaluate(self, request: Dict[str, Any], caller: Optional[AuthenticatedCaller]) -> Evaluation:
        stages: List[Stage] = []
        add = stages.append

        def stop(canonical) -> Evaluation:
            for name in ("kill_switch", "registry", "operation_registered", "provider", "operation_allowed",
                         "role_boundary", "scope", "environment", "resource", "data_classification",
                         "parameters", "budget", "tool_authorization", "risk", "human_approval", "opa_policy"):
                if not any(s.name == name for s in stages):
                    add(Stage(name, NA, "not evaluated: an earlier mandatory gate denied the request"))
            return Evaluation("deny", stages, canonical)

        # --- request shape -------------------------------------------------
        injected = sorted(k for k in request if k in AUTHORITY_FIELDS)
        missing = [k for k in REQUIRED_REQUEST_FIELDS if k not in request]
        try:
            canonical = canonicalize_action_request(request)
        except CanonicalizationError as exc:
            add(Stage("request_shape", FAIL, f"request rejected: {exc}"))
            return stop({"agent_id": str(request.get("agent_id", ""))})
        if injected:
            add(Stage("request_shape", FAIL, f"authority-changing fields are not accepted from an agent: {injected}"))
            return stop(canonical)
        if missing:
            add(Stage("request_shape", FAIL, f"structured request is missing {missing}"))
            return stop(canonical)
        add(Stage("request_shape", PASS, "structured operation request; free text is context only"))

        # --- identity ------------------------------------------------------
        agent_id = canonical["agent_id"]
        if caller is None or not caller.principal_id:
            add(Stage("identity", FAIL, "request is not authenticated"))
            return stop(canonical)
        if not caller.is_agent:
            add(Stage("identity", FAIL, "only an authenticated agent principal can request delegated authority"))
            return stop(canonical)
        if caller.agent_id != agent_id:
            add(Stage("identity", FAIL, f"authenticated as '{caller.agent_id}' but the request claims "
                                        f"'{agent_id}' (impersonation)"))
            return stop(canonical)
        add(Stage("identity", PASS, f"authenticated agent principal {caller.principal_id}"))

        # --- kill switch / current scope ----------------------------------
        scope = self._scope_of(agent_id)
        if scope <= 0:
            add(Stage("kill_switch", FAIL, "agent scope is 0: kill switch active, every action is denied"))
            return stop(canonical)
        add(Stage("kill_switch", PASS, f"agent active at scope {scope}"))

        # --- registry -------------------------------------------------------
        agent = self.registry.get_agent(agent_id)
        if agent is None:
            add(Stage("registry", FAIL, f"agent '{agent_id}' is not registered"))
            return stop(canonical)
        if agent.status != "active":
            add(Stage("registry", FAIL, f"agent status is {agent.status}"))
            return stop(canonical)
        errors = agent.validate_governance_fields()
        if errors:
            add(Stage("registry", FAIL, f"registry entry is invalid: {errors}"))
            return stop(canonical)
        if agent.requires_guardian:
            guardians = [self.registry.get_agent(g) for g in agent.guardian_agent_ids]
            if not any(g is not None and g.status == "active" and g.agent_type == "guardian" for g in guardians):
                add(Stage("registry", FAIL, "agent requires an active guardian and none is registered"))
                return stop(canonical)
        add(Stage("registry", PASS, f"{agent.agent_type} agent owned by {agent.business_owner or agent.owner}, "
                                    f"risk tier {agent.risk_tier}"))

        # --- operation ----------------------------------------------------
        spec = self.operations.get(canonical["operation_id"])
        if spec is None:
            add(Stage("operation_registered", FAIL, f"operationId '{canonical['operation_id']}' is not "
                                                    "registered; unregistered operations are denied"))
            return stop(canonical)
        add(Stage("operation_registered", PASS, f"{spec.method.upper()} {spec.path} ({spec.risk_category})"))

        policy_hash = self.policy_version_hash(agent)
        ev = Evaluation("deny", stages, canonical, agent=agent, spec=spec,
                        policy_version_hash=policy_hash)

        # From here every gate runs so the trace shows the complete picture.
        if canonical["provider"] != spec.provider:
            add(Stage("provider", FAIL, f"operation belongs to {spec.provider}, request says {canonical['provider']}"))
        elif spec.provider not in agent.allowed_providers:
            add(Stage("provider", FAIL, f"provider {spec.provider} is not approved for this agent"))
        else:
            add(Stage("provider", PASS, spec.provider))

        if spec.operation_id in agent.allowed_operations:
            add(Stage("operation_allowed", PASS, "operation is in the agent's approved operations"))
        else:
            add(Stage("operation_allowed", FAIL, f"{spec.operation_id} is not in the agent's approved operations"))

        outcome, reason = evaluate_role_boundary(agent, spec, canonical["target_resource"], self.registry.get_agent)
        add(Stage("role_boundary", PASS if outcome == "pass" else FAIL, reason))

        effective_scope = min(scope, int(agent.approved_scope))
        ev.scope_level = effective_scope
        if effective_scope >= spec.min_scope:
            add(Stage("scope", PASS, f"scope {effective_scope} >= required {spec.min_scope}"))
        else:
            add(Stage("scope", FAIL, f"scope {effective_scope} is below the required {spec.min_scope}; "
                                     "scope changes are human-only"))

        env = canonical["environment"]
        if env not in spec.allowed_environments or env != agent.environment:
            add(Stage("environment", FAIL, f"environment '{env}' is not approved (agent: {agent.environment})"))
        else:
            add(Stage("environment", PASS, env))

        target = canonical["target_resource"]
        if not spec.resource_allowed(target):
            add(Stage("resource", FAIL, f"{target} is outside the operation's resource patterns"))
        elif not any(fnmatch.fnmatchcase(target, p) for p in agent.allowed_resource_patterns):
            add(Stage("resource", FAIL, f"{target} is outside the agent's approved resource boundary"))
        else:
            add(Stage("resource", PASS, target))

        declared = canonical["data_class"]
        effective = spec.data_class
        note = ""
        if declared and _data_class_rank(declared) > _data_class_rank(spec.data_class):
            effective = declared
        elif declared and declared != spec.data_class:
            note = f" (request declared {declared}; the operation's {spec.data_class} classification applies)"
        ev.effective_data_class = effective
        if effective in agent.data_classes:
            add(Stage("data_classification", PASS, f"{effective} is approved for this agent{note}"))
        else:
            add(Stage("data_classification", FAIL, f"{effective} data is not approved for this agent{note}"))

        param_errors = validate_against_schema(spec.parameter_schema, canonical["tool_parameters"])
        if param_errors:
            add(Stage("parameters", FAIL, "; ".join(param_errors)))
        else:
            add(Stage("parameters", PASS, "parameters match the operation schema"))

        # --- budget -------------------------------------------------------
        try:
            session_spent, daily_spent = self.ledger.totals(agent_id, canonical["session_id"])
        except Exception as exc:
            session_spent, daily_spent = Decimal("0"), Decimal("0")
            add(Stage("budget", FAIL, f"spend ledger unavailable ({exc}); failing closed"))
        else:
            budget = evaluate_budget(
                financial_impact=spec.financial_impact, amount_derivation=spec.amount_derivation,
                tool_parameters=canonical["tool_parameters"],
                claimed_financial_context=request.get("financial_context") or {},
                spend_policy=SpendPolicy.from_registry(agent.spend_policy), catalog=self.catalog,
                session_spent=session_spent, daily_spent=daily_spent)
            ev.budget = budget
            result = {NOT_APPLICABLE: NA, STEP_UP: STEP, BUDGET_DENY: FAIL}.get(budget.outcome, PASS)
            add(Stage("budget", result, "; ".join(budget.reasons)))

        # --- tool authorization ------------------------------------------
        if self.config.tool_auth_enabled:
            auth = ToolExecutionAuthManager().authorize_tool(
                agent_id, spec.operation_id, {}, self.tool_auth_table)
            add(Stage("tool_authorization", PASS if auth.authorized else FAIL,
                      "tool registration, agent allowlist, rate and chain checks passed"
                      if auth.authorized else auth.denial_reason))

        # --- risk ----------------------------------------------------------
        factors = {"operation_risk": RISK_BASE.get(spec.risk_category, 30),
                   "environment": 5 if env == "prod" else 0,
                   "data_class": RISK_DATA_CLASS.get(effective, 30),
                   "agent_risk_tier": RISK_TIER.get(agent.risk_tier, 15)}
        policy = SpendPolicy.from_registry(agent.spend_policy)
        if ev.budget is not None and ev.budget.transaction_amount is not None and policy:
            ratio = ev.budget.transaction_amount / max(policy.per_transaction_max, Decimal("1"))
            factors["spend_vs_autonomous_limit"] = float(min(Decimal("25"), (ratio * 25).quantize(Decimal("0.1"))))
        score = float(min(100, sum(factors.values())))
        ev.risk_score, ev.risk_factors = score, factors
        if score >= self.config.escalation_threshold:
            add(Stage("risk", STEP, f"risk {score:.0f}/100 meets the escalation threshold "
                                    f"{self.config.escalation_threshold:.0f}"))
        else:
            add(Stage("risk", PASS, f"risk {score:.0f}/100 is below the escalation threshold "
                                    f"{self.config.escalation_threshold:.0f}"))

        # --- human approval requirements ----------------------------------
        if spec.requires_approval or spec.operation_id in agent.requires_human_for:
            add(Stage("human_approval", STEP, f"{spec.operation_id} always requires a human approver"))
        else:
            add(Stage("human_approval", PASS, "no standing human-approval requirement"))

        # --- OPA policy resolves the verdict -----------------------------
        hard_failed = any(s.result == FAIL for s in stages)
        facts = {
            "hard_gate_failed": hard_failed,
            "budget_outcome": ev.budget.outcome if ev.budget else NOT_APPLICABLE,
            "human_required": any(s.name == "human_approval" and s.result == STEP for s in stages),
            "risk_exceeds_threshold": score >= self.config.escalation_threshold,
            "operation_registered": True,
            "within_boundary": not hard_failed,
            "environment": env, "risk_category": spec.risk_category,
        }
        try:
            decision = self.opa.evaluate(facts)
            verdict = decision.verdict if decision.verdict in ("allow", "escalate", "deny") else "deny"
            ev.policy_rule = (decision.matched_rules or ["default-deny"])[0]
            detail = decision.explanation
        except Exception as exc:
            verdict, detail, ev.policy_rule = "deny", f"policy evaluation failed ({exc}); failing closed", "error"
        # Defense in depth: policy can never override a failed gate or a step-up.
        if hard_failed:
            verdict = "deny"
        elif verdict == "allow" and any(s.result == STEP for s in stages):
            verdict = "escalate"
        add(Stage("opa_policy", {"allow": PASS, "escalate": STEP, "deny": FAIL}[verdict], detail))
        ev.verdict = verdict
        return ev

    def _decision(self, ev: Evaluation):
        outcome = ev.verdict
        policy_result = PolicyEvaluationResult(policy_id=ev.policy_rule or "default-deny", outcome=outcome)
        risk = RiskAssessment(risk_score=ev.risk_score,
                              risk_category=ev.spec.risk_category if ev.spec else "unknown")
        decision = DecisionEngine(escalation_threshold=self.config.escalation_threshold).decide(
            policy_result, risk, dict(ev.canonical), ev.canonical.get("agent_id", ""),
            policy_version_hash=ev.policy_version_hash)
        if ev.hard_failures:
            decision.verdict = "deny"
            decision.explanation = "; ".join(f"{s.name}: {s.detail}" for s in ev.hard_failures)
        elif ev.step_ups and decision.verdict == "allow":
            decision.verdict = "escalate"
        if decision.verdict == "escalate":
            decision.explanation = "; ".join(f"{s.name}: {s.detail}" for s in ev.step_ups) or decision.explanation
        return decision

    def _grant_fields(self, ev: Evaluation, decision_id: str, approval_id: str, delegated_by: str,
                      spend_amount: Optional[Decimal]) -> Dict[str, Any]:
        spec, agent, canonical = ev.spec, ev.agent, ev.canonical
        spend_limit = {}
        if spec.financial_impact and ev.budget is not None:
            policy = SpendPolicy.from_registry(agent.spend_policy)
            limit = spend_amount if approval_id else policy.per_transaction_max
            spend_limit = {"currency": ev.budget.currency, "amount": limit}
        return dict(
            agent_id=canonical["agent_id"], session_id=canonical["session_id"], delegated_by=delegated_by,
            provider=spec.provider, operation_id=spec.operation_id,
            target_resource=canonical["target_resource"], resource_patterns=[canonical["target_resource"]],
            parameter_constraints={k: {"equals": v} for k, v in canonical["tool_parameters"].items()},
            data_classes=[ev.effective_data_class], spend_limit=spend_limit, scope_level=ev.scope_level,
            environment=canonical["environment"], decision_id=decision_id, approval_id=approval_id,
            policy_version_hash=ev.policy_version_hash,
            request_digest=compute_action_request_digest(canonical, ev.policy_version_hash),
            ttl_seconds=min(int(agent.credential_ttl_seconds), int(spec.credential_ttl_seconds)),
            max_uses=spec.max_uses)

    def _mint(self, ev: Evaluation, decision_id: str, approval_id: str, delegated_by: str,
              spend_amount: Optional[Decimal]):
        return self.grants.mint(**self._grant_fields(ev, decision_id, approval_id, delegated_by, spend_amount))

    def _grant_payload(self, grant) -> Dict[str, Any]:
        verified = self.grants.signer.verify(grant.signing_digest(), grant.signature)
        return {**grant.public_view(), "signature_verified": verified,
                "signer_demo_only": bool(getattr(self.grants.signer, "demo_only", False))}

    # ============================================================ agent plane
    def request_authority(self, request: Dict[str, Any], caller: Optional[AuthenticatedCaller]) -> Dict[str, Any]:
        ev = self.evaluate(request, caller)
        decision = self._decision(ev)
        agent_id = ev.canonical.get("agent_id", "")
        self._store_decision(decision, ev)
        self._record(agent_id, decision.decision_id, "decision", decision_id=decision.decision_id,
                     verdict=decision.verdict, operation_id=ev.canonical.get("operation_id"),
                     provider=ev.canonical.get("provider"), target_resource=ev.canonical.get("target_resource"),
                     request_digest=decision.request_digest, policy_version_hash=decision.policy_version_hash,
                     risk_score=ev.risk_score, stages=[s.to_dict() for s in ev.stages],
                     principal=caller.principal_id if caller else "")
        response = {"verdict": decision.verdict, "aarm_decision": AARM.get(decision.verdict, "DENY"),
                    "decision_id": decision.decision_id, "explanation": decision.explanation,
                    "risk_score": ev.risk_score, "risk_factors": ev.risk_factors,
                    "stages": [s.to_dict() for s in ev.stages], "request_digest": decision.request_digest,
                    "policy_version_hash": decision.policy_version_hash,
                    "budget": ev.budget.to_dict() if ev.budget else None}
        if decision.verdict == "escalate":
            approval_id = self.approvals.create_pending_approval(
                decision, timeout_seconds=self.config.approval_timeout_seconds)
            self._record(agent_id, decision.decision_id, "approval_requested", approval_id=approval_id,
                         decision_id=decision.decision_id, request_digest=decision.request_digest)
            response["approval_id"] = approval_id
            response["credential_issued"] = False
        elif decision.verdict == "allow":
            grant = self._mint(ev, decision.decision_id, "",
                               f"policy:{ev.agent.policy_bundle}@{ev.policy_version_hash[:12]}", None)
            self._record(agent_id, decision.decision_id, "grant_minted", grant_id=grant.grant_id,
                         decision_id=decision.decision_id, expires_at=grant.expires_at,
                         signing_key_id=grant.signing_key_id, request_digest=grant.request_digest)
            response["grant"] = self._grant_payload(grant)
        return to_json_safe(response)

    def mint_after_approval(self, approval_id: str, request: Dict[str, Any],
                            caller: Optional[AuthenticatedCaller]) -> Dict[str, Any]:
        """Exchange a human-approved request for a grant (exact request only)."""
        ev = self.evaluate(request, caller)
        agent_id = ev.canonical.get("agent_id", "")
        chain = f"approval-{approval_id}"
        if ev.agent is None or ev.spec is None:
            reason = "; ".join(f"{s.name}: {s.detail}" for s in ev.hard_failures)
            self._record(agent_id, chain, "mint_denied", approval_id=approval_id, reason=reason)
            return {"verdict": "deny", "aarm_decision": "DENY", "reason": reason,
                    "stages": [s.to_dict() for s in ev.stages]}
        ok, reason, item = self.approvals.check_binding(approval_id, ev.canonical, ev.policy_version_hash)
        if not ok:
            self._record(agent_id, chain, "mint_denied", approval_id=approval_id, reason=reason)
            return {"verdict": "deny", "aarm_decision": "DENY", "reason": reason, "approval_id": approval_id}
        if ev.hard_failures:
            reason = "approval cannot override a failed gate: " + "; ".join(
                f"{s.name}: {s.detail}" for s in ev.hard_failures)
            self._record(agent_id, chain, "mint_denied", approval_id=approval_id, reason=reason)
            return {"verdict": "deny", "aarm_decision": "DENY", "reason": reason,
                    "stages": [s.to_dict() for s in ev.stages]}
        # `item` is the approval record check_binding returned above.
        decision_id = item.get("decision_id", "")
        approver = item.get("approver_id", "")
        amount = ev.budget.transaction_amount if ev.budget is not None else None
        grant = self.grants.build(**self._grant_fields(ev, decision_id, approval_id, approver, amount))
        try:
            # One transaction: the approval is consumed exactly when the grant is
            # written. A replay or an expiry cancels both; a failed grant write
            # leaves the approval unused.
            self.grants.mint_in_transaction(
                grant, [self.approvals.consume_transact_item(approval_id, grant.grant_id)])
        except Exception as exc:
            reason = ("approval consumed concurrently (replay attempt)" if _transaction_cancelled(exc)
                      else f"approval could not be consumed: {type(exc).__name__}")
            self._record(agent_id, chain, "mint_denied", approval_id=approval_id, reason=reason)
            return {"verdict": "deny", "aarm_decision": "DENY", "reason": reason, "approval_id": approval_id}
        self._record(agent_id, decision_id, "approval_consumed", approval_id=approval_id,
                     decision_id=decision_id, approver_id=approver)
        self._record(agent_id, decision_id, "grant_minted", grant_id=grant.grant_id, approval_id=approval_id,
                     decision_id=decision_id, expires_at=grant.expires_at, request_digest=grant.request_digest)
        return to_json_safe({"verdict": "allow", "aarm_decision": "ALLOW", "approval_id": approval_id,
                             "decision_id": decision_id, "approved_by": approver,
                             "grant": self._grant_payload(grant)})

    def execute(self, grant_id: str, request: Dict[str, Any], caller: Optional[AuthenticatedCaller]) -> Dict[str, Any]:
        """Verify + consume the grant, exchange it for a credential, execute."""
        try:
            canonical = canonicalize_action_request(request)
        except CanonicalizationError as exc:
            return {"status": "denied", "reason": f"request rejected: {exc}"}
        agent_id = canonical["agent_id"]
        grant = self.grants.get(grant_id)
        chain = grant.decision_id if grant else f"grant-{grant_id}"

        def deny(reason: str, checks=None) -> Dict[str, Any]:
            self._record(agent_id, chain, "execution_denied", grant_id=grant_id, reason=reason)
            current = self.grants.get(grant_id)
            return to_json_safe({"status": "denied", "reason": reason, "grant_id": grant_id,
                                 "grant_status": current.status if current else "MISSING",
                                 "checks": checks or []})

        if caller is None or not caller.is_agent or caller.agent_id != agent_id:
            return deny("execution requires the authenticated agent the grant was issued to")
        if self._scope_of(agent_id) <= 0:
            return deny("kill switch active: agent scope is 0")
        agent = self.registry.get_agent(agent_id)
        if agent is None or agent.status != "active":
            return deny("agent is not registered or not active")
        spec = self.operations.get(canonical["operation_id"])
        if spec is None:
            return deny("operation is not registered")

        verification, verified = self.grants.verify_and_consume(grant_id, request)
        if verified is None:
            return deny(verification.reason, verification.checks_view())
        grant = verified.grant
        self._record(agent_id, chain, "grant_consumed", grant_id=grant_id, decision_id=grant.decision_id,
                     uses_remaining=grant.uses_remaining, grant_status=grant.status)

        if spec.financial_impact:
            policy = SpendPolicy.from_registry(agent.spend_policy)
            amount = Decimal(str(verified.canonical_request["financial_context"]["transaction_amount"]))
            autonomous = not grant.approval_id
            ok, reason = self.ledger.record(
                agent_id, grant.session_id, amount, verified.canonical_request["financial_context"]["currency"],
                grant_id, session_cap=policy.per_session_max if autonomous else None,
                daily_cap=policy.daily_max if autonomous else None, autonomous=autonomous)
            if not ok:
                return deny(reason, verification.checks_view())

        try:
            handle = self.broker.exchange(verified, spec)
        except BrokerRefusal as exc:
            return deny(f"credential exchange refused: {exc}", verification.checks_view())
        credential = handle.metadata()
        self._record(agent_id, chain, "credential_issued", grant_id=grant_id,
                     credential_reference=handle.credential_reference, provider=handle.provider,
                     credential_type=handle.credential_type, credential_expires_at=handle.expires_at,
                     credential_effective_until=handle.effective_until, scopes=handle.scopes,
                     adapter_mode=handle.mode)
        result = self.broker.execute(handle, verified, spec)
        if self.tool_auth_table is not None:
            ToolExecutionAuthManager().record_tool_call(agent_id, spec.operation_id, self.tool_auth_table)
        after = self.grants.get(grant_id)
        final = self._record(agent_id, chain, "execution_completed", grant_id=grant_id,
                             decision_id=grant.decision_id, approval_id=grant.approval_id or None,
                             provider=spec.provider, operation_id=spec.operation_id,
                             request_digest=grant.request_digest,
                             credential_reference=handle.credential_reference,
                             credential_expires_at=handle.expires_at, execution_status=result.status,
                             execution_result_hash=result.result_hash,
                             grant_status_after=after.status if after else "MISSING")
        chain_ok, chain_detail = self.evidence.verify_chain(self.evidence.chain(agent_id, chain))
        return to_json_safe({
            "status": "executed" if result.status == "success" else "failed",
            "grant_id": grant_id, "decision_id": grant.decision_id,
            "grant_checks": verification.checks_view(), "credential": credential,
            "execution": result.to_dict(), "grant_status_after": after.status if after else "MISSING",
            "evidence_id": final["evidence_id"], "evidence_location": final.get("location"),
            "evidence_chain_verified": chain_ok, "evidence_chain_detail": chain_detail})

    # ========================================================= approval plane
    def approve_request(self, approval_id: str, caller: AuthenticatedCaller,
                        conditions: str = "") -> Dict[str, Any]:
        """Human approval with the same separation-of-duties rules as the API."""
        from authority_identity import check_approver_eligibility
        item = self.approvals.get_record(approval_id)
        if not item:
            return {"status": "denied", "reason": f"approval {approval_id} not found"}
        agent = self.registry.get_agent(item.get("agent_id", ""))
        ok, why = check_approver_eligibility(caller, item, agent)
        if not ok:
            self._record(item.get("agent_id", ""), item.get("decision_id", ""), "approval_rejected",
                         approval_id=approval_id, principal=caller.principal_id if caller else "", reason=why)
            return {"status": "denied", "reason": why}
        try:
            result = self.approvals.approve(approval_id, caller.principal_id, agent.owner if agent else "",
                                            conditions)
        except ValueError as exc:
            return {"status": "denied", "reason": str(exc)}
        self._record(item.get("agent_id", ""), item.get("decision_id", ""), "approval_granted",
                     approval_id=approval_id, approver_id=caller.principal_id,
                     request_digest=item.get("request_digest", ""))
        return {"status": "approved", "approval_id": approval_id, "approver_id": caller.principal_id,
                "decision_id": result.decision_id if result else item.get("decision_id", "")}

    # ============================================================ admin plane
    def revoke_grant(self, grant_id: str, caller: AuthenticatedCaller, reason: str) -> Dict[str, Any]:
        ok, why = check_admin(caller, REVOKER_ROLES)
        if not ok:
            return {"status": "denied", "reason": why}
        grant = self.grants.get(grant_id)
        revoked, detail = self.grants.revoke(grant_id, caller.principal_id, reason)
        if grant:
            self._record(grant.agent_id, grant.decision_id, "grant_revoked" if revoked else "revoke_failed",
                         grant_id=grant_id, revoked_by=caller.principal_id, reason=reason, detail=detail)
        return {"status": "revoked" if revoked else "unchanged", "detail": detail, "grant_id": grant_id}

    def activate_kill_switch(self, agent_id: str, caller: AuthenticatedCaller, reason: str) -> Dict[str, Any]:
        ok, why = check_admin(caller, REVOKER_ROLES)
        if not ok:
            return {"status": "denied", "reason": why}
        self.scope_table.update_item(
            Key={"agent_id": agent_id}, UpdateExpression="SET #s = :zero, #u = :by, #t = :now",
            ExpressionAttributeNames={"#s": "scope_level", "#u": "updated_by", "#t": "updated_at"},
            ExpressionAttributeValues={":zero": 0, ":by": caller.principal_id, ":now": _iso_now()})
        revoked = self.grants.revoke_all_for_agent(agent_id, caller.principal_id, f"kill switch: {reason}")
        chain = f"killswitch-{agent_id}-{int(datetime.now(timezone.utc).timestamp())}"
        self._record(agent_id, chain, "kill_switch_activated", activated_by=caller.principal_id,
                     reason=reason, revoked_grants=revoked)
        return {"status": "kill_switch_active", "agent_id": agent_id, "scope_level": 0, "revoked_grants": revoked}

    def admin_set_scope(self, agent_id: str, new_scope: int, caller: AuthenticatedCaller,
                        reason: str = "") -> Dict[str, Any]:
        """The ONLY path that raises or lowers an agent's scope (human admins)."""
        ok, why = check_admin(caller, ADMIN_ROLES)
        if not ok:
            return {"status": "denied", "reason": why}
        agent = self.registry.get_agent(agent_id)
        if agent is None:
            return {"status": "denied", "reason": f"agent '{agent_id}' is not registered"}
        if not isinstance(new_scope, int) or isinstance(new_scope, bool) or not 0 <= new_scope <= 4:
            return {"status": "denied", "reason": "scope must be an integer from 0 to 4"}
        if new_scope > int(agent.approved_scope):
            return {"status": "denied", "reason": (f"scope {new_scope} exceeds the agent's approved scope "
                                                   f"{agent.approved_scope}; change the registry first")}
        previous = self._scope_of(agent_id)
        self.scope_table.update_item(
            Key={"agent_id": agent_id}, UpdateExpression="SET #s = :s, #u = :by, #t = :now",
            ExpressionAttributeNames={"#s": "scope_level", "#u": "updated_by", "#t": "updated_at"},
            ExpressionAttributeValues={":s": new_scope, ":by": caller.principal_id, ":now": _iso_now()})
        chain = f"scope-{agent_id}-{int(datetime.now(timezone.utc).timestamp())}"
        self._record(agent_id, chain, "scope_changed", previous_scope=previous, new_scope=new_scope,
                     changed_by=caller.principal_id, human_authorized=True, reason=reason)
        return {"status": "updated", "agent_id": agent_id, "previous_scope": previous, "scope_level": new_scope}

    def describe_agent(self, agent_id: str) -> Dict[str, Any]:
        agent = self.registry.get_agent(agent_id)
        if agent is None:
            return {}
        view = agent.to_dict()
        view["current_scope"] = self._scope_of(agent_id)
        return to_json_safe(view)


def chain_summary(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Compact view of an evidence chain for UIs and reports."""
    return [{"seq": r["seq"], "event_type": r["event_type"], "record_hash": r["record_hash"][:16] + "...",
             "prev_hash": (r["prev_hash"][:16] + "...") if r["prev_hash"] != "GENESIS" else "GENESIS"}
            for r in sorted(records, key=lambda x: x["seq"])]


def evaluation_digest_matches(canonical: Dict[str, Any], policy_hash: str, digest: str) -> Tuple[bool, str]:
    actual = compute_action_request_digest(canonical, policy_hash)
    return actual == digest, actual
