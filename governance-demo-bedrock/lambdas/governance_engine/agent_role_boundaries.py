"""Role boundaries for agents that watch agents.

Agent types:
  worker      performs approved business operations within its scope
  guardian    observes assigned workers: inspects decisions and evidence,
              evaluates behaviour, recommends suspension, raises alerts
  governance  automation for governance bookkeeping (reports, alerts)

Invariants (enforced for every agent type, before any policy runs):
  * Human-only actions are never performed by an agent. The set is the
    existing CedarEngine.HUMAN_ONLY_ACTIONS boundary (GrantScope, AmendPolicy,
    ApproveException, OverrideDecision, MakeComplianceDetermination, ...).
  * A guardian may only observe agents that list it in guardian_agent_ids,
    and never itself. It cannot grant scope, change policy, approve
    exceptions, modify monitoring or evidence settings, or approve anything.
  * A worker cannot target another agent with any governance operation.
  * Spending authority belongs to workers only.
"""

from typing import Any, Callable, Optional, Tuple

from cedar_engine import CedarEngine

HUMAN_ONLY_ACTIONS = CedarEngine.HUMAN_ONLY_ACTIONS

PASS = "pass"
DENY = "deny"


def target_agent_id(target_resource: str) -> str:
    """agent/<id>[/...] -> <id>; any other resource -> ''."""
    if not target_resource.startswith("agent/"):
        return ""
    return target_resource.split("/", 2)[1] if "/" in target_resource else ""


def evaluate_role_boundary(agent: Any, spec: Any, target_resource: str,
                           lookup_agent: Callable[[str], Optional[Any]]) -> Tuple[str, str]:
    """Return (PASS|DENY, reason) for agent performing spec on target_resource."""
    agent_type = getattr(agent, "agent_type", "worker") or "worker"

    if spec.human_only:
        action = spec.human_only_action or spec.operation_id
        boundary = f" ({action} is in the human-only action set)" if action in HUMAN_ONLY_ACTIONS else ""
        return DENY, (f"{spec.operation_id} is a human-only operation{boundary}; no agent of any type "
                      "can perform it, and authority changes go through the human governance plane")
    if spec.resource_is_human_only(target_resource):
        return DENY, (f"target {target_resource} is a privileged resource; changing it is human-only "
                      f"({spec.human_only_action or 'GrantScope'})")
    if agent_type not in spec.allowed_agent_types:
        return DENY, (f"{agent_type} agents may not perform {spec.operation_id} "
                      f"(allowed: {list(spec.allowed_agent_types) or 'humans only'})")
    if spec.financial_impact and agent_type != "worker":
        return DENY, "only worker agents may hold spending authority"

    subject = target_agent_id(target_resource)
    if spec.provider == "governance" or subject:
        if agent_type == "worker":
            return DENY, "worker agents cannot act on other agents or on governance resources"
        if subject == getattr(agent, "agent_id", ""):
            return DENY, "an agent cannot observe, evaluate or act on itself"
        if spec.requires_assigned_guardian:
            observed = lookup_agent(subject) if subject else None
            if observed is None:
                return DENY, f"observed agent '{subject}' is not registered"
            if agent_type == "guardian" and agent.agent_id not in (observed.guardian_agent_ids or []):
                return DENY, (f"guardian '{agent.agent_id}' is not assigned to observe '{subject}'")
    return PASS, f"{agent_type} agent may request {spec.operation_id} on {target_resource}"
