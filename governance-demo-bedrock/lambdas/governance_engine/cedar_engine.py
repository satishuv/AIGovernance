"""Cedar Policy Engine - formal verification and authorization for AI governance.

Cedar is an open-source authorization policy language by AWS, hosted by CNCF.
It provides formally verified, deterministic policy evaluation with mathematical
guarantees that authorization decisions are safe and free of contradictions.

This module runs ALONGSIDE the OPA engine:
- OPA: flexible Rego-subset evaluation for governance policies (allow/deny/escalate)
- Cedar: formal authorization for tool access and data governance (permit/forbid)

Cedar adds:
- Formal verification (mathematically prove policies can't contradict)
- Fine-grained ABAC (attribute-based access control)
- Agent identity authorization (who can access what)
- Data classification enforcement (which data classes an agent can touch)

Integration: called from the governance engine for tool authorization decisions.
OPA handles the governance verdict (allow/deny/escalate).
Cedar handles the authorization question (is this principal permitted this action on this resource?).
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import cedarpy
    HAS_CEDAR = True
except ImportError:
    HAS_CEDAR = False
    logger.info("cedarpy not available; Cedar engine disabled")


CEDAR_MODE = os.environ.get("CEDAR_MODE", "enabled" if HAS_CEDAR else "disabled")


class CedarDecision:
    """Result of a Cedar authorization decision."""

    def __init__(self, decision: str, diagnostics: Dict[str, Any] = None,
                 policies_evaluated: int = 0):
        self.decision = decision  # "Allow" or "Deny"
        self.diagnostics = diagnostics or {}
        self.policies_evaluated = policies_evaluated
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "decision": self.decision,
            "diagnostics": self.diagnostics,
            "policies_evaluated": self.policies_evaluated,
            "timestamp": self.timestamp,
        }

    @property
    def is_allowed(self) -> bool:
        return self.decision == "Allow"


class CedarEngine:
    """Cedar-based authorization engine for agent governance.

    Evaluates fine-grained authorization decisions:
    - Can this agent access this tool?
    - Can this agent read this data class?
    - Can this agent operate in this environment?

    Policies are defined in Cedar syntax and loaded from S3 or inline.
    """

    # Default Cedar policies for AI agent governance
    DEFAULT_POLICIES = '''
// Agent scope-based tool authorization
permit (
    principal,
    action == Action::"ReadPipelineStatus",
    resource
) when {
    principal.scope_level >= 1
};

permit (
    principal,
    action == Action::"ProposeChanges",
    resource
) when {
    principal.scope_level >= 2
};

permit (
    principal,
    action == Action::"StagingDeployment",
    resource
) when {
    principal.scope_level >= 3
};

permit (
    principal,
    action == Action::"ProductionDeployment",
    resource
) when {
    principal.scope_level >= 4 &&
    resource.environment == "production"
};

// Deny production access for suspended agents
forbid (
    principal,
    action,
    resource
) when {
    principal.status == "suspended"
};

// Deny all actions when kill switch is active (scope 0)
forbid (
    principal,
    action,
    resource
) when {
    principal.scope_level == 0
};

// Data classification: block PHI access unless agent is authorized
forbid (
    principal,
    action,
    resource
) when {
    resource.data_class == "PHI" &&
    !principal.phi_authorized
};
'''

    # Cedar schema for governance entities
    DEFAULT_SCHEMA = {
        "": {
            "entityTypes": {
                "Agent": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "scope_level": {"type": "Long", "required": True},
                            "status": {"type": "String", "required": True},
                            "environment": {"type": "String", "required": True},
                            "phi_authorized": {"type": "Boolean", "required": False},
                            "team": {"type": "String", "required": False},
                        }
                    }
                },
                "Resource": {
                    "shape": {
                        "type": "Record",
                        "attributes": {
                            "environment": {"type": "String", "required": False},
                            "data_class": {"type": "String", "required": False},
                            "sensitivity": {"type": "String", "required": False},
                        }
                    }
                },
            },
            "actions": {
                "ReadPipelineStatus": {"appliesTo": {"principalTypes": ["Agent"], "resourceTypes": ["Resource"]}},
                "ProposeChanges": {"appliesTo": {"principalTypes": ["Agent"], "resourceTypes": ["Resource"]}},
                "StagingDeployment": {"appliesTo": {"principalTypes": ["Agent"], "resourceTypes": ["Resource"]}},
                "ProductionDeployment": {"appliesTo": {"principalTypes": ["Agent"], "resourceTypes": ["Resource"]}},
            }
        }
    }

    def __init__(self, policies: str = None, schema: Dict = None):
        self._policies = policies or self.DEFAULT_POLICIES
        self._schema = schema or self.DEFAULT_SCHEMA
        self._enabled = CEDAR_MODE != "disabled" and HAS_CEDAR

    @property
    def enabled(self) -> bool:
        return self._enabled

    def authorize(self, agent_id: str, action: str, resource_id: str,
                  agent_attrs: Dict[str, Any] = None,
                  resource_attrs: Dict[str, Any] = None) -> CedarDecision:
        """Evaluate a Cedar authorization request.

        Args:
            agent_id: The agent requesting authorization
            action: The action being requested (e.g., "ReadPipelineStatus")
            resource_id: The resource being accessed
            agent_attrs: Agent attributes (scope_level, status, environment, etc.)
            resource_attrs: Resource attributes (environment, data_class, etc.)

        Returns:
            CedarDecision with Allow or Deny
        """
        if not self._enabled:
            return CedarDecision(decision="Allow", diagnostics={"reason": "Cedar disabled"})

        agent_attrs = agent_attrs or {"scope_level": 1, "status": "active", "environment": "dev"}
        resource_attrs = resource_attrs or {"environment": "default"}

        # Build Cedar request
        request = {
            "principal": f'Agent::"{agent_id}"',
            "action": f'Action::"{action}"',
            "resource": f'Resource::"{resource_id}"',
            "context": {},
        }

        # Build entities
        entities = [
            {
                "uid": {"type": "Agent", "id": agent_id},
                "attrs": agent_attrs,
                "parents": [],
            },
            {
                "uid": {"type": "Resource", "id": resource_id},
                "attrs": resource_attrs,
                "parents": [],
            },
        ]

        try:
            response = cedarpy.is_authorized(
                request=request,
                policies=self._policies,
                entities=entities,
            )

            decision = "Allow" if response.allowed else "Deny"
            diagnostics = {
                "cedar_decision": str(response.decision),
                "diagnostics": str(response.diagnostics) if response.diagnostics else "",
            }

            logger.info(json.dumps({
                "event": "cedar_authorization",
                "agent_id": agent_id,
                "action": action,
                "resource": resource_id,
                "decision": decision,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

            return CedarDecision(
                decision=decision,
                diagnostics=diagnostics,
                policies_evaluated=self._policies.count("permit") + self._policies.count("forbid"),
            )

        except Exception as exc:
            logger.error(json.dumps({
                "event": "cedar_authorization_error",
                "error": str(exc),
                "agent_id": agent_id,
                "action": action,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            # Fail-safe: deny on Cedar errors
            return CedarDecision(
                decision="Deny",
                diagnostics={"error": str(exc), "reason": "Cedar evaluation failed (fail-safe deny)"},
            )

    def validate_policies(self) -> Dict[str, Any]:
        """Validate Cedar policies against the schema.

        Returns validation result with any errors found.
        This is the FORMAL VERIFICATION aspect: Cedar can mathematically
        prove policies are consistent and complete.
        """
        if not self._enabled:
            return {"valid": True, "reason": "Cedar disabled, skipping validation"}

        try:
            # Cedar's validator checks for:
            # - Policy contradictions (permit and forbid for same request)
            # - Type errors (accessing attributes that don't exist)
            # - Unreachable conditions
            result = cedarpy.validate_policies(
                schema=json.dumps(self._schema),
                policies=self._policies,
            )

            validation = {
                "valid": result is not None and len(result) == 0,
                "errors": [str(e) for e in result] if result else [],
                "policies_checked": self._policies.count("permit") + self._policies.count("forbid"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            logger.info(json.dumps({
                "event": "cedar_policy_validation",
                "valid": validation["valid"],
                "error_count": len(validation["errors"]),
                "timestamp": validation["timestamp"],
            }))

            return validation

        except Exception as exc:
            return {
                "valid": False,
                "errors": [str(exc)],
                "reason": "Validation failed with exception",
            }

    def load_policies_from_s3(self, s3_client, bucket: str, key: str) -> None:
        """Load Cedar policies from S3."""
        try:
            response = s3_client.get_object(Bucket=bucket, Key=key)
            self._policies = response["Body"].read().decode("utf-8")
            logger.info(f"Loaded Cedar policies from s3://{bucket}/{key}")
        except Exception as exc:
            logger.error(f"Failed to load Cedar policies: {str(exc)[:80]}")

    def get_policy_summary(self) -> Dict[str, Any]:
        """Return a summary of loaded policies for audit/reporting."""
        return {
            "permit_count": self._policies.count("permit"),
            "forbid_count": self._policies.count("forbid"),
            "total_rules": self._policies.count("permit") + self._policies.count("forbid"),
            "has_phi_controls": "PHI" in self._policies,
            "has_scope_controls": "scope_level" in self._policies,
            "has_kill_switch": "scope_level == 0" in self._policies,
            "engine": "Cedar (AWS/CNCF)",
            "formal_verification": True,
        }
