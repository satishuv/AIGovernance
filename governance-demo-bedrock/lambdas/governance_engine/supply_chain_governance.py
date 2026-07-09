"""AI Supply Chain Governance.

Governs the external dependencies AI agents rely on: MCP servers, tools,
models, plugins, prompt libraries, and knowledge sources. Prevents
unreviewed components from expanding agent capabilities.

Addresses:
- MCPTox (arXiv:2508.14925): Tool poisoning via metadata - 72.8% success
- ClawWorm (arXiv:2603.15727): Self-replicating worms in skill marketplaces
- ShareLock (arXiv:2606.27027): Multi-tool threshold poisoning
- OpenClaw (Unit 42, 2026): 341 malicious skills, 17% payload rate
- Amazon Q MCP vulnerability (Wiz, June 2026): Auto-loaded poisoned MCP
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SupplyChainComponent:
    """A registered AI supply chain component."""
    component_id: str
    component_type: str
    name: str
    version: str = ""
    owner: str = ""
    approved: bool = False
    risk_tier: str = "unknown"
    allowed_agents: List[str] = field(default_factory=list)
    last_security_review: str = ""
    review_expiry: str = ""
    hash_digest: str = ""
    source_url: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component_id": self.component_id,
            "component_type": self.component_type,
            "name": self.name,
            "version": self.version,
            "owner": self.owner,
            "approved": self.approved,
            "risk_tier": self.risk_tier,
            "allowed_agents": self.allowed_agents,
            "last_security_review": self.last_security_review,
            "review_expiry": self.review_expiry,
            "hash_digest": self.hash_digest,
            "source_url": self.source_url,
        }


@dataclass
class SupplyChainValidation:
    """Result of validating a supply chain component."""
    component_id: str
    component_type: str
    approved: bool = False
    denial_reason: str = ""
    risk_tier: str = "unknown"
    checks_passed: List[str] = field(default_factory=list)
    checks_failed: List[str] = field(default_factory=list)
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component_id": self.component_id,
            "component_type": self.component_type,
            "approved": self.approved,
            "denial_reason": self.denial_reason,
            "risk_tier": self.risk_tier,
            "checks_passed": self.checks_passed,
            "checks_failed": self.checks_failed,
            "timestamp": self.timestamp,
        }


COMPONENT_TYPES = [
    "mcp_server",
    "tool",
    "model",
    "plugin",
    "prompt_library",
    "knowledge_base",
    "vector_store",
    "dataset",
    "api_endpoint",
]


class SupplyChainGovernance:
    """Validates and governs AI supply chain components."""

    def __init__(self):
        self._registry: Dict[str, SupplyChainComponent] = {}

    def register_component(self, component: SupplyChainComponent) -> None:
        """Register a component in the supply chain registry."""
        self._registry[component.component_id] = component
        logger.info(json.dumps({
            "event": "supply_chain_component_registered",
            "component_id": component.component_id,
            "type": component.component_type,
            "name": component.name,
            "approved": component.approved,
        }))

    def load_registry(self, table) -> None:
        """Load supply chain registry from DynamoDB."""
        try:
            response = table.scan()
            for item in response.get("Items", []):
                comp = SupplyChainComponent(
                    component_id=item["component_id"],
                    component_type=item.get("component_type", "unknown"),
                    name=item.get("name", ""),
                    version=item.get("version", ""),
                    owner=item.get("owner", ""),
                    approved=item.get("approved", False),
                    risk_tier=item.get("risk_tier", "unknown"),
                    allowed_agents=item.get("allowed_agents", []),
                    last_security_review=item.get("last_security_review", ""),
                    review_expiry=item.get("review_expiry", ""),
                    hash_digest=item.get("hash_digest", ""),
                    source_url=item.get("source_url", ""),
                )
                self._registry[comp.component_id] = comp
        except Exception as e:
            logger.error(json.dumps({
                "event": "supply_chain_registry_load_failed",
                "error": str(e),
            }))

    def validate_component(
        self, component_id: str, agent_id: str, component_type: str = ""
    ) -> SupplyChainValidation:
        """Validate whether an agent can use a supply chain component."""
        now = datetime.now(timezone.utc).isoformat()

        component = self._registry.get(component_id)
        if component is None:
            return SupplyChainValidation(
                component_id=component_id,
                component_type=component_type,
                approved=False,
                denial_reason=f"Component '{component_id}' not found in supply chain registry (unregistered)",
                risk_tier="critical",
                checks_failed=["registry_lookup"],
                timestamp=now,
            )

        checks_passed = []
        checks_failed = []

        # Check 1: Component is approved
        if component.approved:
            checks_passed.append("approved")
        else:
            checks_failed.append("not_approved")

        # Check 2: Agent is in allowed list
        if not component.allowed_agents or agent_id in component.allowed_agents:
            checks_passed.append("agent_allowed")
        else:
            checks_failed.append("agent_not_in_allowlist")

        # Check 3: Security review is current
        if component.review_expiry:
            if component.review_expiry >= now[:10]:
                checks_passed.append("review_current")
            else:
                checks_failed.append("review_expired")
        elif component.last_security_review:
            checks_passed.append("has_review_record")
        else:
            checks_failed.append("never_reviewed")

        # Check 4: Hash integrity (if hash provided)
        if component.hash_digest:
            checks_passed.append("hash_present")
        else:
            checks_failed.append("no_integrity_hash")

        # Check 5: Owner assigned
        if component.owner:
            checks_passed.append("owner_assigned")
        else:
            checks_failed.append("no_owner")

        approved = len(checks_failed) == 0
        denial_reason = ""
        if not approved:
            denial_reason = f"Supply chain validation failed: {', '.join(checks_failed)}"

        result = SupplyChainValidation(
            component_id=component_id,
            component_type=component.component_type,
            approved=approved,
            denial_reason=denial_reason,
            risk_tier=component.risk_tier,
            checks_passed=checks_passed,
            checks_failed=checks_failed,
            timestamp=now,
        )

        if not approved:
            logger.warning(json.dumps({
                "event": "supply_chain_validation_failed",
                "component_id": component_id,
                "agent_id": agent_id,
                "checks_failed": checks_failed,
                "risk_tier": component.risk_tier,
            }))

        return result

    def validate_mcp_server(self, server_name: str, agent_id: str) -> SupplyChainValidation:
        """Validate an MCP server before allowing agent connection."""
        component_id = f"mcp-{server_name}"
        return self.validate_component(component_id, agent_id, "mcp_server")

    def validate_tool(self, tool_name: str, agent_id: str) -> SupplyChainValidation:
        """Validate a tool/plugin before agent can invoke it."""
        component_id = f"tool-{tool_name}"
        return self.validate_component(component_id, agent_id, "tool")

    def validate_model(self, model_id: str, agent_id: str) -> SupplyChainValidation:
        """Validate a model before agent can invoke it."""
        component_id = f"model-{model_id}"
        return self.validate_component(component_id, agent_id, "model")

    def get_inventory(self) -> Dict[str, Any]:
        """Return full supply chain inventory with risk summary."""
        components = list(self._registry.values())
        return {
            "total_components": len(components),
            "approved": sum(1 for c in components if c.approved),
            "unapproved": sum(1 for c in components if not c.approved),
            "by_type": self._count_by_field(components, "component_type"),
            "by_risk": self._count_by_field(components, "risk_tier"),
            "components": [c.to_dict() for c in components],
        }

    @staticmethod
    def _count_by_field(components: List[SupplyChainComponent], field_name: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for c in components:
            val = getattr(c, field_name, "unknown")
            counts[val] = counts.get(val, 0) + 1
        return counts
