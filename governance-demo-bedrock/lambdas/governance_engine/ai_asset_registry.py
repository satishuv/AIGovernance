"""Unified AI Asset Registry.

Single inventory of ALL AI assets in the enterprise. Every asset type
is tracked with ownership, risk classification, approval status, and
lifecycle state.

Asset types:
- agent: Autonomous AI agents (Bedrock Agents, LangGraph, CrewAI, etc.)
- model: Foundation models and fine-tuned variants
- tool: Tools/plugins/action groups agents can invoke
- mcp_server: Model Context Protocol servers
- prompt: Prompt templates and prompt libraries
- dataset: Training data, evaluation data, fine-tuning data
- knowledge_base: RAG knowledge bases and vector stores
- vector_store: Embedding stores (OpenSearch, Pinecone, etc.)
- guardrail: Content safety guardrails and filters
- policy: Governance policies (OPA, Cedar)

Every asset requires:
- Registered owner (accountable human)
- Risk classification (low/medium/high/critical)
- Approval status (draft/pending/approved/revoked)
- Data classes it accesses or contains
- Allowed consumers (which agents/users can use it)
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

ASSET_TYPES = [
    "agent",
    "model",
    "tool",
    "mcp_server",
    "prompt",
    "dataset",
    "knowledge_base",
    "vector_store",
    "guardrail",
    "policy",
]

RISK_TIERS = ["low", "medium", "high", "critical"]

APPROVAL_STATES = ["draft", "pending_review", "approved", "revoked", "retired"]


@dataclass
class AIAsset:
    """A registered AI asset in the enterprise inventory."""
    asset_id: str
    asset_type: str
    name: str
    description: str = ""
    owner: str = ""
    business_unit: str = ""
    risk_tier: str = "medium"
    approval_status: str = "draft"
    approved_by: str = ""
    approved_at: str = ""
    data_classes: List[str] = field(default_factory=list)
    allowed_consumers: List[str] = field(default_factory=list)
    environment: str = "dev"
    version: str = "1.0"
    source_url: str = ""
    hash_digest: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    created_at: str = ""
    updated_at: str = ""
    last_reviewed: str = ""
    review_due_at: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "name": self.name,
            "description": self.description,
            "owner": self.owner,
            "business_unit": self.business_unit,
            "risk_tier": self.risk_tier,
            "approval_status": self.approval_status,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "data_classes": self.data_classes,
            "allowed_consumers": self.allowed_consumers,
            "environment": self.environment,
            "version": self.version,
            "source_url": self.source_url,
            "hash_digest": self.hash_digest,
            "tags": self.tags,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "last_reviewed": self.last_reviewed,
            "review_due_at": self.review_due_at,
            "metadata": self.metadata,
        }


@dataclass
class RegistryQuery:
    """Query parameters for searching the registry."""
    asset_type: Optional[str] = None
    owner: Optional[str] = None
    risk_tier: Optional[str] = None
    approval_status: Optional[str] = None
    environment: Optional[str] = None
    business_unit: Optional[str] = None
    data_class: Optional[str] = None
    tag_key: Optional[str] = None
    tag_value: Optional[str] = None


class AIAssetRegistry:
    """Unified registry for all AI assets in the enterprise."""

    def __init__(self):
        self._assets: Dict[str, AIAsset] = {}

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def register(self, asset: AIAsset) -> AIAsset:
        """Register a new AI asset (starts in 'draft' status)."""
        if asset.asset_type not in ASSET_TYPES:
            raise ValueError(f"Invalid asset_type '{asset.asset_type}'. Valid: {ASSET_TYPES}")
        if not asset.owner:
            raise ValueError("Every AI asset must have a registered owner")

        asset.created_at = self._now()
        asset.updated_at = self._now()
        asset.approval_status = "draft"
        self._assets[asset.asset_id] = asset

        logger.info(json.dumps({
            "event": "ai_asset_registered",
            "asset_id": asset.asset_id,
            "asset_type": asset.asset_type,
            "name": asset.name,
            "owner": asset.owner,
            "risk_tier": asset.risk_tier,
        }))
        return asset

    def get(self, asset_id: str) -> Optional[AIAsset]:
        """Get an asset by ID."""
        return self._assets.get(asset_id)

    def update(self, asset_id: str, updates: Dict[str, Any]) -> Optional[AIAsset]:
        """Update asset fields (triggers change management if approved)."""
        asset = self._assets.get(asset_id)
        if asset is None:
            return None

        for key, value in updates.items():
            if hasattr(asset, key) and key not in ("asset_id", "created_at"):
                setattr(asset, key, value)

        asset.updated_at = self._now()

        logger.info(json.dumps({
            "event": "ai_asset_updated",
            "asset_id": asset_id,
            "fields_changed": list(updates.keys()),
        }))
        return asset

    def revoke(self, asset_id: str, revoked_by: str, reason: str) -> Optional[AIAsset]:
        """Revoke an asset (prevents further use)."""
        asset = self._assets.get(asset_id)
        if asset is None:
            return None

        asset.approval_status = "revoked"
        asset.updated_at = self._now()
        asset.metadata["revoked_by"] = revoked_by
        asset.metadata["revocation_reason"] = reason
        asset.metadata["revoked_at"] = self._now()

        logger.warning(json.dumps({
            "event": "ai_asset_revoked",
            "asset_id": asset_id,
            "revoked_by": revoked_by,
            "reason": reason,
        }))
        return asset

    def query(self, q: RegistryQuery) -> List[AIAsset]:
        """Search the registry with filters."""
        results = list(self._assets.values())

        if q.asset_type:
            results = [a for a in results if a.asset_type == q.asset_type]
        if q.owner:
            results = [a for a in results if a.owner == q.owner]
        if q.risk_tier:
            results = [a for a in results if a.risk_tier == q.risk_tier]
        if q.approval_status:
            results = [a for a in results if a.approval_status == q.approval_status]
        if q.environment:
            results = [a for a in results if a.environment == q.environment]
        if q.business_unit:
            results = [a for a in results if a.business_unit == q.business_unit]
        if q.data_class:
            results = [a for a in results if q.data_class in a.data_classes]
        if q.tag_key:
            if q.tag_value:
                results = [a for a in results if a.tags.get(q.tag_key) == q.tag_value]
            else:
                results = [a for a in results if q.tag_key in a.tags]

        return results

    def get_inventory_summary(self) -> Dict[str, Any]:
        """Get a summary of all assets by type, risk, and status."""
        assets = list(self._assets.values())
        return {
            "total_assets": len(assets),
            "by_type": self._count_by(assets, "asset_type"),
            "by_risk": self._count_by(assets, "risk_tier"),
            "by_status": self._count_by(assets, "approval_status"),
            "by_environment": self._count_by(assets, "environment"),
            "by_owner": self._count_by(assets, "owner"),
            "unowned": sum(1 for a in assets if not a.owner),
            "overdue_review": sum(1 for a in assets if a.review_due_at and a.review_due_at < self._now()[:10]),
        }

    def check_access(self, asset_id: str, consumer_id: str) -> bool:
        """Check if a consumer (agent/user) is allowed to use this asset."""
        asset = self._assets.get(asset_id)
        if asset is None:
            return False
        if asset.approval_status != "approved":
            return False
        if not asset.allowed_consumers:
            return True
        return consumer_id in asset.allowed_consumers

    @staticmethod
    def _count_by(assets: List[AIAsset], field: str) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for a in assets:
            val = getattr(a, field, "unknown")
            counts[val] = counts.get(val, 0) + 1
        return counts

    def load_from_table(self, table) -> None:
        """Load assets from DynamoDB."""
        try:
            response = table.scan()
            for item in response.get("Items", []):
                asset = AIAsset(
                    asset_id=item["asset_id"],
                    asset_type=item.get("asset_type", "unknown"),
                    name=item.get("name", ""),
                    description=item.get("description", ""),
                    owner=item.get("owner", ""),
                    business_unit=item.get("business_unit", ""),
                    risk_tier=item.get("risk_tier", "medium"),
                    approval_status=item.get("approval_status", "draft"),
                    data_classes=item.get("data_classes", []),
                    allowed_consumers=item.get("allowed_consumers", []),
                    environment=item.get("environment", "dev"),
                    version=item.get("version", "1.0"),
                )
                self._assets[asset.asset_id] = asset
        except Exception as e:
            logger.error(json.dumps({
                "event": "ai_asset_registry_load_failed",
                "error": str(e),
            }))
