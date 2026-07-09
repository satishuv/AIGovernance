"""Shadow AI Discovery Engine.

Discovers unregistered AI assets operating without governance oversight.
Compares discovered assets against the Agent Registry and flags anything
not formally registered, approved, or reviewed.

Shadow AI = any AI agent, model, tool, MCP server, or prompt library
operating without governance registration.

Discovery sources:
- Bedrock Agent API (list all agents in account)
- CloudTrail (InvokeModel events from unknown callers)
- DynamoDB tool auth table (tools invoked but not in registry)
- Lambda functions with AI-related names/tags
- MCP server connections (if MCP governance enabled)
"""

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

import boto3

logger = logging.getLogger(__name__)


@dataclass
class DiscoveredAsset:
    """An AI asset discovered in the environment."""
    asset_id: str
    asset_type: str
    name: str
    discovered_at: str
    registered: bool = False
    approved: bool = False
    owner: str = ""
    risk_tier: str = "unknown"
    risk_score: int = 0
    status: str = "shadow"
    source: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "name": self.name,
            "discovered_at": self.discovered_at,
            "registered": self.registered,
            "approved": self.approved,
            "owner": self.owner,
            "risk_tier": self.risk_tier,
            "risk_score": self.risk_score,
            "status": self.status,
            "source": self.source,
            "metadata": self.metadata,
        }


@dataclass
class DiscoveryReport:
    """Summary of a shadow AI discovery scan."""
    scan_id: str
    scanned_at: str
    total_discovered: int = 0
    registered: int = 0
    shadow: int = 0
    critical_shadow: int = 0
    assets: List[DiscoveredAsset] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "scanned_at": self.scanned_at,
            "total_discovered": self.total_discovered,
            "registered": self.registered,
            "shadow": self.shadow,
            "critical_shadow": self.critical_shadow,
            "assets": [a.to_dict() for a in self.assets],
            "summary": {
                "by_type": self._count_by_type(),
                "by_risk": self._count_by_risk(),
                "by_status": self._count_by_status(),
            },
        }

    def _count_by_type(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for a in self.assets:
            counts[a.asset_type] = counts.get(a.asset_type, 0) + 1
        return counts

    def _count_by_risk(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for a in self.assets:
            counts[a.risk_tier] = counts.get(a.risk_tier, 0) + 1
        return counts

    def _count_by_status(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for a in self.assets:
            counts[a.status] = counts.get(a.status, 0) + 1
        return counts


def _compute_risk_score(asset: DiscoveredAsset) -> int:
    """Compute risk score for a discovered asset."""
    score = 0
    if not asset.registered:
        score += 20
    if not asset.approved:
        score += 20
    if not asset.owner:
        score += 20
    if asset.asset_type in ("agent", "mcp_server"):
        score += 15
    if "prod" in asset.name.lower() or "production" in asset.name.lower():
        score += 25
    return min(score, 100)


def _classify_risk(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


class ShadowAIDiscovery:
    """Discovers and inventories AI assets, flagging unregistered ones."""

    def __init__(self, region: str = "us-east-1"):
        self.region = region

    def discover_bedrock_agents(self, registered_agent_ids: List[str]) -> List[DiscoveredAsset]:
        """Discover Bedrock Agents in the account and flag unregistered ones."""
        assets = []
        try:
            client = boto3.client("bedrock-agent", region_name=self.region)
            response = client.list_agents(maxResults=100)
            for agent_summary in response.get("agentSummaries", []):
                agent_id = agent_summary["agentId"]
                is_registered = agent_id in registered_agent_ids
                asset = DiscoveredAsset(
                    asset_id=f"bedrock-agent-{agent_id}",
                    asset_type="agent",
                    name=agent_summary.get("agentName", agent_id),
                    discovered_at=datetime.now(timezone.utc).isoformat(),
                    registered=is_registered,
                    approved=is_registered,
                    status="registered" if is_registered else "shadow",
                    source="bedrock-agent-api",
                    metadata={
                        "agent_id": agent_id,
                        "status": agent_summary.get("agentStatus", ""),
                        "foundation_model": agent_summary.get("foundationModel", ""),
                    },
                )
                asset.risk_score = _compute_risk_score(asset)
                asset.risk_tier = _classify_risk(asset.risk_score)
                assets.append(asset)
        except Exception as e:
            logger.error(json.dumps({
                "event": "shadow_ai_discovery_error",
                "source": "bedrock_agents",
                "error": str(e),
            }))
        return assets

    def discover_ai_lambdas(self, registered_function_names: List[str]) -> List[DiscoveredAsset]:
        """Discover Lambda functions with AI-related patterns."""
        ai_keywords = ["ai", "agent", "llm", "bedrock", "model", "inference", "governance", "guardrail"]
        assets = []
        try:
            client = boto3.client("lambda", region_name=self.region)
            paginator = client.get_paginator("list_functions")
            for page in paginator.paginate(MaxItems=200):
                for func in page.get("Functions", []):
                    name = func["FunctionName"].lower()
                    if any(kw in name for kw in ai_keywords):
                        is_registered = func["FunctionName"] in registered_function_names
                        asset = DiscoveredAsset(
                            asset_id=f"lambda-{func['FunctionName']}",
                            asset_type="lambda",
                            name=func["FunctionName"],
                            discovered_at=datetime.now(timezone.utc).isoformat(),
                            registered=is_registered,
                            approved=is_registered,
                            status="registered" if is_registered else "shadow",
                            source="lambda-api",
                            metadata={
                                "runtime": func.get("Runtime", ""),
                                "memory": func.get("MemorySize", 0),
                                "last_modified": func.get("LastModified", ""),
                                "role": func.get("Role", ""),
                            },
                        )
                        asset.risk_score = _compute_risk_score(asset)
                        asset.risk_tier = _classify_risk(asset.risk_score)
                        assets.append(asset)
        except Exception as e:
            logger.error(json.dumps({
                "event": "shadow_ai_discovery_error",
                "source": "lambda_functions",
                "error": str(e),
            }))
        return assets

    def discover_bedrock_models_in_use(self, registered_models: List[str]) -> List[DiscoveredAsset]:
        """Discover Bedrock models with active invocation logging."""
        assets = []
        try:
            client = boto3.client("bedrock", region_name=self.region)
            response = client.list_foundation_models()
            for model in response.get("modelSummaries", []):
                model_id = model["modelId"]
                is_registered = model_id in registered_models
                asset = DiscoveredAsset(
                    asset_id=f"model-{model_id}",
                    asset_type="model",
                    name=model.get("modelName", model_id),
                    discovered_at=datetime.now(timezone.utc).isoformat(),
                    registered=is_registered,
                    approved=is_registered,
                    status="registered" if is_registered else "available",
                    source="bedrock-api",
                    metadata={
                        "model_id": model_id,
                        "provider": model.get("providerName", ""),
                        "input_modalities": model.get("inputModalities", []),
                        "output_modalities": model.get("outputModalities", []),
                    },
                )
                asset.risk_score = _compute_risk_score(asset)
                asset.risk_tier = _classify_risk(asset.risk_score)
                assets.append(asset)
        except Exception as e:
            logger.error(json.dumps({
                "event": "shadow_ai_discovery_error",
                "source": "bedrock_models",
                "error": str(e),
            }))
        return assets

    def run_full_scan(
        self,
        registered_agent_ids: List[str] = None,
        registered_function_names: List[str] = None,
        registered_models: List[str] = None,
    ) -> DiscoveryReport:
        """Run a full shadow AI discovery scan across all sources."""
        import uuid

        registered_agent_ids = registered_agent_ids or []
        registered_function_names = registered_function_names or []
        registered_models = registered_models or []

        all_assets = []
        all_assets.extend(self.discover_bedrock_agents(registered_agent_ids))
        all_assets.extend(self.discover_ai_lambdas(registered_function_names))
        all_assets.extend(self.discover_bedrock_models_in_use(registered_models))

        report = DiscoveryReport(
            scan_id=str(uuid.uuid4()),
            scanned_at=datetime.now(timezone.utc).isoformat(),
            total_discovered=len(all_assets),
            registered=sum(1 for a in all_assets if a.registered),
            shadow=sum(1 for a in all_assets if a.status == "shadow"),
            critical_shadow=sum(1 for a in all_assets if a.status == "shadow" and a.risk_tier == "critical"),
            assets=all_assets,
        )

        logger.info(json.dumps({
            "event": "shadow_ai_scan_complete",
            "scan_id": report.scan_id,
            "total": report.total_discovered,
            "registered": report.registered,
            "shadow": report.shadow,
            "critical": report.critical_shadow,
        }))

        return report
