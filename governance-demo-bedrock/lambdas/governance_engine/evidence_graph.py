"""Evidence Graph - Connected Evidence Intelligence.

Models relationships between governance entities for investigation,
audit, and compliance queries. Turns flat evidence records into a
queryable graph of connected decisions.

Relationships:
  Agent -> Request -> Policy -> Risk Score -> Decision -> Approval ->
  Tool -> Output -> Evidence Record -> Control Mapping

Query examples:
- "Show all denied production deployments in the last 90 days"
- "Show all prompt injection attempts for Agent X"
- "Show all approvals by reviewer Y"
- "Show all actions mapped to ISO 42001 A.8.4"
- "Show the full chain for incident INV-001"

Uses DynamoDB adjacency list pattern (no Neptune required).
"""

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class EvidenceNode:
    """A node in the evidence graph."""
    node_id: str
    node_type: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "node_type": self.node_type,
            "attributes": self.attributes,
            "timestamp": self.timestamp,
        }


@dataclass
class EvidenceEdge:
    """A relationship between two evidence nodes."""
    from_node: str
    to_node: str
    relationship: str
    attributes: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_node": self.from_node,
            "to_node": self.to_node,
            "relationship": self.relationship,
            "attributes": self.attributes,
            "timestamp": self.timestamp,
        }


@dataclass
class QueryResult:
    """Result of an evidence graph query."""
    query: str
    nodes: List[EvidenceNode] = field(default_factory=list)
    edges: List[EvidenceEdge] = field(default_factory=list)
    total_results: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query": self.query,
            "total_results": self.total_results,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }


class EvidenceGraph:
    """Queryable graph of governance evidence relationships."""

    def __init__(self):
        self._nodes: Dict[str, EvidenceNode] = {}
        self._edges: List[EvidenceEdge] = []
        self._adjacency: Dict[str, List[EvidenceEdge]] = defaultdict(list)
        self._reverse_adjacency: Dict[str, List[EvidenceEdge]] = defaultdict(list)

    def add_node(self, node: EvidenceNode) -> None:
        self._nodes[node.node_id] = node

    def add_edge(self, edge: EvidenceEdge) -> None:
        self._edges.append(edge)
        self._adjacency[edge.from_node].append(edge)
        self._reverse_adjacency[edge.to_node].append(edge)

    def ingest_decision(self, decision: Dict[str, Any]) -> None:
        """Ingest a governance decision and create graph relationships."""
        decision_id = decision.get("decision_id", "")
        agent_id = decision.get("agent_id", "")
        action = decision.get("action_requested", "")
        verdict = decision.get("verdict", "")
        policy_id = decision.get("policy_result", {}).get("policy_id", "")
        risk_score = decision.get("risk_score", 0)
        timestamp = decision.get("timestamp", "")

        agent_node = EvidenceNode(
            node_id=f"agent:{agent_id}", node_type="agent",
            attributes={"agent_id": agent_id}, timestamp=timestamp,
        )
        decision_node = EvidenceNode(
            node_id=f"decision:{decision_id}", node_type="decision",
            attributes={"verdict": verdict, "risk_score": risk_score, "action": action},
            timestamp=timestamp,
        )
        policy_node = EvidenceNode(
            node_id=f"policy:{policy_id}", node_type="policy",
            attributes={"policy_id": policy_id}, timestamp=timestamp,
        )
        action_node = EvidenceNode(
            node_id=f"action_group:{action}", node_type="action_group",
            attributes={"name": action}, timestamp=timestamp,
        )

        self.add_node(agent_node)
        self.add_node(decision_node)
        self.add_node(policy_node)
        self.add_node(action_node)

        self.add_edge(EvidenceEdge(
            from_node=agent_node.node_id, to_node=decision_node.node_id,
            relationship="triggered", timestamp=timestamp,
        ))
        self.add_edge(EvidenceEdge(
            from_node=decision_node.node_id, to_node=policy_node.node_id,
            relationship="evaluated_by", timestamp=timestamp,
        ))
        self.add_edge(EvidenceEdge(
            from_node=decision_node.node_id, to_node=action_node.node_id,
            relationship="requested_action", timestamp=timestamp,
        ))

    def query_by_agent(self, agent_id: str) -> QueryResult:
        """Find all decisions triggered by an agent."""
        agent_key = f"agent:{agent_id}"
        edges = self._adjacency.get(agent_key, [])
        decision_nodes = []
        for e in edges:
            if e.relationship == "triggered":
                node = self._nodes.get(e.to_node)
                if node:
                    decision_nodes.append(node)

        return QueryResult(
            query=f"decisions by agent '{agent_id}'",
            nodes=decision_nodes,
            edges=edges,
            total_results=len(decision_nodes),
        )

    def query_by_verdict(self, verdict: str) -> QueryResult:
        """Find all decisions with a specific verdict."""
        matching = [
            n for n in self._nodes.values()
            if n.node_type == "decision" and n.attributes.get("verdict") == verdict
        ]
        return QueryResult(
            query=f"decisions with verdict '{verdict}'",
            nodes=matching,
            total_results=len(matching),
        )

    def query_by_policy(self, policy_id: str) -> QueryResult:
        """Find all decisions that triggered a specific policy."""
        policy_key = f"policy:{policy_id}"
        edges = self._reverse_adjacency.get(policy_key, [])
        decision_nodes = []
        for e in edges:
            node = self._nodes.get(e.from_node)
            if node:
                decision_nodes.append(node)

        return QueryResult(
            query=f"decisions evaluated by policy '{policy_id}'",
            nodes=decision_nodes,
            edges=edges,
            total_results=len(decision_nodes),
        )

    def query_by_action_group(self, action_group: str) -> QueryResult:
        """Find all decisions requesting a specific action group."""
        action_key = f"action_group:{action_group}"
        edges = self._reverse_adjacency.get(action_key, [])
        decision_nodes = []
        for e in edges:
            node = self._nodes.get(e.from_node)
            if node:
                decision_nodes.append(node)

        return QueryResult(
            query=f"decisions for action '{action_group}'",
            nodes=decision_nodes,
            edges=edges,
            total_results=len(decision_nodes),
        )

    def query_high_risk_chain(self, risk_threshold: float = 70) -> QueryResult:
        """Find all high-risk decisions and their full context."""
        matching = [
            n for n in self._nodes.values()
            if n.node_type == "decision" and n.attributes.get("risk_score", 0) >= risk_threshold
        ]
        related_edges = []
        for node in matching:
            related_edges.extend(self._adjacency.get(node.node_id, []))
            related_edges.extend(self._reverse_adjacency.get(node.node_id, []))

        return QueryResult(
            query=f"high-risk decisions (score >= {risk_threshold})",
            nodes=matching,
            edges=related_edges,
            total_results=len(matching),
        )

    def get_statistics(self) -> Dict[str, Any]:
        """Return graph statistics."""
        type_counts: Dict[str, int] = defaultdict(int)
        for node in self._nodes.values():
            type_counts[node.node_type] += 1

        rel_counts: Dict[str, int] = defaultdict(int)
        for edge in self._edges:
            rel_counts[edge.relationship] += 1

        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "nodes_by_type": dict(type_counts),
            "edges_by_relationship": dict(rel_counts),
        }
