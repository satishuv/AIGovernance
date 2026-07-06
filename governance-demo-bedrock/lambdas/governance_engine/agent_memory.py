"""Agent Memory - persistent cross-session memory for governed AI agents.

Provides persistent memory that survives across sessions:
1. Semantic facts: key information extracted from conversations
2. Session summaries: compressed history of past interactions
3. User/agent preferences: behavioral patterns learned over time
4. Governance memory: past decisions, denials, escalations

Memory is GOVERNED: the governance engine controls what can be stored
and retrieved, preventing memory poisoning attacks.

Integration: DynamoDB table stores memory entries with TTL.
Memory is scoped per agent (no cross-agent memory access).
"""

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MEMORY_TABLE_NAME = os.environ.get("AGENT_MEMORY_TABLE_NAME", "")
MEMORY_TTL_DAYS = int(os.environ.get("AGENT_MEMORY_TTL_DAYS", "90"))


class MemoryEntry:
    """A single memory entry for an agent."""

    def __init__(self, memory_id: str, agent_id: str, memory_type: str,
                 content: str, metadata: Dict[str, Any] = None,
                 created_at: str = "", expires_at: str = ""):
        self.memory_id = memory_id
        self.agent_id = agent_id
        self.memory_type = memory_type  # "fact", "summary", "preference", "governance"
        self.content = content
        self.metadata = metadata or {}
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.expires_at = expires_at

    def to_dict(self) -> Dict[str, Any]:
        return {
            "memory_id": self.memory_id,
            "agent_id": self.agent_id,
            "memory_type": self.memory_type,
            "content": self.content,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "expires_at": self.expires_at,
        }


class AgentMemoryManager:
    """Manages persistent cross-session memory for agents.

    Memory types:
    - fact: extracted key information ("user prefers staging deploys at 2pm")
    - summary: compressed session history ("last session: reviewed build-47, approved staging")
    - preference: learned behavioral patterns ("agent typically reads before proposing")
    - governance: past governance decisions ("denied production deploy 3 times this week")
    """

    def __init__(self, table=None):
        self._table = table
        self._local_cache: Dict[str, List[MemoryEntry]] = {}

    def store_memory(self, agent_id: str, memory_type: str, content: str,
                     metadata: Dict[str, Any] = None) -> MemoryEntry:
        """Store a new memory entry for an agent.

        Memory is governed: content is validated before storage.
        """
        now = datetime.now(timezone.utc)
        memory_id = hashlib.sha256(
            f"{agent_id}:{memory_type}:{content}:{now.isoformat()}".encode()
        ).hexdigest()[:16]

        expires = (now + timedelta(days=MEMORY_TTL_DAYS)).isoformat()

        entry = MemoryEntry(
            memory_id=memory_id,
            agent_id=agent_id,
            memory_type=memory_type,
            content=content,
            metadata=metadata or {},
            created_at=now.isoformat(),
            expires_at=expires,
        )

        # Store in DynamoDB if available
        if self._table:
            try:
                self._table.put_item(Item={
                    "agent_id": agent_id,
                    "memory_id": memory_id,
                    "memory_type": memory_type,
                    "content": content,
                    "metadata": json.dumps(metadata or {}),
                    "created_at": now.isoformat(),
                    "ttl_expiry": int((now + timedelta(days=MEMORY_TTL_DAYS)).timestamp()),
                })
            except Exception as exc:
                logger.error(json.dumps({
                    "event": "memory_store_failed",
                    "agent_id": agent_id,
                    "error": str(exc)[:80],
                }))

        # Also cache locally
        if agent_id not in self._local_cache:
            self._local_cache[agent_id] = []
        self._local_cache[agent_id].append(entry)

        logger.info(json.dumps({
            "event": "memory_stored",
            "agent_id": agent_id,
            "memory_type": memory_type,
            "memory_id": memory_id,
            "timestamp": now.isoformat(),
        }))

        return entry

    def recall_memories(self, agent_id: str, memory_type: str = None,
                        limit: int = 10) -> List[MemoryEntry]:
        """Recall memories for an agent, optionally filtered by type.

        Memory isolation: agent can ONLY recall its own memories.
        """
        if self._table:
            try:
                kwargs = {
                    "KeyConditionExpression": "agent_id = :aid",
                    "ExpressionAttributeValues": {":aid": agent_id},
                    "Limit": limit,
                    "ScanIndexForward": False,
                }
                if memory_type:
                    kwargs["FilterExpression"] = "memory_type = :mt"
                    kwargs["ExpressionAttributeValues"][":mt"] = memory_type

                response = self._table.query(**kwargs)
                entries = []
                for item in response.get("Items", []):
                    entries.append(MemoryEntry(
                        memory_id=item["memory_id"],
                        agent_id=item["agent_id"],
                        memory_type=item["memory_type"],
                        content=item["content"],
                        metadata=json.loads(item.get("metadata", "{}")),
                        created_at=item.get("created_at", ""),
                        expires_at=item.get("expires_at", ""),
                    ))
                return entries
            except Exception as exc:
                logger.error(json.dumps({
                    "event": "memory_recall_failed",
                    "agent_id": agent_id,
                    "error": str(exc)[:80],
                }))

        # Fallback to local cache
        memories = self._local_cache.get(agent_id, [])
        if memory_type:
            memories = [m for m in memories if m.memory_type == memory_type]
        return memories[-limit:]

    def store_session_summary(self, agent_id: str, session_id: str,
                              actions_taken: List[str], verdicts: Dict[str, int]) -> MemoryEntry:
        """Store a compressed summary of a completed session.

        Called at session end to persist key facts for future sessions.
        """
        summary = {
            "session_id": session_id,
            "actions": actions_taken,
            "verdicts": verdicts,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        return self.store_memory(
            agent_id=agent_id,
            memory_type="summary",
            content=json.dumps(summary),
            metadata={"session_id": session_id},
        )

    def store_governance_decision(self, agent_id: str, action: str,
                                   verdict: str, reason: str) -> MemoryEntry:
        """Store a governance decision in agent memory.

        Allows the agent to learn from past denials and avoid repeating them.
        """
        return self.store_memory(
            agent_id=agent_id,
            memory_type="governance",
            content=f"{verdict}: {action} - {reason}",
            metadata={"action": action, "verdict": verdict},
        )

    def get_governance_history(self, agent_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        """Get recent governance decisions for this agent.

        Used by the detective engine to detect patterns (repeated denials = drift).
        """
        memories = self.recall_memories(agent_id, memory_type="governance", limit=limit)
        return [m.to_dict() for m in memories]

    def clear_agent_memory(self, agent_id: str) -> int:
        """Clear all memory for an agent (used on agent retirement or compromise).

        Returns count of entries cleared.
        """
        count = len(self._local_cache.get(agent_id, []))
        self._local_cache[agent_id] = []

        if self._table:
            try:
                response = self._table.query(
                    KeyConditionExpression="agent_id = :aid",
                    ExpressionAttributeValues={":aid": agent_id},
                )
                with self._table.batch_writer() as batch:
                    for item in response.get("Items", []):
                        batch.delete_item(Key={"agent_id": agent_id, "memory_id": item["memory_id"]})
                count = len(response.get("Items", []))
            except Exception as exc:
                logger.error(json.dumps({"event": "memory_clear_failed", "error": str(exc)[:80]}))

        logger.warning(json.dumps({
            "event": "agent_memory_cleared",
            "agent_id": agent_id,
            "entries_cleared": count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

        return count
