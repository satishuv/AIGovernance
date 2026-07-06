"""Agent Identity and Access module.

Manages agent identity lifecycle: creation, retrieval, scope level updates,
and suspension. Uses the existing ScopeTable for storage since AgentIdentity
extends the scope concept. All mutations produce structured audit log entries.

Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 19.6, 21.1
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional

from models import AgentIdentity

logger = logging.getLogger(__name__)

VALID_ENVIRONMENTS = {"dev", "staging", "prod"}


class AgentIdentityManager:
    """Manages agent identity records in DynamoDB ScopeTable.

    Args:
        table: A boto3 DynamoDB Table resource for the ScopeTable.
    """

    def __init__(self, table):
        self._table = table

    def create_agent(
        self, agent_id: str, display_name: str, environment: str
    ) -> AgentIdentity:
        """Create a new agent identity with scope_level=1 and status='active'.

        Args:
            agent_id: Unique identifier for the agent.
            display_name: Human-readable name for the agent.
            environment: Deployment environment — must be one of 'dev', 'staging', 'prod'.

        Returns:
            The created AgentIdentity record.

        Raises:
            ValueError: If environment is not in the valid set.
        """
        if environment not in VALID_ENVIRONMENTS:
            raise ValueError(
                f"Invalid environment '{environment}'. "
                f"Must be one of {sorted(VALID_ENVIRONMENTS)}."
            )

        now = datetime.now(timezone.utc).isoformat()
        identity = AgentIdentity(
            agent_id=agent_id,
            display_name=display_name,
            scope_level=1,
            creation_timestamp=now,
            status="active",
            environment=environment,
        )

        self._table.put_item(Item=identity.to_dict())

        logger.info(
            json.dumps(
                {
                    "audit_event": "agent_created",
                    "agent_id": agent_id,
                    "display_name": display_name,
                    "scope_level": 1,
                    "status": "active",
                    "environment": environment,
                    "timestamp": now,
                }
            )
        )

        return identity

    def get_agent(self, agent_id: str) -> Optional[AgentIdentity]:
        """Retrieve an agent identity from DynamoDB.

        Args:
            agent_id: The agent's unique identifier.

        Returns:
            AgentIdentity if found, None otherwise.
        """
        response = self._table.get_item(Key={"agent_id": agent_id})
        item = response.get("Item")
        if item is None:
            return None
        return AgentIdentity.from_dict(item)

    def update_scope_level(
        self,
        agent_id: str,
        new_scope_level: int,
        requester_id: str,
        human_authorized: bool = False,
    ) -> AgentIdentity:
        """Update an agent's scope level.

        If the new scope level is >= 2, explicit human authorization is required.

        Args:
            agent_id: The agent's unique identifier.
            new_scope_level: The target scope level.
            requester_id: Identity of the person requesting the change.
            human_authorized: Whether a human has explicitly authorized this change.

        Returns:
            The updated AgentIdentity record.

        Raises:
            ValueError: If new_scope_level >= 2 and human_authorized is False,
                        or if the agent is not found.
        """
        if new_scope_level >= 2 and not human_authorized:
            raise ValueError(
                f"Scope level changes to {new_scope_level} (>= 2) require explicit "
                "human authorization (human_authorized=True)."
            )

        agent = self.get_agent(agent_id)
        if agent is None:
            raise ValueError(f"Agent '{agent_id}' not found.")

        previous_scope = agent.scope_level
        now = datetime.now(timezone.utc).isoformat()

        self._table.update_item(
            Key={"agent_id": agent_id},
            UpdateExpression="SET scope_level = :sl",
            ExpressionAttributeValues={":sl": new_scope_level},
        )

        logger.info(
            json.dumps(
                {
                    "audit_event": "scope_level_updated",
                    "agent_id": agent_id,
                    "previous_scope": previous_scope,
                    "new_scope": new_scope_level,
                    "requester_id": requester_id,
                    "human_authorized": human_authorized,
                    "timestamp": now,
                }
            )
        )

        # Phase 2: Log scope change via ChangeLogger (Req 21.1)
        change_log_table_name = os.environ.get("CHANGE_LOG_TABLE_NAME", "")
        evidence_bucket = os.environ.get(
            "IMMUTABLE_EVIDENCE_BUCKET_NAME",
            os.environ.get("EVIDENCE_BUCKET_NAME", ""),
        )
        if change_log_table_name and evidence_bucket:
            try:
                import boto3
                from change_logger import ChangeLogger

                dynamodb = boto3.resource("dynamodb")
                s3_client = boto3.client("s3")
                cl = ChangeLogger(dynamodb.Table(change_log_table_name))
                auth_method = "human_authorized" if human_authorized else "system"
                cl.log_scope_change(
                    agent_id=agent_id,
                    previous_scope=previous_scope,
                    new_scope=new_scope_level,
                    requester_id=requester_id,
                    authorization_method=auth_method,
                    s3_client=s3_client,
                    bucket=evidence_bucket,
                )
            except Exception as cl_exc:
                logger.error(
                    json.dumps({
                        "event": "change_logging_failed",
                        "error": str(cl_exc),
                        "agent_id": agent_id,
                        "timestamp": now,
                    })
                )

        agent.scope_level = new_scope_level
        return agent

    def suspend_agent(self, agent_id: str, requester_id: str) -> AgentIdentity:
        """Suspend an agent by setting its status to 'suspended'.

        Args:
            agent_id: The agent's unique identifier.
            requester_id: Identity of the person requesting the suspension.

        Returns:
            The updated AgentIdentity record.

        Raises:
            ValueError: If the agent is not found.
        """
        agent = self.get_agent(agent_id)
        if agent is None:
            raise ValueError(f"Agent '{agent_id}' not found.")

        now = datetime.now(timezone.utc).isoformat()

        self._table.update_item(
            Key={"agent_id": agent_id},
            UpdateExpression="SET #s = :st",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={":st": "suspended"},
        )

        logger.info(
            json.dumps(
                {
                    "audit_event": "agent_suspended",
                    "agent_id": agent_id,
                    "requester_id": requester_id,
                    "timestamp": now,
                }
            )
        )

        agent.status = "suspended"
        return agent

    def is_suspended(self, agent_id: str) -> bool:
        """Check whether an agent is suspended.

        Args:
            agent_id: The agent's unique identifier.

        Returns:
            True if the agent's status is 'suspended', False otherwise
            (including when the agent is not found).
        """
        agent = self.get_agent(agent_id)
        if agent is None:
            return False
        return agent.status == "suspended"
