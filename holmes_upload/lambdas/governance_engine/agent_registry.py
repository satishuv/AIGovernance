"""Agent Registry module.

Manages the formal inventory of all registered agents, capturing each agent's
purpose, owner, data classes accessed, tools used, approved scope, and
deployment environment. All mutations produce structured audit log entries.

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 19.1, 19.6
"""

import json
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from models import AgentRegistryEntry

logger = logging.getLogger(__name__)

VALID_ENVIRONMENTS = {"dev", "staging", "prod"}


class AgentRegistry:
    """Manages agent registry entries in DynamoDB AgentRegistryTable.

    Args:
        table: A boto3 DynamoDB Table resource for the AgentRegistryTable.
    """

    def __init__(self, table):
        self._table = table

    def register_agent(
        self, entry: AgentRegistryEntry, requester_id: str
    ) -> AgentRegistryEntry:
        """Register a new agent in the registry.

        Validates that the entry has a non-empty purpose, owner, at least one
        data_class, and a valid environment before writing to DynamoDB.

        Args:
            entry: The AgentRegistryEntry to register.
            requester_id: Identity of the person requesting the registration.

        Returns:
            The registered AgentRegistryEntry.

        Raises:
            ValueError: If validation fails (empty purpose/owner/data_classes
                        or invalid environment).
        """
        if not entry.purpose or not entry.purpose.strip():
            raise ValueError("Agent registry entry must have a non-empty purpose.")

        if not entry.owner or not entry.owner.strip():
            raise ValueError("Agent registry entry must have a non-empty owner.")

        if not entry.data_classes:
            raise ValueError(
                "Agent registry entry must declare at least one data_class."
            )

        if entry.environment not in VALID_ENVIRONMENTS:
            raise ValueError(
                f"Invalid environment '{entry.environment}'. "
                f"Must be one of {sorted(VALID_ENVIRONMENTS)}."
            )

        self._table.put_item(Item=entry.to_dict())

        now = datetime.now(timezone.utc).isoformat()
        logger.info(
            json.dumps(
                {
                    "audit_event": "agent_registered",
                    "agent_id": entry.agent_id,
                    "purpose": entry.purpose,
                    "owner": entry.owner,
                    "data_classes": entry.data_classes,
                    "tools": entry.tools,
                    "approved_scope": entry.approved_scope,
                    "environment": entry.environment,
                    "requester_id": requester_id,
                    "timestamp": now,
                }
            )
        )

        return entry

    def get_agent(self, agent_id: str) -> Optional[AgentRegistryEntry]:
        """Retrieve an agent registry entry from DynamoDB.

        Args:
            agent_id: The agent's unique identifier.

        Returns:
            AgentRegistryEntry if found, None otherwise.
        """
        response = self._table.get_item(Key={"agent_id": agent_id})
        item = response.get("Item")
        if item is None:
            return None
        return AgentRegistryEntry.from_dict(item)

    def update_agent(
        self, agent_id: str, updates: dict, requester_id: str
    ) -> Optional[AgentRegistryEntry]:
        """Update specified fields of an agent registry entry.

        Args:
            agent_id: The agent's unique identifier.
            updates: Dictionary of field names to new values.
            requester_id: Identity of the person requesting the update.

        Returns:
            The updated AgentRegistryEntry, or None if the agent was not found.

        Raises:
            ValueError: If updates dict is empty.
        """
        if not updates:
            raise ValueError("Updates dict must not be empty.")

        agent = self.get_agent(agent_id)
        if agent is None:
            return None

        update_expressions = []
        expression_attr_names = {}
        expression_attr_values = {}

        for idx, (key, value) in enumerate(updates.items()):
            attr_name = f"#k{idx}"
            attr_value = f":v{idx}"
            update_expressions.append(f"{attr_name} = {attr_value}")
            expression_attr_names[attr_name] = key
            expression_attr_values[attr_value] = value

        self._table.update_item(
            Key={"agent_id": agent_id},
            UpdateExpression="SET " + ", ".join(update_expressions),
            ExpressionAttributeNames=expression_attr_names,
            ExpressionAttributeValues=expression_attr_values,
        )

        now = datetime.now(timezone.utc).isoformat()
        logger.info(
            json.dumps(
                {
                    "audit_event": "agent_registry_updated",
                    "agent_id": agent_id,
                    "fields_changed": list(updates.keys()),
                    "requester_id": requester_id,
                    "timestamp": now,
                }
            )
        )

        return self.get_agent(agent_id)

    def check_data_class_access(self, agent_id: str, data_class: str) -> bool:
        """Check if a data class is declared in the agent's registry entry.

        Args:
            agent_id: The agent's unique identifier.
            data_class: The data class to check access for.

        Returns:
            True if data_class is in the agent's declared data_classes list,
            False otherwise (including when the agent is not found).
        """
        agent = self.get_agent(agent_id)
        if agent is None:
            return False
        return data_class in agent.data_classes

    def query_agents(self, filters: dict) -> List[AgentRegistryEntry]:
        """Query agents with in-memory filtering.

        Scans the AgentRegistryTable and filters results in-memory.
        Acceptable for MVP; production should use GSIs or query patterns.

        Supported filter keys: owner, data_class, tool, scope_level, environment.

        Args:
            filters: Dictionary of filter criteria. Supported keys:
                - owner (str): Match agents with this owner.
                - data_class (str): Match agents declaring this data class.
                - tool (str): Match agents declaring this tool.
                - scope_level (int): Match agents with this approved_scope.
                - environment (str): Match agents in this environment.

        Returns:
            List of matching AgentRegistryEntry objects.
        """
        response = self._table.scan()
        items = response.get("Items", [])

        # Handle paginated scan results
        while "LastEvaluatedKey" in response:
            response = self._table.scan(
                ExclusiveStartKey=response["LastEvaluatedKey"]
            )
            items.extend(response.get("Items", []))

        entries = [AgentRegistryEntry.from_dict(item) for item in items]

        results = []
        for entry in entries:
            if "owner" in filters and entry.owner != filters["owner"]:
                continue
            if "data_class" in filters and filters["data_class"] not in entry.data_classes:
                continue
            if "tool" in filters and filters["tool"] not in entry.tools:
                continue
            if "scope_level" in filters and entry.approved_scope != filters["scope_level"]:
                continue
            if "environment" in filters and entry.environment != filters["environment"]:
                continue
            results.append(entry)

        return results
