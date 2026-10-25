"""Agent Registry module.

Manages the formal inventory of all registered agents, capturing each agent's
purpose, owner, data classes accessed, tools used, approved scope, and
deployment environment. All mutations produce structured audit log entries.

Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 19.1, 19.6
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from authority_identity import AmbiguousAgentPrincipal, normalize_principal_arn
from models import AgentRegistryEntry

logger = logging.getLogger(__name__)

VALID_ENVIRONMENTS = {"dev", "staging", "prod"}

# Global secondary index on runtime_principal. Caller classification on every
# authority request is one Query on this index instead of a registry scan.
RUNTIME_PRINCIPAL_INDEX = "ByRuntimePrincipal"


def _check_list_fields(values: Dict[str, Any]) -> None:
    """Authority boundaries must be lists of non-empty strings (a str would split into characters)."""
    bad = sorted(name for name, value in values.items()
                 if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value))
    if bad:
        raise ValueError(f"registry fields {bad} must be lists of non-empty strings")


def registry_table_definition(table_name: str) -> Dict[str, Any]:
    """create_table arguments matching the deployed AgentRegistryTable.

    Kept next to the code that queries the index so tests and the offline demo
    build the same key schema the CDK storage construct deploys.
    """
    return {
        "TableName": table_name,
        "KeySchema": [{"AttributeName": "agent_id", "KeyType": "HASH"}],
        "AttributeDefinitions": [
            {"AttributeName": "agent_id", "AttributeType": "S"},
            {"AttributeName": "runtime_principal", "AttributeType": "S"},
        ],
        "GlobalSecondaryIndexes": [{
            "IndexName": RUNTIME_PRINCIPAL_INDEX,
            "KeySchema": [{"AttributeName": "runtime_principal", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        "BillingMode": "PAY_PER_REQUEST",
    }


class AgentRegistry:
    """Manages agent registry entries in DynamoDB AgentRegistryTable.

    Args:
        table: A boto3 DynamoDB Table resource for the AgentRegistryTable.
    """

    def __init__(self, table):
        self._table = table

    def register_agent(
        self, entry: AgentRegistryEntry, requester_id: str, create_only: bool = False
    ) -> AgentRegistryEntry:
        """Register a new agent in the registry.

        Validates that the entry has a non-empty purpose, owner, at least one
        data_class, and a valid environment before writing to DynamoDB.

        Args:
            entry: The AgentRegistryEntry to register.
            requester_id: Identity of the person requesting the registration.
            create_only: Refuse (ValueError) when the agent id is already registered, with a
                conditional write, so a registration can never replace an existing entry and its
                owner fields (audit 2026-10-23, run-2).

        Returns:
            The registered AgentRegistryEntry.

        Raises:
            ValueError: If validation fails (empty purpose/owner/data_classes
                        or invalid environment), or create_only and the agent exists.
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
        _check_list_fields({name: getattr(entry, name) for name in AgentRegistryEntry.LIST_FIELDS})

        if create_only:
            try:
                self._table.put_item(Item=entry.to_dict(), ConditionExpression="attribute_not_exists(agent_id)")
            except Exception as exc:
                if "ConditionalCheckFailed" in type(exc).__name__ or "ConditionalCheckFailed" in str(exc):
                    raise ValueError(f"agent '{entry.agent_id}' is already registered") from exc
                raise
        else:
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
        # Strongly consistent: a suspension or a removed operation must apply at the next decision and
        # execution, as the runbook states (audit 2026-10-23, run-2: eventually-consistent-read).
        response = self._table.get_item(Key={"agent_id": agent_id}, ConsistentRead=True)
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
        _check_list_fields({k: v for k, v in updates.items() if k in AgentRegistryEntry.LIST_FIELDS})

        agent = self.get_agent(agent_id)
        if agent is None:
            return None

        update_expressions = []
        remove_names = []
        expression_attr_names = {}
        expression_attr_values = {}

        for idx, (key, value) in enumerate(updates.items()):
            attr_name = f"#k{idx}"
            expression_attr_names[attr_name] = key
            if key == "runtime_principal" and not value:
                # An empty string cannot be an index key value: clearing the
                # runtime principal removes the attribute instead.
                remove_names.append(attr_name)
                continue
            attr_value = f":v{idx}"
            update_expressions.append(f"{attr_name} = {attr_value}")
            expression_attr_values[attr_value] = value

        clauses = []
        if update_expressions:
            clauses.append("SET " + ", ".join(update_expressions))
        if remove_names:
            clauses.append("REMOVE " + ", ".join(remove_names))
        update_kwargs = {
            "Key": {"agent_id": agent_id},
            "UpdateExpression": " ".join(clauses),
            "ExpressionAttributeNames": expression_attr_names,
        }
        if expression_attr_values:
            update_kwargs["ExpressionAttributeValues"] = expression_attr_values
        self._table.update_item(**update_kwargs)

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
        # approved_data_classes is [] unless data_classes is a list: a mistyped String must never be
        # substring-matched (audit 2026-10-23, run-2: scalar-list-field-coerced-to-characters).
        return data_class in agent.approved_data_classes

    def find_by_runtime_principal(self, principal_id: str) -> Optional[AgentRegistryEntry]:
        """The agent whose runtime principal is principal_id, by index query.

        An STS assumed-role session ARN is matched through its role ARN.
        Raises AmbiguousAgentPrincipal when two agents declare the same runtime
        principal: one authenticated principal must map to exactly one agent,
        and guessing between them would let one agent act as another. Query
        errors propagate so callers fail closed.
        """
        from boto3.dynamodb.conditions import Key

        matches: Dict[str, Dict[str, Any]] = {}
        for value in {principal_id, normalize_principal_arn(principal_id)} - {""}:
            kwargs: Dict[str, Any] = {
                "IndexName": RUNTIME_PRINCIPAL_INDEX,
                "KeyConditionExpression": Key("runtime_principal").eq(value),
            }
            while True:
                response = self._table.query(**kwargs)
                for item in response.get("Items", []):
                    matches[str(item["agent_id"])] = item
                if "LastEvaluatedKey" not in response:
                    break
                kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]
        if len(matches) > 1:
            raise AmbiguousAgentPrincipal(
                f"runtime principal is declared by {len(matches)} agents: {sorted(matches)}")
        if not matches:
            return None
        return AgentRegistryEntry.from_dict(next(iter(matches.values())))

    def agent_id_for_principal(self, principal_id: str) -> str:
        """Agent id for an authenticated principal, or "" when it is not an agent."""
        entry = self.find_by_runtime_principal(principal_id)
        return entry.agent_id if entry else ""

    def query_agents(self, filters: dict) -> List[AgentRegistryEntry]:
        """Query agents with in-memory filtering.

        Scans the AgentRegistryTable and filters results in-memory. This is
        for inventory, reporting and administration only. Request-path code
        must use get_agent or find_by_runtime_principal, which are key and
        index reads (P0-18).

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
            if "data_class" in filters and filters["data_class"] not in entry.approved_data_classes:
                continue
            if "tool" in filters and filters["tool"] not in (entry.tools if isinstance(entry.tools, list) else []):
                continue
            if "scope_level" in filters and entry.approved_scope != filters["scope_level"]:
                continue
            if "environment" in filters and entry.environment != filters["environment"]:
                continue
            results.append(entry)

        return results
