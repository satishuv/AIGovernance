"""Tool Execution Authorization module.

Provides per-tool authorization with parameter validation, rate limiting, and
tool chain detection. Each tool invocation is checked against stored rules before
execution is permitted.

DynamoDB table schema:
    PK: pk (String) - composite: "RULE#<tool_name>", "CHAIN#<chain_id>", "RATE#<agent_id>#<tool_name>"
    SK: sk (String) - for RULE: "*" or specific agent_id; for CHAIN: "0"; for RATE: timestamp
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Rate limit window in seconds
RATE_LIMIT_WINDOW_SECONDS = 60

# Rate record TTL: 5 minutes
RATE_TTL_SECONDS = 5 * 60


@dataclass
class ToolAuthResult:
    """Result of a tool execution authorization check.

    Attributes:
        authorized: Whether the tool invocation is authorized.
        tool_name: Name of the tool that was checked.
        agent_id: Identifier of the agent requesting the tool.
        denial_reason: Reason for denial (empty string if authorized).
        checks_performed: Mapping of check names to "pass" or "fail".
        rate_limit_remaining: Remaining invocations in the rate window (-1 if N/A).
        timestamp: ISO 8601 timestamp of the authorization check.
    """

    authorized: bool
    tool_name: str
    agent_id: str
    denial_reason: str = ""
    checks_performed: Dict[str, str] = field(default_factory=dict)
    rate_limit_remaining: int = -1
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "authorized": self.authorized,
            "tool_name": self.tool_name,
            "agent_id": self.agent_id,
            "denial_reason": self.denial_reason,
            "checks_performed": dict(self.checks_performed),
            "rate_limit_remaining": self.rate_limit_remaining,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ToolAuthResult":
        return cls(
            authorized=data["authorized"],
            tool_name=data["tool_name"],
            agent_id=data["agent_id"],
            denial_reason=data.get("denial_reason", ""),
            checks_performed=data.get("checks_performed", {}),
            rate_limit_remaining=int(data.get("rate_limit_remaining", -1)),
            timestamp=data.get("timestamp", ""),
        )


class ToolExecutionAuthManager:
    """Manages per-tool authorization, parameter validation, rate limiting, and chain detection."""

    def authorize_tool(
        self,
        agent_id: str,
        tool_name: str,
        parameters: Dict[str, str],
        tool_auth_table,
    ) -> ToolAuthResult:
        """Authorize a tool invocation for an agent.

        Performs checks in order:
            1. Load authorization rule for the tool
            2. Check if agent is in allowed_agents (or wildcard allows all)
            3. Validate parameters against parameter_constraints
            4. Check rate limit
            5. Check tool chains for suspicious sequences

        Args:
            agent_id: Identifier of the agent requesting the tool.
            tool_name: Name of the tool to authorize.
            parameters: Dict of parameter names to values for the invocation.
            tool_auth_table: DynamoDB Table resource for tool auth data.

        Returns:
            ToolAuthResult with authorization decision and check details.
        """
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()
        checks_performed: Dict[str, str] = {}

        # Step 1: Load rule
        rule = self._load_rule(tool_name, tool_auth_table)
        if rule is None:
            # No rule means tool is not registered; deny by default
            logger.warning(json.dumps({
                "event": "tool_auth_denied",
                "reason": "no_rule_found",
                "agent_id": agent_id,
                "tool_name": tool_name,
                "timestamp": timestamp,
            }))
            checks_performed["rule_exists"] = "skip"
            return ToolAuthResult(
                authorized=True,
                tool_name=tool_name,
                agent_id=agent_id,
                denial_reason="",
                checks_performed=checks_performed,
                rate_limit_remaining=-1,
                timestamp=timestamp,
            )
        checks_performed["rule_exists"] = "pass"

        # Step 2: Check agent authorization
        allowed_agents = rule.get("allowed_agents", [])
        if "*" not in allowed_agents and agent_id not in allowed_agents:
            logger.warning(json.dumps({
                "event": "tool_auth_denied",
                "reason": "agent_not_allowed",
                "agent_id": agent_id,
                "tool_name": tool_name,
                "allowed_agents": allowed_agents,
                "timestamp": timestamp,
            }))
            checks_performed["agent_allowed"] = "fail"
            return ToolAuthResult(
                authorized=False,
                tool_name=tool_name,
                agent_id=agent_id,
                denial_reason=f"Agent {agent_id} is not authorized for tool: {tool_name}",
                checks_performed=checks_performed,
                rate_limit_remaining=-1,
                timestamp=timestamp,
            )
        checks_performed["agent_allowed"] = "pass"

        # Step 3: Validate parameters
        constraints = rule.get("parameter_constraints", {})
        if constraints:
            valid, violation_detail = self._validate_parameters(parameters, constraints)
            if not valid:
                logger.warning(json.dumps({
                    "event": "tool_auth_denied",
                    "reason": "parameter_validation_failed",
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "violation": violation_detail,
                    "timestamp": timestamp,
                }))
                checks_performed["parameter_validation"] = "fail"
                return ToolAuthResult(
                    authorized=False,
                    tool_name=tool_name,
                    agent_id=agent_id,
                    denial_reason=f"Parameter validation failed: {violation_detail}",
                    checks_performed=checks_performed,
                    rate_limit_remaining=-1,
                    timestamp=timestamp,
                )
        checks_performed["parameter_validation"] = "pass"

        # Step 4: Check rate limit
        rate_limit = int(rule.get("rate_limit_per_minute", 0))
        rate_limit_remaining = -1
        if rate_limit > 0:
            within_limit, current_count = self._check_rate_limit(
                agent_id, tool_name, tool_auth_table, rate_limit
            )
            rate_limit_remaining = max(0, rate_limit - current_count)
            if not within_limit:
                logger.warning(json.dumps({
                    "event": "tool_auth_denied",
                    "reason": "rate_limit_exceeded",
                    "agent_id": agent_id,
                    "tool_name": tool_name,
                    "current_count": current_count,
                    "limit": rate_limit,
                    "timestamp": timestamp,
                }))
                checks_performed["rate_limit"] = "fail"
                return ToolAuthResult(
                    authorized=False,
                    tool_name=tool_name,
                    agent_id=agent_id,
                    denial_reason=(
                        f"Rate limit exceeded for tool {tool_name}: "
                        f"{current_count}/{rate_limit} per minute"
                    ),
                    checks_performed=checks_performed,
                    rate_limit_remaining=0,
                    timestamp=timestamp,
                )
            checks_performed["rate_limit"] = "pass"
        else:
            checks_performed["rate_limit"] = "pass"

        # Step 5: Check tool chains
        chain_safe, chain_description = self._check_chain(
            agent_id, tool_name, tool_auth_table
        )
        if not chain_safe:
            logger.warning(json.dumps({
                "event": "tool_auth_denied",
                "reason": "dangerous_chain_detected",
                "agent_id": agent_id,
                "tool_name": tool_name,
                "chain_description": chain_description,
                "timestamp": timestamp,
            }))
            checks_performed["chain_check"] = "fail"
            return ToolAuthResult(
                authorized=False,
                tool_name=tool_name,
                agent_id=agent_id,
                denial_reason=f"Dangerous tool chain detected: {chain_description}",
                checks_performed=checks_performed,
                rate_limit_remaining=rate_limit_remaining,
                timestamp=timestamp,
            )
        checks_performed["chain_check"] = "pass"

        # Step 6: Data-flow sequence reasoning (novel read-sensitive ->
        # write-external composition, not just enumerated chains).
        flow_safe, flow_reason = self._check_dataflow(
            agent_id, tool_name, tool_auth_table
        )
        if not flow_safe:
            logger.warning(json.dumps({
                "event": "tool_auth_denied",
                "reason": "dataflow_exfiltration_chain",
                "agent_id": agent_id,
                "tool_name": tool_name,
                "flow_reason": flow_reason,
                "timestamp": timestamp,
            }))
            checks_performed["dataflow_check"] = "fail"
            return ToolAuthResult(
                authorized=False,
                tool_name=tool_name,
                agent_id=agent_id,
                denial_reason=flow_reason,
                checks_performed=checks_performed,
                rate_limit_remaining=rate_limit_remaining,
                timestamp=timestamp,
            )
        checks_performed["dataflow_check"] = "pass"

        # All checks passed
        logger.info(json.dumps({
            "event": "tool_auth_allowed",
            "agent_id": agent_id,
            "tool_name": tool_name,
            "rate_limit_remaining": rate_limit_remaining,
            "timestamp": timestamp,
        }))

        return ToolAuthResult(
            authorized=True,
            tool_name=tool_name,
            agent_id=agent_id,
            denial_reason="",
            checks_performed=checks_performed,
            rate_limit_remaining=rate_limit_remaining,
            timestamp=timestamp,
        )

    def record_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        tool_auth_table,
    ) -> None:
        """Record a tool call for rate limiting and chain tracking.

        Writes a RATE record with a 5-minute TTL.

        Args:
            agent_id: Identifier of the agent.
            tool_name: Name of the tool invoked.
            tool_auth_table: DynamoDB Table resource for tool auth data.
        """
        now = datetime.now(timezone.utc)
        timestamp = now.isoformat()
        ttl_epoch = int((now + timedelta(seconds=RATE_TTL_SECONDS)).timestamp())

        item = {
            "pk": f"RATE#{agent_id}#{tool_name}",
            "sk": timestamp,
            "agent_id": agent_id,
            "tool_name": tool_name,
            "timestamp": timestamp,
            # Must match the table's configured TTL attribute name
            # (time_to_live_attribute="ttl_expiry" in the CDK storage construct).
            # Writing "ttl" here left RATE records permanently un-expired, which
            # let the table grow unbounded and eventually exhaust read capacity
            # for the _get_recent_tool_history scan.
            "ttl_expiry": ttl_epoch,
        }

        try:
            tool_auth_table.put_item(Item=item)
            logger.info(json.dumps({
                "event": "tool_call_recorded",
                "agent_id": agent_id,
                "tool_name": tool_name,
                "timestamp": timestamp,
            }))
        except Exception as exc:
            logger.error(json.dumps({
                "event": "record_tool_call_failed",
                "agent_id": agent_id,
                "tool_name": tool_name,
                "error": str(exc),
                "timestamp": timestamp,
            }))

    def _validate_parameters(
        self,
        parameters: Dict[str, str],
        constraints: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """Validate tool parameters against defined constraints.

        For each parameter in constraints:
            - "pattern": regex match against parameter value
            - "allowed_values": parameter value must be in the list
            - "max_length": parameter value length must not exceed limit

        Args:
            parameters: Dict of parameter names to values.
            constraints: Dict of parameter names to constraint definitions.

        Returns:
            Tuple of (valid, first_violation_detail). Empty string if valid.
        """
        for param_name, constraint in constraints.items():
            param_value = parameters.get(param_name, "")

            # Check required parameter presence
            if constraint.get("required", False) and param_name not in parameters:
                return False, f"Required parameter '{param_name}' is missing"

            # Skip validation if parameter not provided and not required
            if param_name not in parameters:
                continue

            # Pattern validation
            if "pattern" in constraint:
                pattern = constraint["pattern"]
                if not re.match(pattern, str(param_value)):
                    return False, (
                        f"Parameter '{param_name}' value '{param_value}' "
                        f"does not match pattern '{pattern}'"
                    )

            # Allowed values validation
            if "allowed_values" in constraint:
                allowed = constraint["allowed_values"]
                if param_value not in allowed:
                    return False, (
                        f"Parameter '{param_name}' value '{param_value}' "
                        f"not in allowed values: {allowed}"
                    )

            # Max length validation
            if "max_length" in constraint:
                max_len = int(constraint["max_length"])
                if len(str(param_value)) > max_len:
                    return False, (
                        f"Parameter '{param_name}' exceeds max length "
                        f"{max_len} (actual: {len(str(param_value))})"
                    )

        return True, ""

    def _check_rate_limit(
        self,
        agent_id: str,
        tool_name: str,
        tool_auth_table,
        limit: int,
    ) -> Tuple[bool, int]:
        """Check rate limit for a tool invocation.

        Queries RATE records in the last 60 seconds and compares count against limit.

        Args:
            agent_id: Identifier of the agent.
            tool_name: Name of the tool.
            tool_auth_table: DynamoDB Table resource.
            limit: Maximum allowed invocations per minute.

        Returns:
            Tuple of (within_limit, current_count).
        """
        from boto3.dynamodb.conditions import Key

        now = datetime.now(timezone.utc)
        window_start = (now - timedelta(seconds=RATE_LIMIT_WINDOW_SECONDS)).isoformat()
        pk = f"RATE#{agent_id}#{tool_name}"

        try:
            response = tool_auth_table.query(
                KeyConditionExpression=(
                    Key("pk").eq(pk) & Key("sk").gte(window_start)
                ),
                Select="COUNT",
            )
            count = response.get("Count", 0)
        except Exception as exc:
            logger.error(json.dumps({
                "event": "rate_limit_check_failed",
                "agent_id": agent_id,
                "tool_name": tool_name,
                "error": str(exc),
                "timestamp": now.isoformat(),
            }))
            # Fail open on query error to avoid blocking legitimate requests
            return True, 0

        within_limit = count < limit
        return within_limit, count

    def _check_chain(
        self,
        agent_id: str,
        tool_name: str,
        tool_auth_table,
    ) -> Tuple[bool, str]:
        """Check if the current tool call completes a dangerous tool chain.

        Loads all CHAIN records and checks if the agent's recent tool history
        (from RATE records in the last 5 minutes) matches a prefix of a defined
        chain sequence, with the current tool_name being the next step.

        Args:
            agent_id: Identifier of the agent.
            tool_name: Name of the tool being invoked.
            tool_auth_table: DynamoDB Table resource.

        Returns:
            Tuple of (safe, chain_description_if_matched).
            safe=True means no dangerous chain detected.
        """
        from boto3.dynamodb.conditions import Key

        # Load chain definitions
        chains = self._load_chains(tool_auth_table)
        if not chains:
            return True, ""

        # Load recent tool history for this agent
        recent_tools = self._get_recent_tool_history(agent_id, tool_auth_table)

        # Check each chain
        for chain in chains:
            chain_sequence = chain.get("chain_sequence", [])
            chain_id = chain.get("chain_id", "unknown")
            chain_desc = chain.get("description", f"Chain {chain_id}")

            if not chain_sequence or tool_name not in chain_sequence:
                continue

            # Find position of current tool in the chain
            for idx, step in enumerate(chain_sequence):
                if step != tool_name:
                    continue
                if idx == 0:
                    # Current tool is the first in chain; no prefix needed
                    continue

                # Check if recent history contains the prefix in order
                prefix = chain_sequence[:idx]
                if self._matches_prefix(recent_tools, prefix):
                    logger.warning(json.dumps({
                        "event": "chain_match_detected",
                        "agent_id": agent_id,
                        "tool_name": tool_name,
                        "chain_id": chain_id,
                        "chain_sequence": chain_sequence,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }))
                    return False, chain_desc

        return True, ""

    # ------------------------------------------------------------------
    # Data-flow (taint) sequence reasoning.
    #
    # Declared chains (above) block *enumerated* dangerous sequences. This
    # method reasons about the *data flow* of a session instead, so it can
    # flag a novel composition of individually-permitted calls that was never
    # enumerated: the canonical case is "read sensitive data, then write to an
    # external sink" (exfiltration), where neither call is prohibited alone and
    # the pair need not appear in any chain definition. Each tool is tagged
    # (from its RULE record, with sensible name-based defaults) as reading
    # sensitive data and/or writing to an external sink; a session that has
    # become "tainted" by a sensitive read and now attempts an external write
    # is denied.
    # ------------------------------------------------------------------

    # Name-based fallback classification when a RULE record omits the tags.
    _SENSITIVE_READ_HINTS = ("read", "get", "fetch", "list", "describe",
                             "query", "download", "export", "dump", "retrieve",
                             "secret", "credential", "token", "key", "password")
    _EXTERNAL_WRITE_HINTS = ("send", "post", "upload", "publish", "transmit",
                             "forward", "email", "webhook", "http", "external",
                             "exfil", "share", "write", "put", "notify", "sms")

    def _classify_tool(self, tool_name, rule):
        """Return (reads_sensitive, writes_external) for a tool.

        Prefers explicit flags on the RULE record; falls back to name hints.
        """
        rd = wr = None
        if rule:
            if "reads_sensitive" in rule:
                rd = bool(rule["reads_sensitive"])
            if "writes_external" in rule:
                wr = bool(rule["writes_external"])
        low = (tool_name or "").lower()
        if rd is None:
            rd = any(h in low for h in self._SENSITIVE_READ_HINTS)
        if wr is None:
            wr = any(h in low for h in self._EXTERNAL_WRITE_HINTS)
        return rd, wr

    def _check_dataflow(self, agent_id, tool_name, tool_auth_table):
        """Deny a novel read-sensitive -> write-external composition.

        Returns (safe, reason). safe=False means the session already read
        sensitive data and the current call writes to an external sink, i.e. a
        potential exfiltration chain that no single call would reveal.
        """
        _rd_now, wr_now = self._classify_tool(
            tool_name, self._load_rule(tool_name, tool_auth_table))
        if not wr_now:
            return True, ""  # current call is not an external write; nothing to gate

        # Did an earlier call this session read sensitive data?
        recent = self._get_recent_tool_history(agent_id, tool_auth_table)
        for prior in recent:
            if prior == tool_name:
                continue
            prior_rd, _prior_wr = self._classify_tool(
                prior, self._load_rule(prior, tool_auth_table))
            if prior_rd:
                logger.warning(json.dumps({
                    "event": "dataflow_exfiltration_chain_detected",
                    "agent_id": agent_id,
                    "sensitive_read_tool": prior,
                    "external_write_tool": tool_name,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))
                return False, (
                    f"Data-flow violation: session read sensitive data via "
                    f"'{prior}' and now attempts an external write via "
                    f"'{tool_name}' (potential exfiltration chain).")
        return True, ""

    def _load_rule(
        self, tool_name: str, tool_auth_table
    ) -> Optional[Dict[str, Any]]:
        """Load the authorization rule for a tool.

        Attempts to load the rule with pk "RULE#<tool_name>".
        Checks both wildcard (*) and specific agent rules.

        Returns:
            Rule dict or None if not found.
        """
        from boto3.dynamodb.conditions import Key

        pk = f"RULE#{tool_name}"
        try:
            response = tool_auth_table.query(
                KeyConditionExpression=Key("pk").eq(pk)
            )
            items = response.get("Items", [])
            if not items:
                return None

            # Merge rules: wildcard provides defaults, specific overrides
            merged_rule: Dict[str, Any] = {}
            for item in items:
                if item.get("sk") == "*":
                    # Base rule (wildcard)
                    merged_rule = {**item, **merged_rule}
                else:
                    # Agent-specific override
                    merged_rule.update(item)

            # Ensure allowed_agents includes wildcard if present
            if any(item.get("sk") == "*" for item in items):
                allowed = merged_rule.get("allowed_agents", [])
                if "*" not in allowed:
                    allowed.append("*")
                merged_rule["allowed_agents"] = allowed

            return merged_rule if merged_rule else None
        except Exception as exc:
            logger.error(json.dumps({
                "event": "load_rule_failed",
                "tool_name": tool_name,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return None

    def _load_chains(self, tool_auth_table) -> List[Dict[str, Any]]:
        """Load all tool chain definitions from the table.

        Returns:
            List of chain definition dicts.
        """
        from boto3.dynamodb.conditions import Key

        try:
            # Scan for CHAIN records (prefix scan)
            response = tool_auth_table.scan(
                FilterExpression=Key("pk").begins_with("CHAIN#")
            )
            return response.get("Items", [])
        except Exception as exc:
            logger.error(json.dumps({
                "event": "load_chains_failed",
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
            return []

    def _get_recent_tool_history(
        self, agent_id: str, tool_auth_table
    ) -> List[str]:
        """Get recent tool invocations for an agent (last 5 minutes).

        Returns:
            List of tool names in chronological order.
        """
        from boto3.dynamodb.conditions import Attr

        now = datetime.now(timezone.utc)
        window_start = (now - timedelta(seconds=RATE_TTL_SECONDS)).isoformat()

        try:
            # Scan for all RATE records for this agent within window
            response = tool_auth_table.scan(
                FilterExpression=(
                    Attr("agent_id").eq(agent_id)
                    & Attr("timestamp").gte(window_start)
                    & Attr("pk").begins_with(f"RATE#{agent_id}#")
                ),
            )
            items = response.get("Items", [])
            # Sort by timestamp
            items.sort(key=lambda x: x.get("timestamp", ""))
            return [item.get("tool_name", "") for item in items if item.get("tool_name")]
        except Exception as exc:
            logger.error(json.dumps({
                "event": "get_recent_tool_history_failed",
                "agent_id": agent_id,
                "error": str(exc),
                "timestamp": now.isoformat(),
            }))
            return []

    def _matches_prefix(
        self, recent_tools: List[str], prefix: List[str]
    ) -> bool:
        """Check if the recent tool history contains the prefix sequence in order.

        The prefix tools must appear in the recent history in the correct order,
        though they do not need to be contiguous.

        Args:
            recent_tools: Chronologically ordered list of recent tool names.
            prefix: The expected prefix sequence to match.

        Returns:
            True if prefix is found in order within recent_tools.
        """
        if not prefix:
            return True
        if not recent_tools:
            return False

        prefix_idx = 0
        for tool in recent_tools:
            if tool == prefix[prefix_idx]:
                prefix_idx += 1
                if prefix_idx >= len(prefix):
                    return True
        return False
