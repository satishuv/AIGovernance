"""Queryable Decision History module.

Indexes governance decisions in DynamoDB for efficient querying by agent,
verdict, risk score range, and control ID. All queries support pagination
via last_evaluated_key with a default limit of 100.

Requirements: 22.1, 22.2, 22.3, 22.4
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from models import DecisionHistoryEntry, GovernanceDecision

logger = logging.getLogger(__name__)

DEFAULT_LIMIT = 100


class DecisionHistory:
    """Indexes and queries governance decision history in DynamoDB.

    Args:
        table: A boto3 DynamoDB Table resource for the DecisionHistoryTable.
    """

    def __init__(self, table):
        self._table = table

    def index_decision(self, decision: GovernanceDecision) -> DecisionHistoryEntry:
        """Index a governance decision for queryable history.

        Extracts fields from the GovernanceDecision and writes a
        DecisionHistoryEntry to the DecisionHistoryTable.

        Args:
            decision: The GovernanceDecision to index.

        Returns:
            The created DecisionHistoryEntry.
        """
        now = datetime.now(timezone.utc).isoformat()

        # Extract policy_id from policy_result dict
        policy_id = ""
        if isinstance(decision.policy_result, dict):
            policy_id = decision.policy_result.get("policy_id", "")
        elif hasattr(decision.policy_result, "policy_id"):
            policy_id = decision.policy_result.policy_id

        entry = DecisionHistoryEntry(
            agent_id=decision.agent_id,
            timestamp=decision.timestamp or now,
            decision_id=decision.decision_id,
            action_requested=decision.action_requested,
            verdict=decision.verdict,
            risk_score=decision.risk_score,
            control_ids=list(decision.framework_mapping) if decision.framework_mapping else [],
            policy_id=policy_id,
            environment="",
        )

        # Write the entry
        item = entry.to_dict()
        self._table.put_item(Item=item)

        logger.info(
            json.dumps(
                {
                    "audit_event": "decision_indexed",
                    "decision_id": decision.decision_id,
                    "agent_id": decision.agent_id,
                    "verdict": decision.verdict,
                    "risk_score": decision.risk_score,
                    "control_ids": entry.control_ids,
                    "timestamp": entry.timestamp,
                }
            )
        )

        return entry

    def query_by_agent(
        self,
        agent_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = DEFAULT_LIMIT,
        last_evaluated_key: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[DecisionHistoryEntry], Optional[Dict[str, Any]]]:
        """Query decisions by agent_id with optional date range.

        Args:
            agent_id: The agent to query decisions for.
            start_date: ISO 8601 lower bound on timestamp (inclusive).
            end_date: ISO 8601 upper bound on timestamp (inclusive).
            limit: Maximum number of results to return. Defaults to 100.
            last_evaluated_key: Pagination token from a previous query.

        Returns:
            Tuple of (list of DecisionHistoryEntry, next last_evaluated_key or None).
        """
        key_condition = "#aid = :aid"
        expr_names = {"#aid": "agent_id"}
        expr_values: Dict[str, Any] = {":aid": agent_id}

        if start_date and end_date:
            key_condition += " AND #ts BETWEEN :start AND :end"
            expr_names["#ts"] = "timestamp"
            expr_values[":start"] = start_date
            expr_values[":end"] = end_date
        elif start_date:
            key_condition += " AND #ts >= :start"
            expr_names["#ts"] = "timestamp"
            expr_values[":start"] = start_date
        elif end_date:
            key_condition += " AND #ts <= :end"
            expr_names["#ts"] = "timestamp"
            expr_values[":end"] = end_date

        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": key_condition,
            "ExpressionAttributeNames": expr_names,
            "ExpressionAttributeValues": expr_values,
            "Limit": limit,
        }
        if last_evaluated_key:
            kwargs["ExclusiveStartKey"] = last_evaluated_key

        response = self._table.query(**kwargs)
        items = response.get("Items", [])
        next_key = response.get("LastEvaluatedKey")

        entries = [DecisionHistoryEntry.from_dict(item) for item in items]
        return entries, next_key

    def query_by_verdict(
        self,
        agent_id: str,
        verdict: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        limit: int = DEFAULT_LIMIT,
        last_evaluated_key: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[DecisionHistoryEntry], Optional[Dict[str, Any]]]:
        """Query decisions by agent_id filtered by verdict.

        Uses the primary table query with a filter expression on verdict.

        Args:
            agent_id: The agent to query decisions for.
            verdict: Filter by verdict (allow/deny/escalate).
            start_date: ISO 8601 lower bound on timestamp (inclusive).
            end_date: ISO 8601 upper bound on timestamp (inclusive).
            limit: Maximum number of results to return. Defaults to 100.
            last_evaluated_key: Pagination token from a previous query.

        Returns:
            Tuple of (list of DecisionHistoryEntry, next last_evaluated_key or None).
        """
        key_condition = "#aid = :aid"
        expr_names: Dict[str, str] = {"#aid": "agent_id", "#v": "verdict"}
        expr_values: Dict[str, Any] = {":aid": agent_id, ":verdict": verdict}

        if start_date and end_date:
            key_condition += " AND #ts BETWEEN :start AND :end"
            expr_names["#ts"] = "timestamp"
            expr_values[":start"] = start_date
            expr_values[":end"] = end_date
        elif start_date:
            key_condition += " AND #ts >= :start"
            expr_names["#ts"] = "timestamp"
            expr_values[":start"] = start_date
        elif end_date:
            key_condition += " AND #ts <= :end"
            expr_names["#ts"] = "timestamp"
            expr_values[":end"] = end_date

        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": key_condition,
            "FilterExpression": "#v = :verdict",
            "ExpressionAttributeNames": expr_names,
            "ExpressionAttributeValues": expr_values,
            "Limit": limit,
        }
        if last_evaluated_key:
            kwargs["ExclusiveStartKey"] = last_evaluated_key

        response = self._table.query(**kwargs)
        items = response.get("Items", [])
        next_key = response.get("LastEvaluatedKey")

        entries = [DecisionHistoryEntry.from_dict(item) for item in items]
        return entries, next_key

    def query_by_risk_score_range(
        self,
        agent_id: str,
        min_score: float,
        max_score: float,
        limit: int = DEFAULT_LIMIT,
        last_evaluated_key: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[DecisionHistoryEntry], Optional[Dict[str, Any]]]:
        """Query decisions by agent_id filtered by risk score range.

        Args:
            agent_id: The agent to query decisions for.
            min_score: Minimum risk score (inclusive).
            max_score: Maximum risk score (inclusive).
            limit: Maximum number of results to return. Defaults to 100.
            last_evaluated_key: Pagination token from a previous query.

        Returns:
            Tuple of (list of DecisionHistoryEntry, next last_evaluated_key or None).
        """
        kwargs: Dict[str, Any] = {
            "KeyConditionExpression": "#aid = :aid",
            "FilterExpression": "#rs BETWEEN :min_score AND :max_score",
            "ExpressionAttributeNames": {
                "#aid": "agent_id",
                "#rs": "risk_score",
            },
            "ExpressionAttributeValues": {
                ":aid": agent_id,
                ":min_score": min_score,
                ":max_score": max_score,
            },
            "Limit": limit,
        }
        if last_evaluated_key:
            kwargs["ExclusiveStartKey"] = last_evaluated_key

        response = self._table.query(**kwargs)
        items = response.get("Items", [])
        next_key = response.get("LastEvaluatedKey")

        entries = [DecisionHistoryEntry.from_dict(item) for item in items]
        return entries, next_key

    def query_by_control_id(
        self,
        control_id: str,
        limit: int = DEFAULT_LIMIT,
        last_evaluated_key: Optional[Dict[str, Any]] = None,
    ) -> Tuple[List[DecisionHistoryEntry], Optional[Dict[str, Any]]]:
        """Query decisions by control_id using GSI.

        Args:
            control_id: The framework control ID to query by.
            limit: Maximum number of results to return. Defaults to 100.
            last_evaluated_key: Pagination token from a previous query.

        Returns:
            Tuple of (list of DecisionHistoryEntry, next last_evaluated_key or None).
        """
        kwargs: Dict[str, Any] = {
            "IndexName": "ByControlId",
            "KeyConditionExpression": "#cid = :cid",
            "ExpressionAttributeNames": {"#cid": "control_id"},
            "ExpressionAttributeValues": {":cid": control_id},
            "Limit": limit,
        }
        if last_evaluated_key:
            kwargs["ExclusiveStartKey"] = last_evaluated_key

        response = self._table.query(**kwargs)
        items = response.get("Items", [])
        next_key = response.get("LastEvaluatedKey")

        entries = [DecisionHistoryEntry.from_dict(item) for item in items]
        return entries, next_key
