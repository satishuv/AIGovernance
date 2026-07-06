"""Control Trace module.

Stores and queries Control_Trace objects that link framework controls to
evidence records and governance decisions. Supports batch writes and
queries by control_id, evidence_record_id, and decision_id.

Requirements: 13.1, 13.2, 13.3, 13.4
"""

import json
import logging
from typing import List, Optional

from models import ControlTrace

logger = logging.getLogger(__name__)


class ControlTraceManager:
    """Manages storage and retrieval of Control_Trace objects."""

    @staticmethod
    def store_traces(traces: List[ControlTrace], dynamodb_table) -> int:
        """Batch write ControlTrace objects to the ControlTraceTable.

        Args:
            traces: List of ControlTrace objects to store.
            dynamodb_table: boto3 DynamoDB Table for ControlTraceTable.

        Returns:
            Number of traces successfully written.
        """
        written = 0
        with dynamodb_table.batch_writer() as batch:
            for trace in traces:
                batch.put_item(Item=trace.to_dict())
                written += 1

        logger.info(
            json.dumps({
                "audit_event": "control_traces_stored",
                "trace_count": written,
            })
        )
        return written

    @staticmethod
    def query_by_control_id(
        control_id: str,
        dynamodb_table,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> List[ControlTrace]:
        """Query ControlTrace objects by control_id with optional time range.

        Args:
            control_id: The framework control identifier.
            dynamodb_table: boto3 DynamoDB Table for ControlTraceTable.
            start_time: Optional ISO 8601 start time filter.
            end_time: Optional ISO 8601 end time filter.

        Returns:
            List of matching ControlTrace objects ordered by timestamp.
        """
        from boto3.dynamodb.conditions import Key

        key_expr = Key("control_id").eq(control_id)
        if start_time and end_time:
            key_expr = key_expr & Key("timestamp").between(start_time, end_time)
        elif start_time:
            key_expr = key_expr & Key("timestamp").gte(start_time)
        elif end_time:
            key_expr = key_expr & Key("timestamp").lte(end_time)

        response = dynamodb_table.query(KeyConditionExpression=key_expr)
        items = response.get("Items", [])

        while "LastEvaluatedKey" in response:
            response = dynamodb_table.query(
                KeyConditionExpression=key_expr,
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))

        return [ControlTrace.from_dict(item) for item in items]

    @staticmethod
    def query_by_evidence_record_id(
        evidence_record_id: str, dynamodb_table
    ) -> List[ControlTrace]:
        """Query ControlTrace objects by evidence_record_id using GSI.

        Args:
            evidence_record_id: The evidence record identifier.
            dynamodb_table: boto3 DynamoDB Table for ControlTraceTable.

        Returns:
            List of matching ControlTrace objects.
        """
        from boto3.dynamodb.conditions import Key

        response = dynamodb_table.query(
            IndexName="ByEvidenceRecordId",
            KeyConditionExpression=Key("evidence_record_id").eq(
                evidence_record_id
            ),
        )
        items = response.get("Items", [])

        while "LastEvaluatedKey" in response:
            response = dynamodb_table.query(
                IndexName="ByEvidenceRecordId",
                KeyConditionExpression=Key("evidence_record_id").eq(
                    evidence_record_id
                ),
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))

        return [ControlTrace.from_dict(item) for item in items]

    @staticmethod
    def query_by_decision_id(
        decision_id: str, dynamodb_table
    ) -> List[ControlTrace]:
        """Query ControlTrace objects by decision_id using GSI.

        Args:
            decision_id: The governance decision identifier.
            dynamodb_table: boto3 DynamoDB Table for ControlTraceTable.

        Returns:
            List of matching ControlTrace objects.
        """
        from boto3.dynamodb.conditions import Key

        response = dynamodb_table.query(
            IndexName="ByDecisionId",
            KeyConditionExpression=Key("decision_id").eq(decision_id),
        )
        items = response.get("Items", [])

        while "LastEvaluatedKey" in response:
            response = dynamodb_table.query(
                IndexName="ByDecisionId",
                KeyConditionExpression=Key("decision_id").eq(decision_id),
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))

        return [ControlTrace.from_dict(item) for item in items]
