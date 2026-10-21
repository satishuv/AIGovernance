"""Durable backing for authoritative governance state (P0-12).

V4 invariant 40: no authoritative security state may depend solely on Lambda
or container process memory. Process memory is lost on every cold start and
differs between concurrent instances, so a revocation, a budget total or an
approval held only in memory is silently forgotten or never seen by the next
request.

Classes that hold authoritative state accept a DynamoDB table. With a table,
every mutation is written through and reads come from the table. Without a
table they keep working in memory for tests and local experiments, but they
refuse to start inside a deployed Lambda function.
"""

import json
import os
from decimal import Decimal
from typing import Any, Dict


class MemoryOnlyStateError(RuntimeError):
    """Authoritative state was about to live only in process memory in a deployed function."""


def running_in_lambda() -> bool:
    return bool(os.environ.get("AWS_LAMBDA_FUNCTION_NAME"))


def require_durable(component: str, table: Any) -> None:
    """Refuse memory-only authoritative state inside a deployed function."""
    if table is None and running_in_lambda():
        raise MemoryOnlyStateError(
            f"{component} holds authoritative governance state and needs a DynamoDB table in a "
            "deployed function: process memory is lost on cold start and differs between instances.")


def to_item(value: Dict[str, Any]) -> Dict[str, Any]:
    """A JSON-shaped dict as a DynamoDB item (floats become Decimal)."""
    return json.loads(json.dumps(value, default=str), parse_float=Decimal)


def from_item(value: Any) -> Any:
    """A DynamoDB item back to plain Python numbers."""
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, dict):
        return {k: from_item(v) for k, v in value.items()}
    if isinstance(value, list):
        return [from_item(v) for v in value]
    return value


def scan_all(table) -> list:
    """Every item of a table. Administrative and reporting paths only."""
    response = table.scan()
    items = list(response.get("Items", []))
    while "LastEvaluatedKey" in response:
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
        items.extend(response.get("Items", []))
    return items


def key_table_definition(table_name: str, key: str) -> Dict[str, Any]:
    """create_table arguments for a table keyed by one string attribute."""
    return {
        "TableName": table_name,
        "KeySchema": [{"AttributeName": key, "KeyType": "HASH"}],
        "AttributeDefinitions": [{"AttributeName": key, "AttributeType": "S"}],
        "BillingMode": "PAY_PER_REQUEST",
    }


def conditional_failed(exc: Exception) -> bool:
    code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
    return code == "ConditionalCheckFailedException" or "ConditionalCheckFailed" in str(exc)
