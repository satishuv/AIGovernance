"""Shared helpers for delegated-authority tests (moto-backed, no real AWS)."""

import contextlib
import os
import sys
from unittest.mock import patch

GE = os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine")
if GE not in sys.path:
    sys.path.insert(0, GE)

REGION = "ca-central-1"
FAKE_ENV = {"AWS_ACCESS_KEY_ID": "testing", "AWS_SECRET_ACCESS_KEY": "testing",
            "AWS_SECURITY_TOKEN": "testing", "AWS_SESSION_TOKEN": "testing",
            "AWS_DEFAULT_REGION": REGION}


@contextlib.contextmanager
def offline_demo(aws_mode: str = "mock"):
    import boto3
    from moto import mock_aws

    from authority_factory import build_offline

    with patch.dict(os.environ, FAKE_ENV), mock_aws():
        yield build_offline(
            dynamodb=boto3.resource("dynamodb", region_name=REGION),
            s3=boto3.client("s3", region_name=REGION),
            kms=boto3.client("kms", region_name=REGION),
            sts=boto3.client("sts", region_name=REGION),
            region=REGION, aws_mode=aws_mode)


def purchase(item="productivity-suite", quantity=4, amount=168, session="s-1", **overrides):
    req = {
        "agent_id": "procurement-agent", "session_id": session, "provider": "servicenow",
        "operation_id": "Subscription.Purchase",
        "target_resource": f"catalog/software/approved/{item}", "environment": "prod",
        "tool_parameters": {"catalog_item_id": item, "quantity": quantity, "cost_centre": "CC-1234"},
        "financial_context": {"currency": "CAD", "transaction_amount": amount},
        "business_reason": "seats for the new intake team",
    }
    req.update(overrides)
    return req


def governance(agent_id, operation_id, target, params=None, session="g-1"):
    return {"agent_id": agent_id, "session_id": session, "provider": "governance",
            "operation_id": operation_id, "target_resource": target, "environment": "prod",
            "tool_parameters": params or {}}


def stage(response, name):
    return next(s for s in response["stages"] if s["stage"] == name)


def serialize_conditional_writes(table):
    """Model DynamoDB's guarantee that conditional writes to an item are atomic.

    Real DynamoDB evaluates a ConditionExpression and applies the write as one
    atomic step per item. moto runs each call in the caller's thread without
    that serialization, so concurrent conditional writes can interleave inside
    the emulator and a race test could pass or fail by timing alone. Wrapping
    the table's write methods in a lock reproduces the DynamoDB guarantee, so
    concurrency tests check OUR logic (that only the writes allowed by the
    conditions succeed), deterministically.
    """
    import threading
    lock = threading.Lock()
    for name in ("update_item", "put_item"):
        original = getattr(table, name)

        def locked(*args, _original=original, **kwargs):
            with lock:
                return _original(*args, **kwargs)

        setattr(table, name, locked)
    return table
