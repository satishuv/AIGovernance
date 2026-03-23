"""Agent Lambda handler.

Invokes Amazon Bedrock for reasoning, performs S3 operations within the
current permission boundary, and logs every action to CloudWatch in
structured JSON format.

Environment variables (set by CDK):
    DATA_BUCKET_NAME  – S3 bucket the agent reads from / writes to
    AGENT_ID          – logical agent identifier (default: "demo-agent")
    BEDROCK_MODEL_ID  – Bedrock model to invoke (default: Claude 3 Haiku)
"""

import json
import os
import datetime
import boto3


# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
DATA_BUCKET_NAME = os.environ.get("DATA_BUCKET_NAME", "")
AGENT_ID = os.environ.get("AGENT_ID", "demo-agent")
BEDROCK_MODEL_ID = os.environ.get(
    "BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0"
)

# ---------------------------------------------------------------------------
# AWS clients (created once per container)
# ---------------------------------------------------------------------------
bedrock_client = boto3.client("bedrock-runtime")
s3_client = boto3.client("s3")


def _log_action(action_type: str, target_resource: str, scope_level: int, outcome: str) -> None:
    """Emit a structured JSON log entry to CloudWatch via *print*."""
    entry = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "agent_id": AGENT_ID,
        "action_type": action_type,
        "target_resource": target_resource,
        "scope_level": scope_level,
        "outcome": outcome,
    }
    # print() goes to CloudWatch Logs automatically in Lambda
    print(json.dumps(entry))


def _invoke_bedrock(action: str, target_resource: str, payload: dict) -> str:
    """Call Bedrock with a prompt built from the request context.

    Returns the model's text response.
    Raises on any Bedrock / network error – caller is responsible for
    catching and logging.
    """
    prompt = (
        f"You are a deployment assistant. "
        f"Action requested: {action}. "
        f"Target resource: {target_resource}. "
        f"Payload: {json.dumps(payload)}. "
        f"Provide a concise response."
    )

    body = json.dumps(
        {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 256,
            "messages": [{"role": "user", "content": prompt}],
        }
    )

    response = bedrock_client.invoke_model(
        modelId=BEDROCK_MODEL_ID,
        contentType="application/json",
        accept="application/json",
        body=body,
    )

    response_body = json.loads(response["body"].read())
    return response_body.get("content", [{}])[0].get("text", "")


def _perform_s3_read(target_resource: str) -> dict:
    """Read an object from the Data Bucket and return its content."""
    resp = s3_client.get_object(Bucket=DATA_BUCKET_NAME, Key=target_resource)
    content = resp["Body"].read().decode("utf-8")
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {"raw": content}


def _perform_s3_write(target_resource: str, payload: dict) -> dict:
    """Write *payload* as JSON to the Data Bucket."""
    s3_client.put_object(
        Bucket=DATA_BUCKET_NAME,
        Key=target_resource,
        Body=json.dumps(payload).encode("utf-8"),
        ContentType="application/json",
    )
    return {"written_key": target_resource}


def handler(event, context):
    """Lambda entry point.

    Expected *event* shape::

        {
            "action": "s3:GetObject" | "s3:PutObject",
            "target_resource": "<S3 key>",
            "payload": { ... },
            "scope_level": 1-4
        }

    Returns::

        { "status": "success", "result": { ... } }
        { "error": "<category>", "reason": "<detail>" }
    """
    action = event.get("action", "")
    target_resource = event.get("target_resource", "")
    payload = event.get("payload", {})
    scope_level = event.get("scope_level", 1)

    # --- Step 1: Invoke Bedrock for reasoning ---
    try:
        bedrock_response = _invoke_bedrock(action, target_resource, payload)
    except Exception as exc:
        _log_action(action, target_resource, scope_level, "bedrock_failure")
        return {
            "error": "bedrock_failure",
            "reason": str(exc),
        }

    # --- Step 2: Perform the S3 operation ---
    try:
        if action == "s3:GetObject":
            result = _perform_s3_read(target_resource)
        elif action == "s3:PutObject":
            result = _perform_s3_write(target_resource, payload)
        else:
            _log_action(action, target_resource, scope_level, "unsupported_action")
            return {
                "error": "unsupported_action",
                "reason": f"Action '{action}' is not supported",
            }
    except Exception as exc:
        _log_action(action, target_resource, scope_level, "s3_failure")
        return {
            "error": "s3_failure",
            "reason": str(exc),
        }

    # --- Step 3: Log success and return ---
    _log_action(action, target_resource, scope_level, "success")

    return {
        "status": "success",
        "result": {
            "bedrock_response": bedrock_response,
            "data": result,
        },
    }
