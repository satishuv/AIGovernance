"""Governance Engine Lambda handler - thin entrypoint.

Routes events to either the API Gateway router or the governance pipeline
orchestrator. All business logic lives in pipeline_orchestrator.py and
api_router.py.
"""

import json
import logging
from decimal import Decimal
from typing import Any, Dict

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class DecimalEncoder(json.JSONEncoder):
    """Handle Decimal types from DynamoDB in JSON serialization."""
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o) if o % 1 else int(o)
        return super().default(o)


# Monkey-patch the default JSON encoder so ALL json.dumps calls across
# all governance engine modules handle DynamoDB Decimal values automatically.
_original_default = json.JSONEncoder.default


def _patched_default(self, o):
    if isinstance(o, Decimal):
        return float(o) if o % 1 else int(o)
    return _original_default(self, o)


json.JSONEncoder.default = _patched_default


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point - routes to API handler or pipeline orchestrator."""
    if "httpMethod" in event and "resource" in event:
        from api_router import handle_api_gateway_event
        return handle_api_gateway_event(event, context)

    from pipeline_orchestrator import run_pipeline
    return run_pipeline(event, context)
