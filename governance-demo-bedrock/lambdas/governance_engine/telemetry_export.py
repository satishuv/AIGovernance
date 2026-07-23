"""OpenTelemetry export of governance decisions (AARM R8).

AARM R8 requires exporting action telemetry in a standard, interoperable
format (e.g. OpenTelemetry) suitable for SIEM/observability ingestion, and the
R8 test requires DEFER events to appear with correct schema.

This module formats each decision as an OTLP-JSON LogRecord (the OTLP/HTTP JSON
encoding) using only the standard library, so no heavy opentelemetry SDK is
added to the Lambda bundle. The record is emitted to a dedicated logger whose
CloudWatch log group is scraped by an OTel/ADOT collector or SIEM. A live OTLP
transport can be layered later via an ADOT layer without changing this schema.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict

from verdicts import to_aarm

# Dedicated logger; its CloudWatch log group is the OTel/SIEM scrape target.
_otel_logger = logging.getLogger("aarm.otel")
_otel_logger.setLevel(logging.INFO)

SERVICE_NAME = os.environ.get("OTEL_SERVICE_NAME", "aarm-governance-engine")
SCHEMA_URL = "https://opentelemetry.io/schemas/1.27.0"


def _epoch_nanos(iso_ts: str) -> str:
    """Convert an ISO 8601 timestamp to OTLP epoch-nanoseconds (string)."""
    try:
        dt = datetime.fromisoformat(iso_ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return str(int(dt.timestamp() * 1_000_000_000))
    except Exception:
        return "0"


def _attr(key: str, value: Any) -> Dict[str, Any]:
    """Build one OTLP KeyValue attribute with the right value type."""
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": value}}
    if isinstance(value, float):
        return {"key": key, "value": {"doubleValue": value}}
    return {"key": key, "value": {"stringValue": str(value)}}


def build_otlp_log_record(decision: Dict[str, Any]) -> Dict[str, Any]:
    """Build an OTLP/JSON logs payload for a governance decision.

    Maps the internal verdict to its AARM decision name (escalate -> STEP_UP)
    and includes DEFER events with full schema, satisfying the R8 test.
    """
    verdict = decision.get("verdict", "")
    aarm_decision = to_aarm(verdict)
    ts_nanos = _epoch_nanos(decision.get("timestamp", ""))

    attributes = [
        _attr("aarm.decision", aarm_decision),
        _attr("governance.verdict", verdict),
        _attr("governance.decision_id", decision.get("decision_id", "")),
        _attr("governance.agent_id", decision.get("agent_id", "")),
        _attr("governance.action_requested", decision.get("action_requested", "")),
        _attr("governance.risk_score", float(decision.get("risk_score", 0) or 0)),
        _attr("session.id", decision.get("session_id", "")),
    ]

    log_record = {
        "timeUnixNano": ts_nanos,
        "severityText": "INFO",
        "body": {"stringValue": f"governance decision {aarm_decision}"},
        "attributes": attributes,
    }

    return {
        "resourceLogs": [
            {
                "resource": {
                    "attributes": [_attr("service.name", SERVICE_NAME)],
                },
                "scopeLogs": [
                    {
                        "scope": {"name": "aarm.governance", "version": "1.0"},
                        "logRecords": [log_record],
                        "schemaUrl": SCHEMA_URL,
                    }
                ],
            }
        ]
    }


def export_decision(decision: Dict[str, Any]) -> None:
    """Emit a decision as an OTLP-JSON record. Never raises.

    Non-blocking best-effort, mirroring the existing CloudWatch metric
    publishing pattern: telemetry export must not affect the decision path.
    """
    try:
        payload = build_otlp_log_record(decision)
        _otel_logger.info(json.dumps(payload))
    except Exception:
        pass
