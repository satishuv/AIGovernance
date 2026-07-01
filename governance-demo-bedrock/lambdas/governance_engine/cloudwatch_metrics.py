"""CloudWatch Metrics Publisher module.

Publishes custom governance metrics to the AGCP/Governance CloudWatch namespace
at 1-minute granularity. Covers decision counts, latency, risk scores,
kill switch activations, and evidence write failures.

Requirements: 25.1, 25.2
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

NAMESPACE = "AGCP/Governance"
STORAGE_RESOLUTION = 60  # 1-minute granularity


class CloudWatchMetricsPublisher:
    """Publishes governance metrics to CloudWatch custom namespace."""

    def publish_decision_metric(self, verdict: str, cloudwatch_client) -> None:
        """Publish GovernanceDecisionCount metric with Verdict dimension.

        Args:
            verdict: The decision verdict (allow/deny/escalate).
            cloudwatch_client: boto3 CloudWatch client.
        """
        try:
            cloudwatch_client.put_metric_data(
                Namespace=NAMESPACE,
                MetricData=[
                    {
                        "MetricName": "GovernanceDecisionCount",
                        "Dimensions": [
                            {"Name": "Verdict", "Value": verdict},
                        ],
                        "Timestamp": datetime.now(timezone.utc),
                        "Value": 1,
                        "Unit": "Count",
                        "StorageResolution": STORAGE_RESOLUTION,
                    }
                ],
            )
        except Exception as exc:
            logger.error(json.dumps({
                "event": "publish_decision_metric_failed",
                "verdict": verdict,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

    def publish_latency_metric(
        self, latency_ms: float, cloudwatch_client
    ) -> None:
        """Publish PolicyEvalLatency metric in milliseconds.

        Args:
            latency_ms: Pipeline latency in milliseconds.
            cloudwatch_client: boto3 CloudWatch client.
        """
        try:
            cloudwatch_client.put_metric_data(
                Namespace=NAMESPACE,
                MetricData=[
                    {
                        "MetricName": "PolicyEvalLatency",
                        "Timestamp": datetime.now(timezone.utc),
                        "Value": latency_ms,
                        "Unit": "Milliseconds",
                        "StorageResolution": STORAGE_RESOLUTION,
                    }
                ],
            )
        except Exception as exc:
            logger.error(json.dumps({
                "event": "publish_latency_metric_failed",
                "latency_ms": latency_ms,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

    def publish_risk_score_metric(
        self, risk_score: float, cloudwatch_client
    ) -> None:
        """Publish AverageRiskScore metric.

        Args:
            risk_score: The risk score value (0-100).
            cloudwatch_client: boto3 CloudWatch client.
        """
        try:
            cloudwatch_client.put_metric_data(
                Namespace=NAMESPACE,
                MetricData=[
                    {
                        "MetricName": "AverageRiskScore",
                        "Timestamp": datetime.now(timezone.utc),
                        "Value": risk_score,
                        "Unit": "None",
                        "StorageResolution": STORAGE_RESOLUTION,
                    }
                ],
            )
        except Exception as exc:
            logger.error(json.dumps({
                "event": "publish_risk_score_metric_failed",
                "risk_score": risk_score,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

    def publish_kill_switch_metric(self, cloudwatch_client) -> None:
        """Publish KillSwitchActivationCount metric (value=1).

        Args:
            cloudwatch_client: boto3 CloudWatch client.
        """
        try:
            cloudwatch_client.put_metric_data(
                Namespace=NAMESPACE,
                MetricData=[
                    {
                        "MetricName": "KillSwitchActivationCount",
                        "Timestamp": datetime.now(timezone.utc),
                        "Value": 1,
                        "Unit": "Count",
                        "StorageResolution": STORAGE_RESOLUTION,
                    }
                ],
            )
        except Exception as exc:
            logger.error(json.dumps({
                "event": "publish_kill_switch_metric_failed",
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

    def publish_evidence_failure_metric(self, cloudwatch_client) -> None:
        """Publish EvidenceWriteFailureCount metric (value=1).

        Args:
            cloudwatch_client: boto3 CloudWatch client.
        """
        try:
            cloudwatch_client.put_metric_data(
                Namespace=NAMESPACE,
                MetricData=[
                    {
                        "MetricName": "EvidenceWriteFailureCount",
                        "Timestamp": datetime.now(timezone.utc),
                        "Value": 1,
                        "Unit": "Count",
                        "StorageResolution": STORAGE_RESOLUTION,
                    }
                ],
            )
        except Exception as exc:
            logger.error(json.dumps({
                "event": "publish_evidence_failure_metric_failed",
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
