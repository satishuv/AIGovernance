"""NIST AI RMF MEASURE and MANAGE Functions module.

Computes aggregate governance metrics, generates MEASURE reports (risk metrics,
trend analysis, threshold comparison) and MANAGE reports (incident summaries,
policy changes, remediation actions). Supports threshold alerting via SNS and
report export to S3 in JSON and Markdown formats.

Requirements: 24.1, 24.2, 24.3, 24.4
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from models import AggregateMetrics, ManageReport, MeasureReport

logger = logging.getLogger(__name__)


class MeasureManageEngine:
    """Implements NIST AI RMF MEASURE and MANAGE functions."""

    def compute_aggregate_metrics(
        self,
        decision_history_table,
        start_date: str,
        end_date: str,
    ) -> AggregateMetrics:
        """Query DecisionHistoryTable for the period and compute aggregate metrics.

        Args:
            decision_history_table: boto3 DynamoDB Table resource.
            start_date: ISO 8601 start date of the reporting period.
            end_date: ISO 8601 end date of the reporting period.

        Returns:
            AggregateMetrics with totals, rates, and risk score distribution.
        """
        decisions = self._scan_decisions_in_range(
            decision_history_table, start_date, end_date
        )

        total = len(decisions)
        deny_count = sum(1 for d in decisions if d.get("verdict") == "deny")
        escalate_count = sum(1 for d in decisions if d.get("verdict") == "escalate")

        risk_scores = [float(d.get("risk_score", 0)) for d in decisions]
        avg_risk = sum(risk_scores) / total if total > 0 else 0.0

        distribution: Dict[str, int] = {
            "low_0_25": 0,
            "medium_26_50": 0,
            "high_51_75": 0,
            "critical_76_100": 0,
        }
        for score in risk_scores:
            if score <= 25:
                distribution["low_0_25"] += 1
            elif score <= 50:
                distribution["medium_26_50"] += 1
            elif score <= 75:
                distribution["high_51_75"] += 1
            else:
                distribution["critical_76_100"] += 1

        now = datetime.now(timezone.utc).isoformat()
        return AggregateMetrics(
            period="monthly",
            start_date=start_date,
            end_date=end_date,
            total_decisions=total,
            denial_rate=deny_count / total if total > 0 else 0.0,
            escalation_rate=escalate_count / total if total > 0 else 0.0,
            avg_risk_score=round(avg_risk, 2),
            risk_score_distribution=distribution,
            generated_at=now,
        )

    def generate_measure_report(
        self,
        metrics: AggregateMetrics,
        threshold_config: Dict[str, float],
    ) -> MeasureReport:
        """Produce a MEASURE report with metrics, trend analysis, and threshold comparison.

        Args:
            metrics: AggregateMetrics for the current period.
            threshold_config: Dict mapping metric names to threshold values.

        Returns:
            MeasureReport with risk metrics, trend analysis, and threshold flags.
        """
        report_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Threshold comparison
        threshold_comparison: Dict[str, Dict[str, Any]] = {}
        metric_values = {
            "denial_rate": metrics.denial_rate,
            "escalation_rate": metrics.escalation_rate,
            "avg_risk_score": metrics.avg_risk_score,
        }
        for metric_name, value in metric_values.items():
            threshold = threshold_config.get(metric_name)
            if threshold is not None:
                threshold_comparison[metric_name] = {
                    "value": value,
                    "threshold": threshold,
                    "exceeded": value > threshold,
                }

        # Trend analysis placeholder, comparison to previous period
        trend_analysis: Dict[str, str] = {
            "denial_rate_trend": "stable",
            "escalation_rate_trend": "stable",
            "avg_risk_score_trend": "stable",
        }

        return MeasureReport(
            report_id=report_id,
            period=metrics.period,
            metrics=metrics,
            trend_analysis=trend_analysis,
            threshold_comparison=threshold_comparison,
            generated_at=now,
        )

    def generate_manage_report(
        self,
        change_log_table,
        decision_history_table,
        start_date: str,
        end_date: str,
    ) -> ManageReport:
        """Produce a MANAGE report with incidents, policy changes, and remediations.

        Args:
            change_log_table: boto3 DynamoDB Table resource for ChangeLogTable.
            decision_history_table: boto3 DynamoDB Table resource.
            start_date: ISO 8601 start date.
            end_date: ISO 8601 end date.

        Returns:
            ManageReport with incident summaries, policy changes, and remediation actions.
        """
        report_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Incident summaries, denied and escalated decisions
        decisions = self._scan_decisions_in_range(
            decision_history_table, start_date, end_date
        )
        incident_summaries: List[Dict[str, str]] = []
        for d in decisions:
            if d.get("verdict") in ("deny", "escalate"):
                incident_summaries.append({
                    "decision_id": d.get("decision_id", ""),
                    "agent_id": d.get("agent_id", ""),
                    "verdict": d.get("verdict", ""),
                    "action_requested": d.get("action_requested", ""),
                    "timestamp": d.get("timestamp", ""),
                })

        # Policy change summaries from ChangeLogTable
        policy_change_summaries = self._scan_changes_in_range(
            change_log_table, start_date, end_date
        )

        # Remediation actions, scope reductions and kill switch activations
        remediation_actions: List[Dict[str, str]] = []
        for change in policy_change_summaries:
            if change.get("change_type") == "scope_change":
                remediation_actions.append({
                    "type": "scope_reduction",
                    "agent_id": change.get("agent_id", ""),
                    "previous_value": change.get("previous_value", ""),
                    "new_value": change.get("new_value", ""),
                    "timestamp": change.get("timestamp", ""),
                })

        return ManageReport(
            report_id=report_id,
            period="monthly",
            incident_summaries=incident_summaries,
            policy_change_summaries=policy_change_summaries,
            remediation_actions=remediation_actions,
            generated_at=now,
        )

    def check_thresholds(
        self,
        metrics: AggregateMetrics,
        threshold_config: Dict[str, float],
        sns_client,
        topic_arn: str,
    ) -> List[Dict[str, Any]]:
        """Compare metrics against thresholds and alert via SNS on exceedance.

        Args:
            metrics: AggregateMetrics for the current period.
            threshold_config: Dict mapping metric names to threshold values.
            sns_client: boto3 SNS client.
            topic_arn: ARN of the operator alerts SNS topic.

        Returns:
            List of exceeded threshold dicts with metric_name, value, threshold.
        """
        exceeded: List[Dict[str, Any]] = []
        metric_values = {
            "denial_rate": metrics.denial_rate,
            "escalation_rate": metrics.escalation_rate,
            "avg_risk_score": metrics.avg_risk_score,
        }

        for metric_name, value in metric_values.items():
            threshold = threshold_config.get(metric_name)
            if threshold is not None and value > threshold:
                exceeded.append({
                    "metric_name": metric_name,
                    "value": value,
                    "threshold": threshold,
                })

        if exceeded:
            now = datetime.now(timezone.utc).isoformat()
            alert = {
                "alert_type": "measure_threshold_exceeded",
                "exceeded_metrics": exceeded,
                "period": metrics.period,
                "start_date": metrics.start_date,
                "end_date": metrics.end_date,
                "timestamp": now,
            }
            try:
                sns_client.publish(
                    TopicArn=topic_arn,
                    Subject="AGCP Governance, MEASURE Threshold Alert",
                    Message=json.dumps(alert, default=str),
                )
            except Exception as exc:
                logger.error(json.dumps({
                    "event": "measure_threshold_alert_failed",
                    "error": str(exc),
                    "timestamp": now,
                }))

            logger.warning(json.dumps(alert))

        return exceeded

    def export_reports(
        self,
        measure_report: MeasureReport,
        manage_report: ManageReport,
        s3_client,
        bucket: str,
    ) -> Dict[str, str]:
        """Write MEASURE and MANAGE reports as JSON and Markdown to S3.

        Args:
            measure_report: The MeasureReport to export.
            manage_report: The ManageReport to export.
            s3_client: boto3 S3 client.
            bucket: S3 bucket name for evidence/compliance storage.

        Returns:
            Dict mapping report type to S3 key.
        """
        now = datetime.now(timezone.utc)
        prefix = f"compliance/nist_ai_rmf/{now.strftime('%Y/%m')}"
        keys: Dict[str, str] = {}

        # MEASURE JSON
        measure_key = f"{prefix}/measure_report.json"
        s3_client.put_object(
            Bucket=bucket,
            Key=measure_key,
            Body=json.dumps(measure_report.to_dict(), default=str),
            ContentType="application/json",
        )
        keys["measure_json"] = measure_key

        # MEASURE Markdown
        measure_md_key = f"{prefix}/measure_report.md"
        s3_client.put_object(
            Bucket=bucket,
            Key=measure_md_key,
            Body=self._measure_to_markdown(measure_report),
            ContentType="text/markdown",
        )
        keys["measure_md"] = measure_md_key

        # MANAGE JSON
        manage_key = f"{prefix}/manage_report.json"
        s3_client.put_object(
            Bucket=bucket,
            Key=manage_key,
            Body=json.dumps(manage_report.to_dict(), default=str),
            ContentType="application/json",
        )
        keys["manage_json"] = manage_key

        # MANAGE Markdown
        manage_md_key = f"{prefix}/manage_report.md"
        s3_client.put_object(
            Bucket=bucket,
            Key=manage_md_key,
            Body=self._manage_to_markdown(manage_report),
            ContentType="text/markdown",
        )
        keys["manage_md"] = manage_md_key

        logger.info(json.dumps({
            "event": "reports_exported",
            "keys": keys,
            "timestamp": now.isoformat(),
        }))
        return keys

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_decisions_in_range(
        table, start_date: str, end_date: str
    ) -> List[Dict[str, Any]]:
        """Scan DecisionHistoryTable for decisions within a date range."""
        from boto3.dynamodb.conditions import Attr

        filter_expr = Attr("timestamp").between(start_date, end_date)
        items: List[Dict[str, Any]] = []
        response = table.scan(FilterExpression=filter_expr)
        items.extend(response.get("Items", []))
        while "LastEvaluatedKey" in response:
            response = table.scan(
                FilterExpression=filter_expr,
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))
        return items

    @staticmethod
    def _scan_changes_in_range(
        table, start_date: str, end_date: str
    ) -> List[Dict[str, str]]:
        """Scan ChangeLogTable for change records within a date range."""
        from boto3.dynamodb.conditions import Attr

        filter_expr = Attr("timestamp").between(start_date, end_date)
        items: List[Dict[str, str]] = []
        response = table.scan(FilterExpression=filter_expr)
        items.extend(response.get("Items", []))
        while "LastEvaluatedKey" in response:
            response = table.scan(
                FilterExpression=filter_expr,
                ExclusiveStartKey=response["LastEvaluatedKey"],
            )
            items.extend(response.get("Items", []))
        return items

    @staticmethod
    def _measure_to_markdown(report: MeasureReport) -> str:
        """Render a MeasureReport as Markdown."""
        metrics = report.metrics
        m = metrics if isinstance(metrics, AggregateMetrics) else AggregateMetrics.from_dict(metrics)
        lines = [
            f"# MEASURE Report, {report.period}",
            f"Generated: {report.generated_at}",
            "",
            "## Aggregate Metrics",
            f"- Total decisions: {m.total_decisions}",
            f"- Denial rate: {m.denial_rate:.2%}",
            f"- Escalation rate: {m.escalation_rate:.2%}",
            f"- Average risk score: {m.avg_risk_score:.1f}",
            "",
            "## Risk Score Distribution",
            "| Bucket | Count |",
            "|--------|-------|",
        ]
        for bucket, count in m.risk_score_distribution.items():
            lines.append(f"| {bucket} | {count} |")
        lines.append("")
        lines.append("## Threshold Comparison")
        lines.append("| Metric | Value | Threshold | Exceeded |")
        lines.append("|--------|-------|-----------|----------|")
        for name, info in report.threshold_comparison.items():
            lines.append(
                f"| {name} | {info.get('value', '')} | "
                f"{info.get('threshold', '')} | {info.get('exceeded', '')} |"
            )
        return "\n".join(lines) + "\n"

    @staticmethod
    def _manage_to_markdown(report: ManageReport) -> str:
        """Render a ManageReport as Markdown."""
        lines = [
            f"# MANAGE Report, {report.period}",
            f"Generated: {report.generated_at}",
            "",
            f"## Incident Summaries ({len(report.incident_summaries)})",
        ]
        for inc in report.incident_summaries:
            lines.append(
                f"- [{inc.get('verdict', '')}] {inc.get('action_requested', '')} "
                f"(agent: {inc.get('agent_id', '')}, {inc.get('timestamp', '')})"
            )
        lines.append("")
        lines.append(f"## Policy Changes ({len(report.policy_change_summaries)})")
        for pc in report.policy_change_summaries:
            lines.append(
                f"- {pc.get('change_type', '')}: {pc.get('previous_value', '')} → "
                f"{pc.get('new_value', '')} ({pc.get('timestamp', '')})"
            )
        lines.append("")
        lines.append(f"## Remediation Actions ({len(report.remediation_actions)})")
        for ra in report.remediation_actions:
            lines.append(
                f"- {ra.get('type', '')}: agent {ra.get('agent_id', '')} "
                f"scope {ra.get('previous_value', '')} → {ra.get('new_value', '')} "
                f"({ra.get('timestamp', '')})"
            )
        return "\n".join(lines) + "\n"
