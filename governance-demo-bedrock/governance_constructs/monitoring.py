from aws_cdk import (
    Duration,
    RemovalPolicy,
    aws_s3 as s3,
    aws_cloudtrail as cloudtrail,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
)
from constructs import Construct


class MonitoringConstruct(Construct):
    """CloudWatch dashboard, alarms, and CloudTrail."""

    def __init__(
        self, scope: Construct, construct_id: str, *, storage, skip_cloudtrail=False, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- CloudTrail (conditional) ---

        if not skip_cloudtrail:
            self.trail_bucket = s3.Bucket(
                self,
                "TrailBucket",
                encryption=s3.BucketEncryption.S3_MANAGED,
                block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
                removal_policy=RemovalPolicy.DESTROY,
                auto_delete_objects=True,
            )

            self.governance_trail = cloudtrail.Trail(
                self,
                "GovernanceTrail",
                bucket=self.trail_bucket,
                trail_name="governance-demo-bedrock-trail",
                is_multi_region_trail=False,
            )

            self.governance_trail.add_s3_event_selector(
                [cloudtrail.S3EventSelector(bucket=storage.data_bucket)],
                read_write_type=cloudtrail.ReadWriteType.ALL,
            )

        # --- CloudWatch Alarms ---

        self.policy_eval_latency_alarm = cloudwatch.Alarm(
            self,
            "PolicyEvalLatencyAlarm",
            alarm_name="AGCP-PolicyEvalLatencyAlarm",
            metric=cloudwatch.Metric(
                namespace="AGCP/Governance",
                metric_name="PolicyEvalLatency",
                statistic="Average",
                period=Duration.seconds(60),
            ),
            threshold=200,
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Policy evaluation latency exceeds 200ms",
        )
        self.policy_eval_latency_alarm.add_alarm_action(
            cw_actions.SnsAction(storage.operator_alerts_topic)
        )

        self.evidence_write_failure_alarm = cloudwatch.Alarm(
            self,
            "EvidenceWriteFailureAlarm",
            alarm_name="AGCP-EvidenceWriteFailureAlarm",
            metric=cloudwatch.Metric(
                namespace="AGCP/Governance",
                metric_name="EvidenceWriteFailureCount",
                statistic="Sum",
                period=Duration.seconds(60),
            ),
            threshold=1,
            evaluation_periods=5,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            alarm_description="Evidence write failure rate exceeds threshold",
        )
        self.evidence_write_failure_alarm.add_alarm_action(
            cw_actions.SnsAction(storage.operator_alerts_topic)
        )

        self.kill_switch_activation_alarm = cloudwatch.Alarm(
            self,
            "KillSwitchActivationAlarm",
            alarm_name="AGCP-KillSwitchActivationAlarm",
            metric=cloudwatch.Metric(
                namespace="AGCP/Governance",
                metric_name="KillSwitchActivationCount",
                statistic="Sum",
                period=Duration.seconds(60),
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
            alarm_description="Kill switch has been activated",
        )
        self.kill_switch_activation_alarm.add_alarm_action(
            cw_actions.SnsAction(storage.operator_alerts_topic)
        )

        # --- CloudWatch Dashboard ---

        self.governance_dashboard = cloudwatch.Dashboard(
            self,
            "GovernanceDashboard",
            dashboard_name="AIGovernance-Monitoring",
        )

        self.governance_dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Governance Verdicts (5min)",
                left=[
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="DecisionCount",
                        dimensions_map={"Verdict": "allow"},
                        statistic="Sum",
                        period=Duration.minutes(5),
                        label="ALLOW",
                        color="#2ca02c",
                    ),
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="DecisionCount",
                        dimensions_map={"Verdict": "deny"},
                        statistic="Sum",
                        period=Duration.minutes(5),
                        label="DENY",
                        color="#d62728",
                    ),
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="DecisionCount",
                        dimensions_map={"Verdict": "escalate"},
                        statistic="Sum",
                        period=Duration.minutes(5),
                        label="ESCALATE",
                        color="#ff7f0e",
                    ),
                ],
                width=12,
            ),
            cloudwatch.GraphWidget(
                title="Risk Score Distribution (5min)",
                left=[
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="RiskScore",
                        statistic="Average",
                        period=Duration.minutes(5),
                        label="Average Risk",
                        color="#1f77b4",
                    ),
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="RiskScore",
                        statistic="Maximum",
                        period=Duration.minutes(5),
                        label="Max Risk",
                        color="#d62728",
                    ),
                ],
                width=12,
            ),
        )

        self.governance_dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Security Blocks by Layer",
                left=[
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="SecurityBlock",
                        dimensions_map={"Layer": "input_sanitizer"},
                        statistic="Sum",
                        period=Duration.minutes(5),
                        label="Input Sanitizer",
                    ),
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="SecurityBlock",
                        dimensions_map={"Layer": "threat_detector"},
                        statistic="Sum",
                        period=Duration.minutes(5),
                        label="Threat Detector",
                    ),
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="SecurityBlock",
                        dimensions_map={"Layer": "tool_auth"},
                        statistic="Sum",
                        period=Duration.minutes(5),
                        label="Tool Auth",
                    ),
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="SecurityBlock",
                        dimensions_map={"Layer": "scope_enforcement"},
                        statistic="Sum",
                        period=Duration.minutes(5),
                        label="Scope Enforcement",
                    ),
                ],
                width=12,
            ),
            cloudwatch.GraphWidget(
                title="Agent Health Score",
                left=[
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="AgentHealthScore",
                        dimensions_map={"AgentId": "demo-agent"},
                        statistic="Average",
                        period=Duration.minutes(5),
                        label="Health (0-100)",
                        color="#2ca02c",
                    ),
                ],
                left_y_axis=cloudwatch.YAxisProps(min=0, max=100),
                width=12,
            ),
        )

        self.governance_dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Governance Pipeline Latency (ms)",
                left=[
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="PipelineLatency",
                        statistic="Average",
                        period=Duration.minutes(5),
                        label="Avg Latency",
                        color="#1f77b4",
                    ),
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="PipelineLatency",
                        statistic="p99",
                        period=Duration.minutes(5),
                        label="p99 Latency",
                        color="#d62728",
                    ),
                ],
                width=12,
            ),
            cloudwatch.GraphWidget(
                title="Runtime Drift Score",
                left=[
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="DriftScore",
                        dimensions_map={"AgentId": "demo-agent"},
                        statistic="Maximum",
                        period=Duration.minutes(5),
                        label="Drift (0-100)",
                        color="#ff7f0e",
                    ),
                ],
                left_y_axis=cloudwatch.YAxisProps(min=0, max=100),
                width=12,
            ),
        )

        self.governance_dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="OPA Policy Evaluation Time (ms)",
                left=[
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="PolicyEvalTime",
                        statistic="Average",
                        period=Duration.minutes(5),
                        label="Avg Eval Time",
                    ),
                ],
                width=8,
            ),
            cloudwatch.SingleValueWidget(
                title="Kill Switch Status",
                metrics=[
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="KillSwitchActive",
                        statistic="Maximum",
                        period=Duration.minutes(1),
                    ),
                ],
                width=4,
            ),
            cloudwatch.SingleValueWidget(
                title="Total Decisions (24h)",
                metrics=[
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="DecisionCount",
                        statistic="Sum",
                        period=Duration.hours(24),
                    ),
                ],
                width=4,
            ),
            cloudwatch.SingleValueWidget(
                title="Denial Rate (24h)",
                metrics=[
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="DenialRate",
                        statistic="Average",
                        period=Duration.hours(24),
                    ),
                ],
                width=4,
            ),
            cloudwatch.SingleValueWidget(
                title="Evidence Records (24h)",
                metrics=[
                    cloudwatch.Metric(
                        namespace="AGCP/Governance",
                        metric_name="EvidenceWriteCount",
                        statistic="Sum",
                        period=Duration.hours(24),
                    ),
                ],
                width=4,
            ),
        )
