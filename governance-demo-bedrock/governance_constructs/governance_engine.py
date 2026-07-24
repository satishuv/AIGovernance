import json
import os

from aws_cdk import (
    Duration,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_stepfunctions as sfn,
    aws_events as events,
    aws_events_targets as targets,
    custom_resources as cr,
)
from constructs import Construct


class GovernanceEngineConstruct(Construct):
    """Governance Engine Lambda, Step Functions pipeline, EventBridge rules."""

    def __init__(
        self, scope: Construct, construct_id: str, *, storage, bedrock_agent, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        stack = scope
        stack_dir = os.path.dirname(os.path.dirname(__file__))

        # --- Main Governance Engine Lambda ---

        self.governance_engine_lambda = _lambda.Function(
            self,
            "GovernanceEngineLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                os.path.join(stack_dir, "lambdas", "governance_engine")
            ),
            timeout=Duration.seconds(30),
            memory_size=256,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "POLICY_BUCKET_NAME": storage.policy_bucket.bucket_name,
                "POLICY_PREFIX": "policies/",
                "POLICY_METADATA_TABLE_NAME": storage.policy_metadata_table.table_name,
                "RISK_CONFIG_TABLE_NAME": storage.risk_config_table.table_name,
                "FRAMEWORK_MAPPING_TABLE_NAME": storage.framework_mapping_table.table_name,
                "EVIDENCE_BUCKET_NAME": storage.evidence_bucket.bucket_name,
                "OPERATOR_SNS_TOPIC_ARN": storage.operator_alerts_topic.topic_arn,
                "SCOPE_TABLE_NAME": storage.scope_table.table_name,
                "AGENT_REGISTRY_TABLE_NAME": storage.agent_registry_table.table_name,
                "TOOL_MODEL_REGISTRY_TABLE_NAME": storage.tool_model_registry_table.table_name,
                "GOVERNANCE_ROLES_TABLE_NAME": storage.governance_roles_table.table_name,
                "CONTROL_TRACE_TABLE_NAME": storage.control_trace_table.table_name,
                "THREAT_PATTERNS_TABLE_NAME": storage.threat_patterns_table.table_name,
                "CONTROL_MAPPING_TABLE_NAME": storage.control_mapping_table.table_name,
                "IMMUTABLE_EVIDENCE_BUCKET_NAME": storage.immutable_evidence_bucket.bucket_name,
                "PENDING_APPROVAL_TABLE_NAME": storage.pending_approval_table.table_name,
                "CHANGE_LOG_TABLE_NAME": storage.change_log_table.table_name,
                "DECISION_HISTORY_TABLE_NAME": storage.decision_history_table.table_name,
                "DENIAL_PATTERN_TABLE_NAME": storage.denial_pattern_table.table_name,
                "EXFILTRATION_ALLOWLIST_TABLE_NAME": storage.exfiltration_allowlist_table.table_name,
                "SCOPE_REDUCTION_HISTORY_TABLE_NAME": storage.scope_reduction_history_table.table_name,
                "MULTI_AGENT_CONFIG_TABLE_NAME": storage.multi_agent_config_table.table_name,
                "METRICS_THRESHOLD_TABLE_NAME": storage.metrics_threshold_table.table_name,
                "RUNTIME_DRIFT_TABLE_NAME": storage.runtime_drift_table.table_name,
                "AGENT_HEALTH_TABLE_NAME": storage.agent_health_table.table_name,
                "TOOL_AUTH_TABLE_NAME": storage.tool_auth_table.table_name,
                "OPA_MODE": "embedded",
                "OPA_ENDPOINT": "",
                "BEDROCK_GUARDRAIL_ID": "xilmtxfq02om",
                "BEDROCK_GUARDRAIL_VERSION": "DRAFT",
                "EVIDENCE_SIGNING_KEY_ID": storage.evidence_signing_key.key_id,
                "DECISION_TRACE_TABLE_NAME": storage.decision_trace_table.table_name,
            },
        )

        # Grant access to all tables
        storage.policy_bucket.grant_read(self.governance_engine_lambda)
        storage.evidence_bucket.grant_read_write(self.governance_engine_lambda)
        storage.scope_table.grant_read_write_data(self.governance_engine_lambda)
        storage.policy_metadata_table.grant_read_data(self.governance_engine_lambda)
        storage.risk_config_table.grant_read_data(self.governance_engine_lambda)
        storage.framework_mapping_table.grant_read_data(self.governance_engine_lambda)
        storage.operator_alerts_topic.grant_publish(self.governance_engine_lambda)
        storage.agent_registry_table.grant_read_write_data(self.governance_engine_lambda)
        storage.tool_model_registry_table.grant_read_write_data(self.governance_engine_lambda)
        storage.governance_roles_table.grant_read_write_data(self.governance_engine_lambda)
        storage.control_trace_table.grant_read_write_data(self.governance_engine_lambda)
        storage.threat_patterns_table.grant_read_write_data(self.governance_engine_lambda)
        storage.control_mapping_table.grant_read_write_data(self.governance_engine_lambda)
        storage.immutable_evidence_bucket.grant_read_write(self.governance_engine_lambda)
        storage.pending_approval_table.grant_read_write_data(self.governance_engine_lambda)
        storage.change_log_table.grant_read_write_data(self.governance_engine_lambda)
        storage.decision_history_table.grant_read_write_data(self.governance_engine_lambda)
        storage.denial_pattern_table.grant_read_write_data(self.governance_engine_lambda)
        storage.exfiltration_allowlist_table.grant_read_write_data(self.governance_engine_lambda)
        storage.scope_reduction_history_table.grant_read_write_data(self.governance_engine_lambda)
        storage.multi_agent_config_table.grant_read_write_data(self.governance_engine_lambda)
        storage.metrics_threshold_table.grant_read_write_data(self.governance_engine_lambda)
        storage.runtime_drift_table.grant_read_write_data(self.governance_engine_lambda)
        storage.agent_health_table.grant_read_write_data(self.governance_engine_lambda)
        storage.tool_auth_table.grant_read_write_data(self.governance_engine_lambda)

        # AARM R5/R6: allow the engine to sign evidence receipts.
        storage.evidence_signing_key.grant(self.governance_engine_lambda, "kms:Sign")
        # Auditor decision traces: write signed traces + serve GET /trace.
        storage.decision_trace_table.grant_read_write_data(self.governance_engine_lambda)

        self.governance_engine_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["bedrock:ApplyGuardrail"],
                resources=[f"arn:aws:bedrock:{stack.region}:{stack.account}:guardrail/*"],
            )
        )
        # cloudwatch:PutMetricData requires Resource: "*" per AWS IAM documentation.
        # This action does not support resource-level permissions. See:
        # https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazoncloudwatch.html
        self.governance_engine_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["cloudwatch:PutMetricData"],
                resources=["*"],
                conditions={"StringEquals": {"cloudwatch:namespace": "AGCP/Governance"}},
            )
        )

        # Wire scope enforcer to governance engine
        self.governance_engine_lambda.grant_invoke(bedrock_agent.scope_enforcer_lambda)
        bedrock_agent.scope_enforcer_lambda.add_environment(
            "GOVERNANCE_ENGINE_LAMBDA_ARN",
            self.governance_engine_lambda.function_arn,
        )

        # --- Kill Switch Phase 1c Lambda ---

        self.kill_switch_phase1c_lambda = _lambda.Function(
            self,
            "KillSwitchPhase1cLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="kill_switch.handler",
            code=_lambda.Code.from_asset(
                os.path.join(stack_dir, "lambdas", "governance_engine")
            ),
            timeout=Duration.seconds(30),
            memory_size=256,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "SCOPE_TABLE_NAME": storage.scope_table.table_name,
                "AGENT_REGISTRY_TABLE_NAME": storage.agent_registry_table.table_name,
                "GOVERNANCE_ROLES_TABLE_NAME": storage.governance_roles_table.table_name,
                "OPERATOR_SNS_TOPIC_ARN": storage.operator_alerts_topic.topic_arn,
            },
        )

        storage.scope_table.grant_read_write_data(self.kill_switch_phase1c_lambda)
        storage.agent_registry_table.grant_read_data(self.kill_switch_phase1c_lambda)
        storage.governance_roles_table.grant_read_data(self.kill_switch_phase1c_lambda)
        storage.operator_alerts_topic.grant_publish(self.kill_switch_phase1c_lambda)

        # --- Compliance Refresh Lambda ---

        self.compliance_refresh_lambda = _lambda.Function(
            self,
            "ComplianceRefreshLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="compliance_refresh.handler",
            code=_lambda.Code.from_asset(
                os.path.join(stack_dir, "lambdas", "governance_engine")
            ),
            timeout=Duration.seconds(30),
            memory_size=256,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "CONTROL_MAPPING_TABLE_NAME": storage.control_mapping_table.table_name,
                "EVIDENCE_BUCKET_NAME": storage.evidence_bucket.bucket_name,
                "IMMUTABLE_EVIDENCE_BUCKET_NAME": storage.immutable_evidence_bucket.bucket_name,
            },
        )

        storage.control_mapping_table.grant_read_data(self.compliance_refresh_lambda)
        storage.evidence_bucket.grant_read_write(self.compliance_refresh_lambda)
        storage.immutable_evidence_bucket.grant_read_write(self.compliance_refresh_lambda)

        self.compliance_refresh_trigger = cr.AwsCustomResource(
            self,
            "ComplianceRefreshTrigger",
            on_create=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": self.compliance_refresh_lambda.function_name,
                    "InvocationType": "RequestResponse",
                    "Payload": json.dumps({"trigger": "cdk_deployment"}),
                },
                physical_resource_id=cr.PhysicalResourceId.of(
                    "ComplianceRefreshTrigger"
                ),
            ),
            on_update=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": self.compliance_refresh_lambda.function_name,
                    "InvocationType": "RequestResponse",
                    "Payload": json.dumps({"trigger": "cdk_deployment_update"}),
                },
                physical_resource_id=cr.PhysicalResourceId.of(
                    "ComplianceRefreshTrigger"
                ),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["lambda:InvokeFunction"],
                    resources=[self.compliance_refresh_lambda.function_arn],
                ),
            ]),
        )

        # --- Step Functions Pipeline Lambdas ---

        self.input_defense_lambda = _lambda.Function(
            self,
            "InputDefenseLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler_input_defense.handler",
            code=_lambda.Code.from_asset(
                os.path.join(stack_dir, "lambdas", "governance_engine")
            ),
            timeout=Duration.seconds(30),
            memory_size=256,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "THREAT_PATTERNS_TABLE_NAME": storage.threat_patterns_table.table_name,
            },
        )
        storage.threat_patterns_table.grant_read_data(self.input_defense_lambda)

        self.authorization_lambda = _lambda.Function(
            self,
            "AuthorizationLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler_authorization.handler",
            code=_lambda.Code.from_asset(
                os.path.join(stack_dir, "lambdas", "governance_engine")
            ),
            timeout=Duration.seconds(30),
            memory_size=256,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "SCOPE_TABLE_NAME": storage.scope_table.table_name,
                "AGENT_REGISTRY_TABLE_NAME": storage.agent_registry_table.table_name,
                "TOOL_MODEL_REGISTRY_TABLE_NAME": storage.tool_model_registry_table.table_name,
                "TOOL_AUTH_TABLE_NAME": storage.tool_auth_table.table_name,
            },
        )
        storage.scope_table.grant_read_data(self.authorization_lambda)
        storage.agent_registry_table.grant_read_data(self.authorization_lambda)
        storage.tool_model_registry_table.grant_read_data(self.authorization_lambda)
        storage.tool_auth_table.grant_read_write_data(self.authorization_lambda)

        self.policy_risk_lambda = _lambda.Function(
            self,
            "PolicyRiskLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler_policy_risk.handler",
            code=_lambda.Code.from_asset(
                os.path.join(stack_dir, "lambdas", "governance_engine")
            ),
            timeout=Duration.seconds(15),
            memory_size=256,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "POLICY_BUCKET_NAME": storage.policy_bucket.bucket_name,
                "POLICY_PREFIX": "policies/",
                "RISK_CONFIG_TABLE_NAME": storage.risk_config_table.table_name,
                "FRAMEWORK_MAPPING_TABLE_NAME": storage.framework_mapping_table.table_name,
                "RUNTIME_DRIFT_TABLE_NAME": storage.runtime_drift_table.table_name,
                "OPA_MODE": "embedded",
                "OPA_ENDPOINT": "",
            },
        )
        storage.policy_bucket.grant_read(self.policy_risk_lambda)
        storage.risk_config_table.grant_read_data(self.policy_risk_lambda)
        storage.framework_mapping_table.grant_read_data(self.policy_risk_lambda)
        storage.runtime_drift_table.grant_read_data(self.policy_risk_lambda)

        self.post_decision_lambda = _lambda.Function(
            self,
            "PostDecisionLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler_post_decision.handler",
            code=_lambda.Code.from_asset(
                os.path.join(stack_dir, "lambdas", "governance_engine")
            ),
            timeout=Duration.seconds(30),
            memory_size=256,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "EVIDENCE_BUCKET_NAME": storage.evidence_bucket.bucket_name,
                "IMMUTABLE_EVIDENCE_BUCKET_NAME": storage.immutable_evidence_bucket.bucket_name,
                "AGENT_HEALTH_TABLE_NAME": storage.agent_health_table.table_name,
                "DECISION_HISTORY_TABLE_NAME": storage.decision_history_table.table_name,
                "RUNTIME_DRIFT_TABLE_NAME": storage.runtime_drift_table.table_name,
                "CONTROL_TRACE_TABLE_NAME": storage.control_trace_table.table_name,
                "EVIDENCE_SIGNING_KEY_ID": storage.evidence_signing_key.key_id,
            },
        )
        storage.evidence_bucket.grant_read_write(self.post_decision_lambda)
        storage.immutable_evidence_bucket.grant_read_write(self.post_decision_lambda)
        storage.agent_health_table.grant_read_write_data(self.post_decision_lambda)
        storage.decision_history_table.grant_read_write_data(self.post_decision_lambda)
        storage.runtime_drift_table.grant_read_write_data(self.post_decision_lambda)
        storage.control_trace_table.grant_read_write_data(self.post_decision_lambda)
        # AARM R5/R6: allow post-decision evidence writes to sign receipts.
        storage.evidence_signing_key.grant(self.post_decision_lambda, "kms:Sign")

        # --- Step Functions State Machine ---

        self.sfn_pipeline_role = iam.Role(
            self,
            "GovernancePipelineRole",
            assumed_by=iam.ServicePrincipal("states.amazonaws.com"),
            inline_policies={
                "GovernancePipelinePolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=["lambda:InvokeFunction"],
                            resources=[
                                self.input_defense_lambda.function_arn,
                                self.authorization_lambda.function_arn,
                                self.policy_risk_lambda.function_arn,
                                self.post_decision_lambda.function_arn,
                            ],
                        ),
                        iam.PolicyStatement(
                            actions=["dynamodb:GetItem"],
                            resources=[storage.scope_table.table_arn],
                        ),
                        iam.PolicyStatement(
                            actions=["events:PutEvents"],
                            resources=[
                                f"arn:aws:events:{stack.region}:{stack.account}:event-bus/default",
                            ],
                        ),
                    ]
                ),
            },
        )

        _state_machine_path = os.path.join(
            stack_dir, "state_machine", "governance_pipeline.asl.json"
        )
        with open(_state_machine_path) as f:
            _asl_definition = f.read()

        _asl_definition = _asl_definition.replace(
            "${ScopeTableName}", storage.scope_table.table_name
        )
        _asl_definition = _asl_definition.replace(
            "${InputDefenseLambdaArn}", self.input_defense_lambda.function_arn
        )
        _asl_definition = _asl_definition.replace(
            "${AuthorizationLambdaArn}", self.authorization_lambda.function_arn
        )
        _asl_definition = _asl_definition.replace(
            "${PolicyRiskLambdaArn}", self.policy_risk_lambda.function_arn
        )
        _asl_definition = _asl_definition.replace(
            "${PostDecisionLambdaArn}", self.post_decision_lambda.function_arn
        )

        self.governance_pipeline = sfn.CfnStateMachine(
            self,
            "GovernancePipelineStateMachine",
            state_machine_name="governance-pipeline",
            state_machine_type="EXPRESS",
            definition_string=_asl_definition,
            role_arn=self.sfn_pipeline_role.role_arn,
            tracing_configuration=sfn.CfnStateMachine.TracingConfigurationProperty(
                enabled=True,
            ),
        )

        # --- EventBridge Rules ---

        self.post_decision_rule = events.Rule(
            self,
            "PostDecisionEventRule",
            event_pattern=events.EventPattern(
                source=["governance.pipeline"],
                detail_type=["GovernanceDecision"],
            ),
        )
        self.post_decision_rule.add_target(
            targets.LambdaFunction(self.post_decision_lambda)
        )

        self.monthly_report_rule = events.Rule(
            self,
            "MonthlyReportRule",
            rule_name="AGCP-MonthlyMeasureManageReport",
            description="Triggers monthly MEASURE/MANAGE report generation on the 1st of each month",
            schedule=events.Schedule.cron(
                minute="0", hour="2", day="1", month="*", year="*",
            ),
        )
        self.monthly_report_rule.add_target(
            targets.LambdaFunction(
                self.governance_engine_lambda,
                event=events.RuleTargetInput.from_object({
                    "trigger": "monthly_report",
                    "report_type": "measure_manage",
                }),
            )
        )

        # Wire governance mode to scope enforcer
        bedrock_agent.scope_enforcer_lambda.add_environment(
            "GOVERNANCE_MODE", "step_functions"
        )
        bedrock_agent.scope_enforcer_lambda.add_environment(
            "GOVERNANCE_PIPELINE_ARN",
            self.governance_pipeline.attr_arn,
        )
        bedrock_agent.scope_enforcer_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["states:StartSyncExecution"],
                resources=[self.governance_pipeline.attr_arn],
            )
        )
