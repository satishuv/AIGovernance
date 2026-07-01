import json
import os

from aws_cdk import (
    Stack,
    RemovalPolicy,
    Duration,
    CfnOutput,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_bedrock as bedrock,
    aws_logs as logs,
    aws_cloudtrail as cloudtrail,
    aws_sns as sns,
    aws_apigateway as apigw,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_events as events,
    aws_events_targets as targets,
    aws_stepfunctions as sfn,
    custom_resources as cr,
)
from constructs import Construct


class GovernanceBedrockStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- S3 Bucket ---

        # Data Bucket: stores mock pipeline data (builds, test results, configs, rollback plans)
        self.data_bucket = s3.Bucket(
            self,
            "DataBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        # --- DynamoDB Tables ---

        # Scope Table: stores current scope level per agent
        self.scope_table = dynamodb.Table(
            self,
            "ScopeTable",
            partition_key=dynamodb.Attribute(
                name="agent_id", type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )

        # Pending Table: stores proposed changes awaiting human approval
        self.pending_table = dynamodb.Table(
            self,
            "PendingTable",
            partition_key=dynamodb.Attribute(
                name="request_id", type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- IAM Permission Boundaries ---

        # Scope 1: ReadPipelineStatus only (S3 GetObject)
        self.scope_1_boundary = iam.ManagedPolicy(
            self,
            "Scope1Boundary",
            statements=[
                iam.PolicyStatement(
                    actions=["s3:GetObject"],
                    resources=[self.data_bucket.arn_for_objects("*")],
                ),
            ],
        )

        # Scope 2: ReadPipelineStatus + ProposeChanges (S3 GetObject + DynamoDB PutItem)
        self.scope_2_boundary = iam.ManagedPolicy(
            self,
            "Scope2Boundary",
            statements=[
                iam.PolicyStatement(
                    actions=["s3:GetObject"],
                    resources=[self.data_bucket.arn_for_objects("*")],
                ),
                iam.PolicyStatement(
                    actions=["dynamodb:PutItem"],
                    resources=[self.pending_table.table_arn],
                ),
            ],
        )

        # Scope 3: Scope 2 + StagingDeployment
        self.scope_3_boundary = iam.ManagedPolicy(
            self,
            "Scope3Boundary",
            statements=[
                iam.PolicyStatement(
                    actions=["s3:GetObject", "s3:PutObject"],
                    resources=[self.data_bucket.arn_for_objects("*")],
                ),
                iam.PolicyStatement(
                    actions=[
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "dynamodb:GetItem",
                    ],
                    resources=[self.scope_table.table_arn],
                ),
            ],
        )

        # Scope 4: Full autonomy
        self.scope_4_boundary = iam.ManagedPolicy(
            self,
            "Scope4Boundary",
            statements=[
                iam.PolicyStatement(
                    actions=["s3:*"],
                    resources=[
                        self.data_bucket.bucket_arn,
                        self.data_bucket.arn_for_objects("*"),
                    ],
                ),
                iam.PolicyStatement(
                    actions=["dynamodb:*"],
                    resources=[
                        self.scope_table.table_arn,
                        self.pending_table.table_arn,
                    ],
                ),
                iam.PolicyStatement(
                    actions=["logs:*"],
                    resources=["*"],
                ),
            ],
        )

        # --- Action Group Lambda resource and IAM role ---

        self.action_group_lambda_role = iam.Role(
            self,
            "ActionGroupLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
            ],
            permissions_boundary=self.scope_1_boundary,
        )

        self.agent_log_group = logs.LogGroup(
            self,
            "AgentActionsLogGroup",
            log_group_name="/governance-demo-bedrock/agent-actions",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.action_group_lambda = _lambda.Function(
            self,
            "ActionGroupLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                os.path.join(os.path.dirname(__file__), "lambdas", "action_group")
            ),
            timeout=Duration.seconds(60),
            memory_size=512,
            role=self.action_group_lambda_role,
            environment={
                "DATA_BUCKET_NAME": self.data_bucket.bucket_name,
                "PENDING_TABLE_NAME": self.pending_table.table_name,
                "LOG_GROUP_NAME": self.agent_log_group.log_group_name,
            },
        )

        self.data_bucket.grant_read_write(self.action_group_lambda)
        self.pending_table.grant_read_write_data(self.action_group_lambda)
        self.agent_log_group.grant_write(self.action_group_lambda)

        # --- Bedrock Agent resource with action groups ---

        self.bedrock_agent_role = iam.Role(
            self,
            "BedrockAgentRole",
            assumed_by=iam.ServicePrincipal("bedrock.amazonaws.com"),
            inline_policies={
                "BedrockAgentPolicy": iam.PolicyDocument(
                    statements=[
                        iam.PolicyStatement(
                            actions=[
                                "bedrock:InvokeModel",
                                "bedrock:InvokeModelWithResponseStream",
                            ],
                            resources=[
                                f"arn:aws:bedrock:{self.region}::foundation-model/amazon.nova-micro-v1:0",
                                f"arn:aws:bedrock:{self.region}::foundation-model/amazon.nova-lite-v1:0",
                            ],
                        ),
                        iam.PolicyStatement(
                            actions=["lambda:InvokeFunction"],
                            resources=[self.action_group_lambda.function_arn],
                        ),
                    ]
                ),
            },
        )

        schemas_dir = os.path.join(os.path.dirname(__file__), "schemas")

        def _load_schema(filename):
            with open(os.path.join(schemas_dir, filename)) as f:
                return f.read()

        read_pipeline_schema = _load_schema("read_pipeline_status.json")
        propose_changes_schema = _load_schema("propose_changes.json")
        staging_deployment_schema = _load_schema("staging_deployment.json")
        production_deployment_schema = _load_schema("production_deployment.json")

        self.schema_deployment = s3deploy.BucketDeployment(
            self,
            "SchemaDeployment",
            sources=[s3deploy.Source.asset(schemas_dir)],
            destination_bucket=self.data_bucket,
            destination_key_prefix="schemas",
        )

        agent_instruction = (
            "You are a Software Deployment Pipeline Agent. You help operators manage "
            "builds, test results, deployment plans, and rollbacks. "
            "You have access to four action groups: ReadPipelineStatus, ProposeChanges, "
            "StagingDeployment, and ProductionDeployment. "
            "Check the session attributes for your current scope_level and "
            "permitted_action_groups. Only use action groups listed in "
            "permitted_action_groups. If an action group is not permitted at your "
            "current scope level, inform the user that the operation requires a "
            "higher scope level."
        )

        self.bedrock_agent = bedrock.CfnAgent(
            self,
            "BedrockAgent",
            agent_name="governance-demo-pipeline-agent",
            agent_resource_role_arn=self.bedrock_agent_role.role_arn,
            foundation_model="amazon.nova-micro-v1:0",
            idle_session_ttl_in_seconds=600,
            instruction=agent_instruction,
            action_groups=[
                bedrock.CfnAgent.AgentActionGroupProperty(
                    action_group_name="ReadPipelineStatus",
                    action_group_executor=bedrock.CfnAgent.ActionGroupExecutorProperty(
                        lambda_=self.action_group_lambda.function_arn,
                    ),
                    api_schema=bedrock.CfnAgent.APISchemaProperty(
                        payload=read_pipeline_schema,
                    ),
                    description="Read-only operations for querying build status and test results.",
                ),
                bedrock.CfnAgent.AgentActionGroupProperty(
                    action_group_name="ProposeChanges",
                    action_group_executor=bedrock.CfnAgent.ActionGroupExecutorProperty(
                        lambda_=self.action_group_lambda.function_arn,
                    ),
                    api_schema=bedrock.CfnAgent.APISchemaProperty(
                        payload=propose_changes_schema,
                    ),
                    description="Draft deployment plans and rollback strategies for review.",
                ),
                bedrock.CfnAgent.AgentActionGroupProperty(
                    action_group_name="StagingDeployment",
                    action_group_executor=bedrock.CfnAgent.ActionGroupExecutorProperty(
                        lambda_=self.action_group_lambda.function_arn,
                    ),
                    api_schema=bedrock.CfnAgent.APISchemaProperty(
                        payload=staging_deployment_schema,
                    ),
                    description="Deploy builds to staging and trigger test suites.",
                ),
                bedrock.CfnAgent.AgentActionGroupProperty(
                    action_group_name="ProductionDeployment",
                    action_group_executor=bedrock.CfnAgent.ActionGroupExecutorProperty(
                        lambda_=self.action_group_lambda.function_arn,
                    ),
                    api_schema=bedrock.CfnAgent.APISchemaProperty(
                        payload=production_deployment_schema,
                    ),
                    description="Deploy builds to production and execute rollbacks.",
                ),
            ],
            auto_prepare=True,
        )

        self.action_group_lambda.add_permission(
            "BedrockAgentInvoke",
            principal=iam.ServicePrincipal("bedrock.amazonaws.com"),
            source_arn=self.bedrock_agent.attr_agent_arn,
        )

        self.bedrock_agent_alias = bedrock.CfnAgentAlias(
            self,
            "BedrockAgentAlias",
            agent_id=self.bedrock_agent.attr_agent_id,
            agent_alias_name="live",
        )

        # --- Scope Enforcer and Kill Switch Lambda resources ---

        scope_boundary_arns = json.dumps({
            "1": self.scope_1_boundary.managed_policy_arn,
            "2": self.scope_2_boundary.managed_policy_arn,
            "3": self.scope_3_boundary.managed_policy_arn,
            "4": self.scope_4_boundary.managed_policy_arn,
        })

        self.scope_enforcer_lambda = _lambda.Function(
            self,
            "ScopeEnforcerLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                os.path.join(os.path.dirname(__file__), "lambdas", "scope_enforcer")
            ),
            timeout=Duration.seconds(90),
            memory_size=256,
            environment={
                "AGENT_ID": self.bedrock_agent.attr_agent_id,
                "AGENT_ALIAS_ID": self.bedrock_agent_alias.attr_agent_alias_id,
                "SCOPE_TABLE_NAME": self.scope_table.table_name,
                "ACTION_GROUP_LAMBDA_ROLE_NAME": self.action_group_lambda_role.role_name,
                "SCOPE_BOUNDARY_ARNS": scope_boundary_arns,
            },
        )

        self.scope_table.grant_read_write_data(self.scope_enforcer_lambda)
        self.scope_enforcer_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["iam:PutRolePermissionsBoundary"],
                resources=[self.action_group_lambda_role.role_arn],
            )
        )
        self.scope_enforcer_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=[
                    "bedrock:InvokeAgent",
                    "bedrock:InvokeModel",
                    "bedrock-agent-runtime:InvokeAgent",
                    "bedrock-agent:InvokeAgent"
                ],
                resources=["*"],
            )
        )

        self.kill_switch_lambda = _lambda.Function(
            self,
            "KillSwitchLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                os.path.join(os.path.dirname(__file__), "lambdas", "kill_switch")
            ),
            timeout=Duration.seconds(10),
            memory_size=128,
            environment={
                "SCOPE_TABLE_NAME": self.scope_table.table_name,
                "ACTION_GROUP_LAMBDA_ROLE_NAME": self.action_group_lambda_role.role_name,
            },
        )

        self.scope_table.grant_write_data(self.kill_switch_lambda)
        self.kill_switch_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["iam:PutRolePolicy"],
                resources=[self.action_group_lambda_role.role_arn],
            )
        )

        # --- CloudTrail trail (conditional) ---

        skip_cloudtrail = self.node.try_get_context("skip_cloudtrail")
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
                [cloudtrail.S3EventSelector(bucket=self.data_bucket)],
                read_write_type=cloudtrail.ReadWriteType.ALL,
            )

        # --- Scope Table initialization and sample data deployment ---

        self.scope_table_init = cr.AwsCustomResource(
            self,
            "ScopeTableInit",
            on_create=cr.AwsSdkCall(
                service="DynamoDB",
                action="putItem",
                parameters={
                    "TableName": self.scope_table.table_name,
                    "Item": {
                        "agent_id": {"S": "demo-agent"},
                        "scope_level": {"N": "1"},
                        "updated_at": {"S": "2025-01-15T10:30:00Z"},
                        "updated_by": {"S": "cdk-init"},
                    },
                },
                physical_resource_id=cr.PhysicalResourceId.of("ScopeTableInit"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["dynamodb:PutItem"],
                    resources=[self.scope_table.table_arn],
                ),
            ]),
        )

        sample_data_dir = os.path.join(os.path.dirname(__file__), "sample_data")
        self.sample_data_deployment = s3deploy.BucketDeployment(
            self,
            "SampleDataDeployment",
            sources=[s3deploy.Source.asset(sample_data_dir)],
            destination_bucket=self.data_bucket,
        )

        # ===================================================================
        # Phase 1a — Core Governance Engine Infrastructure
        # ===================================================================

        # --- Task 9.1: DynamoDB tables for governance metadata ---

        self.policy_metadata_table = dynamodb.Table(
            self,
            "PolicyMetadataTable",
            partition_key=dynamodb.Attribute(
                name="policy_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="version", type=dynamodb.AttributeType.NUMBER
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.risk_config_table = dynamodb.Table(
            self,
            "RiskConfigTable",
            partition_key=dynamodb.Attribute(
                name="config_key", type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.framework_mapping_table = dynamodb.Table(
            self,
            "FrameworkMappingTable",
            partition_key=dynamodb.Attribute(
                name="action_type", type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- Task 9.2: S3 bucket for policy definitions ---

        self.policy_bucket = s3.Bucket(
            self,
            "PolicyBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        # --- Task 9.3: S3 bucket for evidence storage ---

        self.evidence_bucket = s3.Bucket(
            self,
            "EvidenceBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        # --- Task 9.5: SNS topic for operator alerts ---

        self.operator_alerts_topic = sns.Topic(
            self,
            "OperatorAlertsTopic",
            display_name="Governance Operator Alerts",
        )

        # --- Task 9.4: Governance Engine Lambda ---

        self.governance_engine_lambda = _lambda.Function(
            self,
            "GovernanceEngineLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                os.path.join(
                    os.path.dirname(__file__), "lambdas", "governance_engine"
                )
            ),
            timeout=Duration.seconds(10),
            memory_size=256,
            environment={
                "POLICY_BUCKET_NAME": self.policy_bucket.bucket_name,
                "POLICY_PREFIX": "policies/",
                "POLICY_METADATA_TABLE_NAME": self.policy_metadata_table.table_name,
                "RISK_CONFIG_TABLE_NAME": self.risk_config_table.table_name,
                "FRAMEWORK_MAPPING_TABLE_NAME": self.framework_mapping_table.table_name,
                "EVIDENCE_BUCKET_NAME": self.evidence_bucket.bucket_name,
                "OPERATOR_SNS_TOPIC_ARN": self.operator_alerts_topic.topic_arn,
            },
        )

        self.policy_bucket.grant_read(self.governance_engine_lambda)
        self.evidence_bucket.grant_read_write(self.governance_engine_lambda)
        self.policy_metadata_table.grant_read_data(self.governance_engine_lambda)
        self.risk_config_table.grant_read_data(self.governance_engine_lambda)
        self.framework_mapping_table.grant_read_data(self.governance_engine_lambda)
        self.operator_alerts_topic.grant_publish(self.governance_engine_lambda)

        # --- Task 9.6: Grant Scope Enforcer permission to invoke Governance Engine ---

        self.governance_engine_lambda.grant_invoke(self.scope_enforcer_lambda)
        self.scope_enforcer_lambda.add_environment(
            "GOVERNANCE_ENGINE_LAMBDA_ARN",
            self.governance_engine_lambda.function_arn,
        )

        # --- Task 9.7: Seed data defined below, deployed via consolidated SeedTablesLambda ---
        # (see end of stack for the single Lambda + AwsCustomResource that seeds all tables)

        # --- Task 9.8: Upload sample policy definitions to PolicyBucket ---

        policies_dir = os.path.join(os.path.dirname(__file__), "sample_data", "policies")
        self.policy_deployment = s3deploy.BucketDeployment(
            self, "PolicyDeployment",
            sources=[s3deploy.Source.asset(policies_dir)],
            destination_bucket=self.policy_bucket,
            destination_key_prefix="policies/",
        )

        # ===================================================================
        # Phase 1b — Identity, Registry, and Governance Roles Infrastructure
        # ===================================================================

        # --- Task 21.1: DynamoDB tables for Phase 1b ---

        self.agent_registry_table = dynamodb.Table(
            self,
            "AgentRegistryTable",
            partition_key=dynamodb.Attribute(
                name="agent_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.tool_model_registry_table = dynamodb.Table(
            self,
            "ToolModelRegistryTable",
            partition_key=dynamodb.Attribute(
                name="entry_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.governance_roles_table = dynamodb.Table(
            self,
            "GovernanceRolesTable",
            partition_key=dynamodb.Attribute(
                name="user_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="role", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- Task 21.2: Grant Governance Engine Lambda access to Phase 1b tables ---

        self.agent_registry_table.grant_read_write_data(self.governance_engine_lambda)
        self.tool_model_registry_table.grant_read_write_data(self.governance_engine_lambda)
        self.governance_roles_table.grant_read_write_data(self.governance_engine_lambda)

        self.governance_engine_lambda.add_environment(
            "AGENT_REGISTRY_TABLE_NAME",
            self.agent_registry_table.table_name,
        )
        self.governance_engine_lambda.add_environment(
            "TOOL_MODEL_REGISTRY_TABLE_NAME",
            self.tool_model_registry_table.table_name,
        )
        self.governance_engine_lambda.add_environment(
            "GOVERNANCE_ROLES_TABLE_NAME",
            self.governance_roles_table.table_name,
        )

        # --- Task 21.3: ScopeTable Phase1b seed — consolidated into SeedTablesLambda ---

        # --- Task 21.4: Phase 1b seeds — consolidated into SeedTablesLambda ---

        # ===================================================================
        # Phase 1c — Evidence, Compliance, and Security Infrastructure
        # ===================================================================

        # --- Task 35.1: DynamoDB tables for Phase 1c ---

        self.control_trace_table = dynamodb.Table(
            self,
            "ControlTraceTable",
            partition_key=dynamodb.Attribute(
                name="control_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.control_trace_table.add_global_secondary_index(
            index_name="ByEvidenceRecordId",
            partition_key=dynamodb.Attribute(
                name="evidence_record_id", type=dynamodb.AttributeType.STRING
            ),
        )

        self.control_trace_table.add_global_secondary_index(
            index_name="ByDecisionId",
            partition_key=dynamodb.Attribute(
                name="decision_id", type=dynamodb.AttributeType.STRING
            ),
        )

        self.threat_patterns_table = dynamodb.Table(
            self,
            "ThreatPatternsTable",
            partition_key=dynamodb.Attribute(
                name="pattern_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.control_mapping_table = dynamodb.Table(
            self,
            "ControlMappingTable",
            partition_key=dynamodb.Attribute(
                name="control_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- Task 35.2: Immutable Evidence Bucket with S3 Object Lock ---

        self.immutable_evidence_bucket = s3.Bucket(
            self,
            "ImmutableEvidenceBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            object_lock_enabled=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=False,
        )

        # Set default Object Lock retention in compliance mode (365 days)
        cfn_bucket = self.immutable_evidence_bucket.node.default_child
        cfn_bucket.add_property_override(
            "ObjectLockConfiguration",
            {
                "ObjectLockEnabled": "Enabled",
                "Rule": {
                    "DefaultRetention": {
                        "Mode": "COMPLIANCE",
                        "Days": 365,
                    }
                },
            },
        )

        # --- Task 35.3: Kill Switch Lambda for Phase 1c ---

        self.kill_switch_phase1c_lambda = _lambda.Function(
            self,
            "KillSwitchPhase1cLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="kill_switch.handler",
            code=_lambda.Code.from_asset(
                os.path.join(
                    os.path.dirname(__file__), "lambdas", "governance_engine"
                )
            ),
            timeout=Duration.seconds(10),
            memory_size=256,
            environment={
                "SCOPE_TABLE_NAME": self.scope_table.table_name,
                "AGENT_REGISTRY_TABLE_NAME": self.agent_registry_table.table_name,
                "GOVERNANCE_ROLES_TABLE_NAME": self.governance_roles_table.table_name,
                "OPERATOR_SNS_TOPIC_ARN": self.operator_alerts_topic.topic_arn,
            },
        )

        self.scope_table.grant_read_write_data(self.kill_switch_phase1c_lambda)
        self.agent_registry_table.grant_read_data(self.kill_switch_phase1c_lambda)
        self.governance_roles_table.grant_read_data(self.kill_switch_phase1c_lambda)
        self.operator_alerts_topic.grant_publish(self.kill_switch_phase1c_lambda)

        # --- Task 35.4: API Gateway for Kill Switch ---

        self.kill_switch_api = apigw.RestApi(
            self,
            "KillSwitchApi",
            rest_api_name="GovernanceKillSwitchAPI",
            description="API Gateway for Kill Switch activate/deactivate",
            deploy_options=apigw.StageOptions(stage_name="prod"),
        )

        kill_switch_resource = self.kill_switch_api.root.add_resource("kill-switch")
        activate_resource = kill_switch_resource.add_resource("activate")
        deactivate_resource = kill_switch_resource.add_resource("deactivate")

        kill_switch_integration = apigw.LambdaIntegration(
            self.kill_switch_phase1c_lambda,
        )

        activate_resource.add_method(
            "POST",
            kill_switch_integration,
            authorization_type=apigw.AuthorizationType.IAM,
        )

        deactivate_resource.add_method(
            "POST",
            kill_switch_integration,
            authorization_type=apigw.AuthorizationType.IAM,
        )

        # --- Task 35.5: Grant Governance Engine Lambda access to Phase 1c tables ---

        self.control_trace_table.grant_read_write_data(self.governance_engine_lambda)
        self.threat_patterns_table.grant_read_write_data(self.governance_engine_lambda)
        self.control_mapping_table.grant_read_write_data(self.governance_engine_lambda)
        self.immutable_evidence_bucket.grant_read_write(self.governance_engine_lambda)

        self.governance_engine_lambda.add_environment(
            "CONTROL_TRACE_TABLE_NAME",
            self.control_trace_table.table_name,
        )
        self.governance_engine_lambda.add_environment(
            "THREAT_PATTERNS_TABLE_NAME",
            self.threat_patterns_table.table_name,
        )
        self.governance_engine_lambda.add_environment(
            "CONTROL_MAPPING_TABLE_NAME",
            self.control_mapping_table.table_name,
        )
        self.governance_engine_lambda.add_environment(
            "IMMUTABLE_EVIDENCE_BUCKET_NAME",
            self.immutable_evidence_bucket.bucket_name,
        )

        # --- Task 35.6: Phase 1c seeds — consolidated into SeedTablesLambda ---

        # ===================================================================
        # Phase 2 — Human Oversight + Evidence Pipeline Infrastructure
        # ===================================================================

        # --- Task 49.1: DynamoDB tables for Phase 2 ---

        # PendingApprovalTable: stores pending approval records
        self.pending_approval_table = dynamodb.Table(
            self,
            "PendingApprovalTable",
            partition_key=dynamodb.Attribute(
                name="approval_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.pending_approval_table.add_global_secondary_index(
            index_name="ByAgentId",
            partition_key=dynamodb.Attribute(
                name="agent_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="created_at", type=dynamodb.AttributeType.STRING
            ),
        )

        self.pending_approval_table.add_global_secondary_index(
            index_name="ByStatus",
            partition_key=dynamodb.Attribute(
                name="status", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="created_at", type=dynamodb.AttributeType.STRING
            ),
        )

        # ChangeLogTable: stores scope and policy change records
        self.change_log_table = dynamodb.Table(
            self,
            "ChangeLogTable",
            partition_key=dynamodb.Attribute(
                name="record_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="ttl_expiry",
        )

        self.change_log_table.add_global_secondary_index(
            index_name="ByAgentId",
            partition_key=dynamodb.Attribute(
                name="agent_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp", type=dynamodb.AttributeType.STRING
            ),
        )

        self.change_log_table.add_global_secondary_index(
            index_name="ByPolicyId",
            partition_key=dynamodb.Attribute(
                name="policy_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp", type=dynamodb.AttributeType.STRING
            ),
        )

        self.change_log_table.add_global_secondary_index(
            index_name="ByRequesterId",
            partition_key=dynamodb.Attribute(
                name="requester_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp", type=dynamodb.AttributeType.STRING
            ),
        )

        # DecisionHistoryTable: stores indexed governance decision records
        self.decision_history_table = dynamodb.Table(
            self,
            "DecisionHistoryTable",
            partition_key=dynamodb.Attribute(
                name="agent_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.decision_history_table.add_global_secondary_index(
            index_name="ByVerdict",
            partition_key=dynamodb.Attribute(
                name="verdict", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp", type=dynamodb.AttributeType.STRING
            ),
        )

        self.decision_history_table.add_global_secondary_index(
            index_name="ByControlId",
            partition_key=dynamodb.Attribute(
                name="control_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp", type=dynamodb.AttributeType.STRING
            ),
        )

        # --- Task 49.2: Grant Governance Engine Lambda access to Phase 2 tables ---

        self.pending_approval_table.grant_read_write_data(self.governance_engine_lambda)
        self.change_log_table.grant_read_write_data(self.governance_engine_lambda)
        self.decision_history_table.grant_read_write_data(self.governance_engine_lambda)

        self.governance_engine_lambda.add_environment(
            "PENDING_APPROVAL_TABLE_NAME",
            self.pending_approval_table.table_name,
        )
        self.governance_engine_lambda.add_environment(
            "CHANGE_LOG_TABLE_NAME",
            self.change_log_table.table_name,
        )
        self.governance_engine_lambda.add_environment(
            "DECISION_HISTORY_TABLE_NAME",
            self.decision_history_table.table_name,
        )

        # --- Task 49.3: API Gateway endpoints for Approval Workflow ---

        self.approval_api = apigw.RestApi(
            self,
            "ApprovalApi",
            rest_api_name="GovernanceApprovalAPI",
            description="API Gateway for approval workflow and decision history",
            deploy_options=apigw.StageOptions(stage_name="prod"),
        )

        governance_integration = apigw.LambdaIntegration(
            self.governance_engine_lambda,
        )

        approvals_resource = self.approval_api.root.add_resource("approvals")
        pending_resource = approvals_resource.add_resource("pending")
        approval_id_resource = approvals_resource.add_resource("{approval_id}")
        approve_resource = approval_id_resource.add_resource("approve")
        deny_resource = approval_id_resource.add_resource("deny")

        pending_resource.add_method(
            "GET",
            governance_integration,
            authorization_type=apigw.AuthorizationType.IAM,
        )

        approve_resource.add_method(
            "POST",
            governance_integration,
            authorization_type=apigw.AuthorizationType.IAM,
        )

        deny_resource.add_method(
            "POST",
            governance_integration,
            authorization_type=apigw.AuthorizationType.IAM,
        )

        # --- Task 49.4: API Gateway endpoints for Decision History queries ---

        decisions_resource = self.approval_api.root.add_resource("decisions")
        decisions_agent_resource = decisions_resource.add_resource("{agent_id}")

        decisions_agent_resource.add_method(
            "GET",
            governance_integration,
            authorization_type=apigw.AuthorizationType.IAM,
        )

        # --- Task 49.5: Seed Phase 2 tables and upload compliance mapping data ---

        # Upload compliance mapping files to evidence S3 bucket
        compliance_dir = os.path.join(
            os.path.dirname(__file__), "sample_data", "compliance"
        )
        self.compliance_deployment = s3deploy.BucketDeployment(
            self,
            "ComplianceDeployment",
            sources=[s3deploy.Source.asset(compliance_dir)],
            destination_bucket=self.evidence_bucket,
            destination_key_prefix="compliance/",
        )

        # Phase 2 seeds — consolidated into SeedTablesLambda

        # --- Task 53.2: Compliance Refresh Lambda and custom resource trigger ---

        self.compliance_refresh_lambda = _lambda.Function(
            self,
            "ComplianceRefreshLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="compliance_refresh.handler",
            code=_lambda.Code.from_asset(
                os.path.join(
                    os.path.dirname(__file__), "lambdas", "governance_engine"
                )
            ),
            timeout=Duration.seconds(30),
            memory_size=256,
            environment={
                "CONTROL_MAPPING_TABLE_NAME": self.control_mapping_table.table_name,
                "EVIDENCE_BUCKET_NAME": self.evidence_bucket.bucket_name,
                "IMMUTABLE_EVIDENCE_BUCKET_NAME": self.immutable_evidence_bucket.bucket_name,
            },
        )

        self.control_mapping_table.grant_read_data(self.compliance_refresh_lambda)
        self.evidence_bucket.grant_read_write(self.compliance_refresh_lambda)
        self.immutable_evidence_bucket.grant_read_write(self.compliance_refresh_lambda)

        # Custom resource to trigger compliance refresh on stack create/update
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

        # ===================================================================
        # Phase 3 — Compliance, Metrics, and Advanced Security Infrastructure
        # ===================================================================

        # --- Task 69.1: DynamoDB tables for Phase 3 ---

        self.denial_pattern_table = dynamodb.Table(
            self,
            "DenialPatternTable",
            partition_key=dynamodb.Attribute(
                name="agent_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="window_start", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.exfiltration_allowlist_table = dynamodb.Table(
            self,
            "ExfiltrationAllowlistTable",
            partition_key=dynamodb.Attribute(
                name="endpoint_pattern", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.scope_reduction_history_table = dynamodb.Table(
            self,
            "ScopeReductionHistoryTable",
            partition_key=dynamodb.Attribute(
                name="agent_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="timestamp", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.multi_agent_config_table = dynamodb.Table(
            self,
            "MultiAgentConfigTable",
            partition_key=dynamodb.Attribute(
                name="agent_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.metrics_threshold_table = dynamodb.Table(
            self,
            "MetricsThresholdTable",
            partition_key=dynamodb.Attribute(
                name="metric_name", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

        # --- Phase 4: Advanced Security Tables ---

        # Runtime Drift Table: behavioral baselines and drift tracking
        self.runtime_drift_table = dynamodb.Table(
            self,
            "RuntimeDriftTable",
            partition_key=dynamodb.Attribute(
                name="agent_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="record_type", type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="ttl_expiry",
        )

        # Agent Health Table: continuous health monitoring
        self.agent_health_table = dynamodb.Table(
            self,
            "AgentHealthTable",
            partition_key=dynamodb.Attribute(
                name="agent_id", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="record_type", type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="ttl_expiry",
        )

        # Tool Auth Table: per-tool authorization rules, chains, rate limits
        self.tool_auth_table = dynamodb.Table(
            self,
            "ToolAuthTable",
            partition_key=dynamodb.Attribute(
                name="pk", type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="sk", type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
            time_to_live_attribute="ttl_expiry",
        )

        # --- Task 69.2: CloudWatch alarms ---

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
            cw_actions.SnsAction(self.operator_alerts_topic)
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
            cw_actions.SnsAction(self.operator_alerts_topic)
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
            cw_actions.SnsAction(self.operator_alerts_topic)
        )

        # --- Task 69.3: Grant Lambda access to Phase 3 tables and CloudWatch ---

        self.denial_pattern_table.grant_read_write_data(self.governance_engine_lambda)
        self.exfiltration_allowlist_table.grant_read_write_data(self.governance_engine_lambda)
        self.scope_reduction_history_table.grant_read_write_data(self.governance_engine_lambda)
        self.multi_agent_config_table.grant_read_write_data(self.governance_engine_lambda)
        self.metrics_threshold_table.grant_read_write_data(self.governance_engine_lambda)

        # Phase 4 table permissions
        self.runtime_drift_table.grant_read_write_data(self.governance_engine_lambda)
        self.agent_health_table.grant_read_write_data(self.governance_engine_lambda)
        self.tool_auth_table.grant_read_write_data(self.governance_engine_lambda)

        self.governance_engine_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["cloudwatch:PutMetricData"],
                resources=["*"],
            )
        )

        self.governance_engine_lambda.add_environment(
            "DENIAL_PATTERN_TABLE_NAME",
            self.denial_pattern_table.table_name,
        )
        self.governance_engine_lambda.add_environment(
            "EXFILTRATION_ALLOWLIST_TABLE_NAME",
            self.exfiltration_allowlist_table.table_name,
        )
        self.governance_engine_lambda.add_environment(
            "SCOPE_REDUCTION_HISTORY_TABLE_NAME",
            self.scope_reduction_history_table.table_name,
        )
        self.governance_engine_lambda.add_environment(
            "MULTI_AGENT_CONFIG_TABLE_NAME",
            self.multi_agent_config_table.table_name,
        )
        self.governance_engine_lambda.add_environment(
            "METRICS_THRESHOLD_TABLE_NAME",
            self.metrics_threshold_table.table_name,
        )

        # Phase 4 environment variables
        self.governance_engine_lambda.add_environment(
            "RUNTIME_DRIFT_TABLE_NAME", self.runtime_drift_table.table_name
        )
        self.governance_engine_lambda.add_environment(
            "AGENT_HEALTH_TABLE_NAME", self.agent_health_table.table_name
        )
        self.governance_engine_lambda.add_environment(
            "TOOL_AUTH_TABLE_NAME", self.tool_auth_table.table_name
        )

        # --- Task 69.4: Phase 3 seeds — consolidated into SeedTablesLambda ---

        # --- Task 69.5: EventBridge rule for monthly MEASURE/MANAGE reports ---

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

        # ===================================================================
        # Phase 5 — Scalable Step Functions Pipeline
        # ===================================================================

        # --- 5.1: Input Defense Lambda (threat detection + sanitization) ---

        self.input_defense_lambda = _lambda.Function(
            self,
            "InputDefenseLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler_input_defense.handler",
            code=_lambda.Code.from_asset(
                os.path.join(
                    os.path.dirname(__file__), "lambdas", "governance_engine"
                )
            ),
            timeout=Duration.seconds(10),
            memory_size=256,
            environment={
                "THREAT_PATTERNS_TABLE_NAME": self.threat_patterns_table.table_name,
            },
        )
        self.threat_patterns_table.grant_read_data(self.input_defense_lambda)

        # --- 5.2: Authorization Lambda (identity + registry + tool auth) ---

        self.authorization_lambda = _lambda.Function(
            self,
            "AuthorizationLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler_authorization.handler",
            code=_lambda.Code.from_asset(
                os.path.join(
                    os.path.dirname(__file__), "lambdas", "governance_engine"
                )
            ),
            timeout=Duration.seconds(10),
            memory_size=256,
            environment={
                "SCOPE_TABLE_NAME": self.scope_table.table_name,
                "AGENT_REGISTRY_TABLE_NAME": self.agent_registry_table.table_name,
                "TOOL_MODEL_REGISTRY_TABLE_NAME": self.tool_model_registry_table.table_name,
                "TOOL_AUTH_TABLE_NAME": self.tool_auth_table.table_name,
            },
        )
        self.scope_table.grant_read_data(self.authorization_lambda)
        self.agent_registry_table.grant_read_data(self.authorization_lambda)
        self.tool_model_registry_table.grant_read_data(self.authorization_lambda)
        self.tool_auth_table.grant_read_write_data(self.authorization_lambda)

        # --- 5.3: Policy and Risk Lambda (policy eval + risk scoring + decision) ---

        self.policy_risk_lambda = _lambda.Function(
            self,
            "PolicyRiskLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler_policy_risk.handler",
            code=_lambda.Code.from_asset(
                os.path.join(
                    os.path.dirname(__file__), "lambdas", "governance_engine"
                )
            ),
            timeout=Duration.seconds(15),
            memory_size=256,
            environment={
                "POLICY_BUCKET_NAME": self.policy_bucket.bucket_name,
                "POLICY_PREFIX": "policies/",
                "RISK_CONFIG_TABLE_NAME": self.risk_config_table.table_name,
                "FRAMEWORK_MAPPING_TABLE_NAME": self.framework_mapping_table.table_name,
                "RUNTIME_DRIFT_TABLE_NAME": self.runtime_drift_table.table_name,
            },
        )
        self.policy_bucket.grant_read(self.policy_risk_lambda)
        self.risk_config_table.grant_read_data(self.policy_risk_lambda)
        self.framework_mapping_table.grant_read_data(self.policy_risk_lambda)
        self.runtime_drift_table.grant_read_data(self.policy_risk_lambda)

        # --- 5.4: Post-Decision Lambda (evidence, health, history - async) ---

        self.post_decision_lambda = _lambda.Function(
            self,
            "PostDecisionLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="handler_post_decision.handler",
            code=_lambda.Code.from_asset(
                os.path.join(
                    os.path.dirname(__file__), "lambdas", "governance_engine"
                )
            ),
            timeout=Duration.seconds(30),
            memory_size=256,
            environment={
                "EVIDENCE_BUCKET_NAME": self.evidence_bucket.bucket_name,
                "IMMUTABLE_EVIDENCE_BUCKET_NAME": self.immutable_evidence_bucket.bucket_name,
                "AGENT_HEALTH_TABLE_NAME": self.agent_health_table.table_name,
                "DECISION_HISTORY_TABLE_NAME": self.decision_history_table.table_name,
                "RUNTIME_DRIFT_TABLE_NAME": self.runtime_drift_table.table_name,
                "CONTROL_TRACE_TABLE_NAME": self.control_trace_table.table_name,
            },
        )
        self.evidence_bucket.grant_read_write(self.post_decision_lambda)
        self.immutable_evidence_bucket.grant_read_write(self.post_decision_lambda)
        self.agent_health_table.grant_read_write_data(self.post_decision_lambda)
        self.decision_history_table.grant_read_write_data(self.post_decision_lambda)
        self.runtime_drift_table.grant_read_write_data(self.post_decision_lambda)
        self.control_trace_table.grant_read_write_data(self.post_decision_lambda)

        # --- 5.5: Step Functions IAM Role ---

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
                            resources=[self.scope_table.table_arn],
                        ),
                        iam.PolicyStatement(
                            actions=["events:PutEvents"],
                            resources=[
                                f"arn:aws:events:{self.region}:{self.account}:event-bus/default",
                            ],
                        ),
                    ]
                ),
            },
        )

        # --- 5.6: Step Functions Express State Machine ---

        _state_machine_path = os.path.join(
            os.path.dirname(__file__), "state_machine", "governance_pipeline.asl.json"
        )
        with open(_state_machine_path) as f:
            _asl_definition = f.read()

        # Substitute resource ARNs and table names into the ASL template
        _asl_definition = _asl_definition.replace(
            "${ScopeTableName}", self.scope_table.table_name
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
        )

        # --- 5.7: EventBridge Rule for async post-decision processing ---

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

        # --- 5.8: Add governance mode env vars to scope enforcer ---

        self.scope_enforcer_lambda.add_environment(
            "GOVERNANCE_MODE", "step_functions"
        )
        self.scope_enforcer_lambda.add_environment(
            "GOVERNANCE_PIPELINE_ARN",
            self.governance_pipeline.attr_arn,
        )
        self.scope_enforcer_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["states:StartSyncExecution"],
                resources=[self.governance_pipeline.attr_arn],
            )
        )

        # ===================================================================
        # Consolidated Seed Tables — single Lambda replaces all individual
        # AwsCustomResource seed instances to avoid IAM policy size limits
        # ===================================================================

        # --- Seed Lambda Function ---

        self.seed_tables_lambda = _lambda.Function(
            self,
            "SeedTablesLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                os.path.join(os.path.dirname(__file__), "lambdas", "seed_tables")
            ),
            timeout=Duration.seconds(120),
            memory_size=256,
        )

        # Grant the seed Lambda write access to ALL seeded tables
        all_seed_table_arns = [
            self.scope_table.table_arn,
            self.risk_config_table.table_arn,
            self.framework_mapping_table.table_arn,
            self.agent_registry_table.table_arn,
            self.governance_roles_table.table_arn,
            self.threat_patterns_table.table_arn,
            self.control_mapping_table.table_arn,
            self.pending_approval_table.table_arn,
            self.exfiltration_allowlist_table.table_arn,
            self.metrics_threshold_table.table_arn,
            self.multi_agent_config_table.table_arn,
            self.tool_model_registry_table.table_arn,
            self.runtime_drift_table.table_arn,
            self.agent_health_table.table_arn,
            self.tool_auth_table.table_arn,
        ]

        self.seed_tables_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["dynamodb:PutItem", "dynamodb:BatchWriteItem"],
                resources=all_seed_table_arns,
            )
        )

        # --- Build seed payload (native Python dicts for boto3 resource) ---

        # Load control mapping data from sample_data files
        control_mapping_dir = os.path.join(
            os.path.dirname(__file__), "sample_data", "control_mapping"
        )
        control_mapping_items = []
        for filename in ["iso42001_mappings.json", "nist_ai_rmf_mappings.json"]:
            filepath = os.path.join(control_mapping_dir, filename)
            with open(filepath) as f:
                data = json.load(f)
            for m in data.get("mappings", []):
                composite_id = f"{m['control_id']}#{m['implementation_component']}"
                control_mapping_items.append({
                    "control_id": composite_id,
                    "framework": data["framework"],
                    "control_name": m["control_name"],
                    "implementation_component": m["implementation_component"],
                    "evidence_generated": m["evidence_generated"],
                })

        seed_payload = {
            "seeds": [
                # --- ScopeTable (Phase 1b update with AgentIdentity fields) ---
                {
                    "table_name": self.scope_table.table_name,
                    "items": [
                        {
                            "agent_id": "demo-agent",
                            "scope_level": 1,
                            "updated_at": "2025-01-15T10:30:00Z",
                            "updated_by": "cdk-init",
                            "environment": "dev",
                            "status": "active",
                            "display_name": "Demo Agent",
                        },
                    ],
                },
                # --- RiskConfigTable ---
                {
                    "table_name": self.risk_config_table.table_name,
                    "items": [
                        {
                            "config_key": "escalation_threshold",
                            "value": 70,
                            "description": "Risk score threshold above which actions are escalated",
                        },
                        {
                            "config_key": "scope_level_weights",
                            "weights": {"0": 0, "1": 10, "2": 25, "3": 50, "4": 75},
                            "description": "Risk weight per scope level",
                        },
                        {
                            "config_key": "action_group_weights",
                            "weights": {
                                "data_access": 10, "data_modification": 30,
                                "deployment": 50, "configuration_change": 40,
                                "emergency_action": 60,
                            },
                            "description": "Risk weight per action group category",
                        },
                        {
                            "config_key": "target_resource_weights",
                            "weights": {
                                "production": 30, "staging": 15,
                                "development": 5, "default": 10,
                            },
                            "description": "Risk weight per target resource type",
                        },
                        {
                            "config_key": "category_base_weights",
                            "weights": {
                                "data_access": 5, "data_modification": 15,
                                "deployment": 25, "configuration_change": 20,
                                "emergency_action": 35,
                            },
                            "description": "Base risk weight per risk category",
                        },
                        {
                            "config_key": "history_factor_weight",
                            "value": 5,
                            "description": "Risk weight multiplier per recent action in history",
                        },
                        {
                            "config_key": "scope_reduction_mode",
                            "value": "approval-gated",
                            "time_window_seconds": 3600,
                            "sustained_period_seconds": 1800,
                            "cooldown_seconds": 7200,
                            "high_risk_threshold": 70,
                            "description": "Graduated scope reduction configuration",
                        },
                    ],
                },
                # --- FrameworkMappingTable ---
                {
                    "table_name": self.framework_mapping_table.table_name,
                    "items": [
                        {
                            "action_type": "data_access",
                            "iso_42001_controls": ["A.8.4", "A.6.2.2"],
                            "nist_ai_rmf_functions": ["GOVERN 1.1", "MAP 1.1"],
                        },
                        {
                            "action_type": "data_modification",
                            "iso_42001_controls": ["A.8.4", "A.8.5", "A.6.2.2"],
                            "nist_ai_rmf_functions": ["GOVERN 1.1", "GOVERN 1.2", "MAP 1.5"],
                        },
                        {
                            "action_type": "deployment",
                            "iso_42001_controls": ["A.8.2", "A.8.5", "A.6.2.1"],
                            "nist_ai_rmf_functions": ["GOVERN 1.2", "MAP 3.4", "MANAGE 1.1"],
                        },
                        {
                            "action_type": "configuration_change",
                            "iso_42001_controls": ["A.8.2", "A.8.4", "A.6.2.1"],
                            "nist_ai_rmf_functions": ["GOVERN 1.1", "GOVERN 1.2", "MANAGE 2.2"],
                        },
                        {
                            "action_type": "emergency_action",
                            "iso_42001_controls": ["A.8.2", "A.8.5", "A.6.2.1", "A.6.2.2"],
                            "nist_ai_rmf_functions": ["GOVERN 1.2", "MANAGE 1.1", "MANAGE 4.1"],
                        },
                    ],
                },
                # --- AgentRegistryTable ---
                {
                    "table_name": self.agent_registry_table.table_name,
                    "items": [
                        {
                            "agent_id": "demo-agent",
                            "purpose": "Software Deployment Pipeline Agent",
                            "owner": "governance-admin",
                            "data_classes": ["pipeline_status", "deployment_config"],
                            "tools": ["ReadPipelineStatus", "ProposeChanges"],
                            "approved_scope": 2,
                            "environment": "dev",
                        },
                    ],
                },
                # --- GovernanceRolesTable ---
                {
                    "table_name": self.governance_roles_table.table_name,
                    "items": [
                        {
                            "user_id": "governance-admin",
                            "role": "policy_author",
                            "scope": "global",
                            "assigned_by": "cdk-init",
                            "assigned_at": "2025-01-15T10:30:00Z",
                        },
                        {
                            "user_id": "governance-admin",
                            "role": "operator",
                            "scope": "global",
                            "assigned_by": "cdk-init",
                            "assigned_at": "2025-01-15T10:30:00Z",
                        },
                        {
                            "user_id": "demo-auditor",
                            "role": "auditor",
                            "scope": "global",
                            "assigned_by": "cdk-init",
                            "assigned_at": "2025-01-15T10:30:00Z",
                        },
                    ],
                },
                # --- ThreatPatternsTable ---
                {
                    "table_name": self.threat_patterns_table.table_name,
                    "items": [
                        {"pattern_id": "kb-sql-injection-1", "category": "known_bad",
                         "pattern": "';\\s*drop\\s+table",
                         "description": "SQL injection: DROP TABLE attempt",
                         "risk_weight": 100, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "kb-sql-injection-2", "category": "known_bad",
                         "pattern": "or\\s+1\\s*=\\s*1",
                         "description": "SQL injection: OR 1=1 tautology",
                         "risk_weight": 100, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "kb-prompt-injection-1", "category": "known_bad",
                         "pattern": "ignore\\s+previous\\s+instructions",
                         "description": "Prompt injection: ignore previous instructions",
                         "risk_weight": 100, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "kb-prompt-injection-2", "category": "known_bad",
                         "pattern": "system:\\s*override",
                         "description": "Prompt injection: system override attempt",
                         "risk_weight": 100, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "kb-disallowed-cmd-1", "category": "known_bad",
                         "pattern": "rm\\s+-rf",
                         "description": "Disallowed command: rm -rf",
                         "risk_weight": 100, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "kb-disallowed-cmd-2", "category": "known_bad",
                         "pattern": "format\\s+c:",
                         "description": "Disallowed command: format c:",
                         "risk_weight": 100, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "sus-partial-prompt-1", "category": "suspicious",
                         "pattern": "you\\s+are\\s+now",
                         "description": "Suspicious: partial prompt injection indicator",
                         "risk_weight": 30, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "sus-encoding-1", "category": "suspicious",
                         "pattern": "%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}",
                         "description": "Suspicious: unusual URL encoding sequences",
                         "risk_weight": 20, "updated_at": "2025-01-15T10:30:00Z"},
                        {"pattern_id": "sus-length-1", "category": "suspicious",
                         "pattern": ".{5000,}",
                         "description": "Suspicious: anomalous input length (>5000 chars)",
                         "risk_weight": 25, "updated_at": "2025-01-15T10:30:00Z"},
                    ],
                },
                # --- ToolModelRegistryTable ---
                {
                    "table_name": self.tool_model_registry_table.table_name,
                    "items": [
                        {"entry_id": "tc-read-pipeline", "category": "tool_connector",
                         "name": "ReadPipelineStatus", "version": "*",
                         "approval_status": "approved", "approved_by": "governance-admin",
                         "description": "Read pipeline status action group (Scope 1+)",
                         "registered_at": "2025-01-15T10:30:00Z"},
                        {"entry_id": "tc-propose-changes", "category": "tool_connector",
                         "name": "ProposeChanges", "version": "*",
                         "approval_status": "approved", "approved_by": "governance-admin",
                         "description": "Propose changes action group (Scope 2+)",
                         "registered_at": "2025-01-15T10:30:00Z"},
                        {"entry_id": "tc-staging-deploy", "category": "tool_connector",
                         "name": "StagingDeployment", "version": "*",
                         "approval_status": "approved", "approved_by": "governance-admin",
                         "description": "Staging deployment action group (Scope 3+)",
                         "registered_at": "2025-01-15T10:30:00Z"},
                        {"entry_id": "tc-production-deploy", "category": "tool_connector",
                         "name": "ProductionDeployment", "version": "*",
                         "approval_status": "approved", "approved_by": "governance-admin",
                         "description": "Production deployment action group (Scope 4)",
                         "registered_at": "2025-01-15T10:30:00Z"},
                    ],
                },
                # --- ControlMappingTable (loaded from sample_data JSON files) ---
                {
                    "table_name": self.control_mapping_table.table_name,
                    "items": control_mapping_items,
                },
                # --- PendingApprovalTable ---
                {
                    "table_name": self.pending_approval_table.table_name,
                    "items": [
                        {
                            "approval_id": "sample-approval-001",
                            "decision_id": "sample-decision-001",
                            "agent_id": "demo-agent",
                            "action_requested": "StagingDeployment",
                            "risk_score": 75,
                            "escalation_reason": "Risk score 75 exceeds escalation threshold of 70",
                            "status": "pending",
                            "approver_id": "",
                            "approval_conditions": "",
                            "denial_reason": "",
                            "created_at": "2025-01-15T10:30:00Z",
                            "resolved_at": "",
                            "timeout_seconds": 3600,
                        },
                    ],
                },
                # --- ExfiltrationAllowlistTable ---
                {
                    "table_name": self.exfiltration_allowlist_table.table_name,
                    "items": [
                        {"endpoint_pattern": "amazonaws.com",
                         "description": "Default approved endpoint: amazonaws.com",
                         "added_at": "2025-01-15T10:30:00Z"},
                        {"endpoint_pattern": "aws.amazon.com",
                         "description": "Default approved endpoint: aws.amazon.com",
                         "added_at": "2025-01-15T10:30:00Z"},
                        {"endpoint_pattern": "github.com",
                         "description": "Default approved endpoint: github.com",
                         "added_at": "2025-01-15T10:30:00Z"},
                    ],
                },
                # --- MetricsThresholdTable ---
                {
                    "table_name": self.metrics_threshold_table.table_name,
                    "items": [
                        {"metric_name": "denial_rate", "threshold": 0.3,
                         "description": "Maximum acceptable denial rate"},
                        {"metric_name": "escalation_rate", "threshold": 0.2,
                         "description": "Maximum acceptable escalation rate"},
                        {"metric_name": "avg_risk_score", "threshold": 60,
                         "description": "Maximum acceptable average risk score"},
                    ],
                },
                # --- MultiAgentConfigTable ---
                {
                    "table_name": self.multi_agent_config_table.table_name,
                    "items": [
                        {
                            "agent_id": "demo-agent",
                            "policy_binding_ids": ["default-deny", "allow-read-at-scope-1"],
                            "risk_profile": {"base_risk": 10, "escalation_threshold": 70},
                            "evidence_partition": "evidence/demo-agent/",
                            "environment": "dev",
                        },
                    ],
                },
                # --- RuntimeDriftTable (Phase 4) ---
                {
                    "table_name": self.runtime_drift_table.table_name,
                    "items": [
                        {
                            "agent_id": "demo-agent",
                            "record_type": "baseline",
                            "action_group_frequencies": {
                                "ReadPipelineStatus": 0.7,
                                "ProposeChanges": 0.2,
                                "StagingDeployment": 0.08,
                                "ProductionDeployment": 0.02,
                            },
                            "target_resources": ["pipeline_status", "deployment_config"],
                            "avg_risk_score": 22,
                            "window_hours": 24,
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                    ],
                },
                # --- AgentHealthTable (Phase 4) ---
                {
                    "table_name": self.agent_health_table.table_name,
                    "items": [
                        {
                            "agent_id": "demo-agent",
                            "record_type": "health_state",
                            "health_score": 85,
                            "status": "healthy",
                            "last_action_at": "2025-01-15T10:30:00Z",
                            "denial_rate_1h": 0.05,
                            "avg_latency_ms": 120,
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                    ],
                },
                # --- ToolAuthTable (Phase 4) ---
                {
                    "table_name": self.tool_auth_table.table_name,
                    "items": [
                        {
                            "pk": "RULE#ReadPipelineStatus",
                            "sk": "CONFIG",
                            "tool_name": "ReadPipelineStatus",
                            "rate_limit": 30,
                            "rate_window_seconds": 60,
                            "allowed_agents": ["demo-agent"],
                            "min_scope": 1,
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                        {
                            "pk": "RULE#ProposeChanges",
                            "sk": "CONFIG",
                            "tool_name": "ProposeChanges",
                            "rate_limit": 10,
                            "rate_window_seconds": 60,
                            "allowed_agents": ["demo-agent"],
                            "min_scope": 2,
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                        {
                            "pk": "RULE#ProductionDeployment",
                            "sk": "CONFIG",
                            "tool_name": "ProductionDeployment",
                            "rate_limit": 2,
                            "rate_window_seconds": 3600,
                            "allowed_agents": ["demo-agent"],
                            "min_scope": 4,
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                        {
                            "pk": "RULE#SensitiveDataExport",
                            "sk": "CONFIG",
                            "tool_name": "SensitiveDataExport",
                            "rate_limit": 0,
                            "rate_window_seconds": 60,
                            "allowed_agents": [],
                            "min_scope": 99,
                            "blocked": True,
                            "block_reason": "Sensitive data export is globally blocked",
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                        {
                            "pk": "CHAIN#exfiltration_pattern",
                            "sk": "DEFINITION",
                            "chain_name": "exfiltration_pattern",
                            "description": "Detects potential data exfiltration via tool chaining",
                            "sequence": [
                                "ReadPipelineStatus",
                                "SensitiveDataExport",
                            ],
                            "window_seconds": 300,
                            "action": "DENY",
                            "risk_boost": 50,
                            "updated_at": "2025-01-15T10:30:00Z",
                        },
                    ],
                },
            ],
        }

        # --- Single AwsCustomResource to invoke the seed Lambda ---

        self.seed_tables_trigger = cr.AwsCustomResource(
            self,
            "SeedTablesTrigger",
            on_create=cr.AwsSdkCall(
                service="Lambda",
                action="invoke",
                parameters={
                    "FunctionName": self.seed_tables_lambda.function_name,
                    "InvocationType": "RequestResponse",
                    "Payload": json.dumps(seed_payload),
                },
                physical_resource_id=cr.PhysicalResourceId.of("SeedTablesTrigger"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["lambda:InvokeFunction"],
                    resources=[self.seed_tables_lambda.function_arn],
                ),
            ]),
        )
