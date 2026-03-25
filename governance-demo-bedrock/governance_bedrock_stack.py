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
            runtime=_lambda.Runtime.PYTHON_3_9,
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
                            actions=["bedrock:InvokeModel"],
                            resources=[
                                f"arn:aws:bedrock:{self.region}::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
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
            foundation_model="anthropic.claude-3-haiku-20240307-v1:0",
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
            runtime=_lambda.Runtime.PYTHON_3_9,
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
                actions=["bedrock:InvokeAgent"],
                resources=[self.bedrock_agent.attr_agent_arn],
            )
        )

        self.kill_switch_lambda = _lambda.Function(
            self,
            "KillSwitchLambda",
            runtime=_lambda.Runtime.PYTHON_3_9,
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
            runtime=_lambda.Runtime.PYTHON_3_9,
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

        # --- Task 9.7: Seed DynamoDB tables with initial configuration ---

        risk_config_items = [
            {"config_key": "escalation_threshold", "value": 70,
             "description": "Risk score threshold above which actions are escalated"},
            {"config_key": "scope_level_weights",
             "weights": {"0": 0, "1": 10, "2": 25, "3": 50, "4": 75},
             "description": "Risk weight per scope level"},
            {"config_key": "action_group_weights",
             "weights": {"data_access": 10, "data_modification": 30,
                         "deployment": 50, "configuration_change": 40,
                         "emergency_action": 60},
             "description": "Risk weight per action group category"},
            {"config_key": "target_resource_weights",
             "weights": {"production": 30, "staging": 15,
                         "development": 5, "default": 10},
             "description": "Risk weight per target resource type"},
            {"config_key": "category_base_weights",
             "weights": {"data_access": 5, "data_modification": 15,
                         "deployment": 25, "configuration_change": 20,
                         "emergency_action": 35},
             "description": "Base risk weight per risk category"},
            {"config_key": "history_factor_weight", "value": 5,
             "description": "Risk weight multiplier per recent action in history"},
        ]

        for idx, item in enumerate(risk_config_items):
            ddb_item = {"config_key": {"S": item["config_key"]}}
            if "value" in item:
                ddb_item["value"] = {"N": str(item["value"])}
            if "weights" in item:
                ddb_item["weights"] = {
                    "M": {k: {"N": str(v)} for k, v in item["weights"].items()}
                }
            if "description" in item:
                ddb_item["description"] = {"S": item["description"]}
            cr.AwsCustomResource(
                self, f"RiskConfigSeed{idx}",
                on_create=cr.AwsSdkCall(
                    service="DynamoDB", action="putItem",
                    parameters={
                        "TableName": self.risk_config_table.table_name,
                        "Item": ddb_item,
                    },
                    physical_resource_id=cr.PhysicalResourceId.of(f"RiskConfigSeed{idx}"),
                ),
                policy=cr.AwsCustomResourcePolicy.from_statements([
                    iam.PolicyStatement(
                        actions=["dynamodb:PutItem"],
                        resources=[self.risk_config_table.table_arn],
                    ),
                ]),
            )

        framework_mapping_items = [
            {"action_type": "data_access",
             "iso_42001_controls": ["A.8.4", "A.6.2.2"],
             "nist_ai_rmf_functions": ["GOVERN 1.1", "MAP 1.1"]},
            {"action_type": "data_modification",
             "iso_42001_controls": ["A.8.4", "A.8.5", "A.6.2.2"],
             "nist_ai_rmf_functions": ["GOVERN 1.1", "GOVERN 1.2", "MAP 1.5"]},
            {"action_type": "deployment",
             "iso_42001_controls": ["A.8.2", "A.8.5", "A.6.2.1"],
             "nist_ai_rmf_functions": ["GOVERN 1.2", "MAP 3.4", "MANAGE 1.1"]},
            {"action_type": "configuration_change",
             "iso_42001_controls": ["A.8.2", "A.8.4", "A.6.2.1"],
             "nist_ai_rmf_functions": ["GOVERN 1.1", "GOVERN 1.2", "MANAGE 2.2"]},
            {"action_type": "emergency_action",
             "iso_42001_controls": ["A.8.2", "A.8.5", "A.6.2.1", "A.6.2.2"],
             "nist_ai_rmf_functions": ["GOVERN 1.2", "MANAGE 1.1", "MANAGE 4.1"]},
        ]

        for idx, item in enumerate(framework_mapping_items):
            ddb_item = {
                "action_type": {"S": item["action_type"]},
                "iso_42001_controls": {"L": [{"S": c} for c in item["iso_42001_controls"]]},
                "nist_ai_rmf_functions": {"L": [{"S": f} for f in item["nist_ai_rmf_functions"]]},
            }
            cr.AwsCustomResource(
                self, f"FrameworkMappingSeed{idx}",
                on_create=cr.AwsSdkCall(
                    service="DynamoDB", action="putItem",
                    parameters={
                        "TableName": self.framework_mapping_table.table_name,
                        "Item": ddb_item,
                    },
                    physical_resource_id=cr.PhysicalResourceId.of(f"FrameworkMappingSeed{idx}"),
                ),
                policy=cr.AwsCustomResourcePolicy.from_statements([
                    iam.PolicyStatement(
                        actions=["dynamodb:PutItem"],
                        resources=[self.framework_mapping_table.table_arn],
                    ),
                ]),
            )

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

        # --- Task 21.3: Update ScopeTable seed to include AgentIdentity fields ---

        self.scope_table_init_phase1b = cr.AwsCustomResource(
            self,
            "ScopeTableInitPhase1b",
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
                        "environment": {"S": "dev"},
                        "status": {"S": "active"},
                        "display_name": {"S": "Demo Agent"},
                    },
                },
                physical_resource_id=cr.PhysicalResourceId.of("ScopeTableInitPhase1b"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["dynamodb:PutItem"],
                    resources=[self.scope_table.table_arn],
                ),
            ]),
        )

        # --- Task 21.4: Seed Phase 1b DynamoDB tables with initial data ---

        # Seed AgentRegistryTable with demo agent
        self.agent_registry_seed = cr.AwsCustomResource(
            self,
            "AgentRegistrySeed0",
            on_create=cr.AwsSdkCall(
                service="DynamoDB",
                action="putItem",
                parameters={
                    "TableName": self.agent_registry_table.table_name,
                    "Item": {
                        "agent_id": {"S": "demo-agent"},
                        "purpose": {"S": "Software Deployment Pipeline Agent"},
                        "owner": {"S": "governance-admin"},
                        "data_classes": {"L": [
                            {"S": "pipeline_status"},
                            {"S": "deployment_config"},
                        ]},
                        "tools": {"L": [
                            {"S": "ReadPipelineStatus"},
                            {"S": "ProposeChanges"},
                        ]},
                        "approved_scope": {"N": "2"},
                        "environment": {"S": "dev"},
                    },
                },
                physical_resource_id=cr.PhysicalResourceId.of("AgentRegistrySeed0"),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements([
                iam.PolicyStatement(
                    actions=["dynamodb:PutItem"],
                    resources=[self.agent_registry_table.table_arn],
                ),
            ]),
        )

        # Seed GovernanceRolesTable with initial role assignments
        governance_role_seeds = [
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
        ]

        for idx, role_item in enumerate(governance_role_seeds):
            ddb_item = {
                "user_id": {"S": role_item["user_id"]},
                "role": {"S": role_item["role"]},
                "scope": {"S": role_item["scope"]},
                "assigned_by": {"S": role_item["assigned_by"]},
                "assigned_at": {"S": role_item["assigned_at"]},
            }
            cr.AwsCustomResource(
                self,
                f"GovernanceRoleSeed{idx}",
                on_create=cr.AwsSdkCall(
                    service="DynamoDB",
                    action="putItem",
                    parameters={
                        "TableName": self.governance_roles_table.table_name,
                        "Item": ddb_item,
                    },
                    physical_resource_id=cr.PhysicalResourceId.of(
                        f"GovernanceRoleSeed{idx}"
                    ),
                ),
                policy=cr.AwsCustomResourcePolicy.from_statements([
                    iam.PolicyStatement(
                        actions=["dynamodb:PutItem"],
                        resources=[self.governance_roles_table.table_arn],
                    ),
                ]),
            )

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
            runtime=_lambda.Runtime.PYTHON_3_9,
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

        # --- Task 35.6: Seed Phase 1c DynamoDB tables ---

        # Seed ThreatPatternsTable with known-bad and suspicious patterns
        threat_pattern_seeds = [
            {
                "pattern_id": "kb-sql-injection-1",
                "category": "known_bad",
                "pattern": "';\\s*drop\\s+table",
                "description": "SQL injection: DROP TABLE attempt",
                "risk_weight": 100,
                "updated_at": "2025-01-15T10:30:00Z",
            },
            {
                "pattern_id": "kb-sql-injection-2",
                "category": "known_bad",
                "pattern": "or\\s+1\\s*=\\s*1",
                "description": "SQL injection: OR 1=1 tautology",
                "risk_weight": 100,
                "updated_at": "2025-01-15T10:30:00Z",
            },
            {
                "pattern_id": "kb-prompt-injection-1",
                "category": "known_bad",
                "pattern": "ignore\\s+previous\\s+instructions",
                "description": "Prompt injection: ignore previous instructions",
                "risk_weight": 100,
                "updated_at": "2025-01-15T10:30:00Z",
            },
            {
                "pattern_id": "kb-prompt-injection-2",
                "category": "known_bad",
                "pattern": "system:\\s*override",
                "description": "Prompt injection: system override attempt",
                "risk_weight": 100,
                "updated_at": "2025-01-15T10:30:00Z",
            },
            {
                "pattern_id": "kb-disallowed-cmd-1",
                "category": "known_bad",
                "pattern": "rm\\s+-rf",
                "description": "Disallowed command: rm -rf",
                "risk_weight": 100,
                "updated_at": "2025-01-15T10:30:00Z",
            },
            {
                "pattern_id": "kb-disallowed-cmd-2",
                "category": "known_bad",
                "pattern": "format\\s+c:",
                "description": "Disallowed command: format c:",
                "risk_weight": 100,
                "updated_at": "2025-01-15T10:30:00Z",
            },
            {
                "pattern_id": "sus-partial-prompt-1",
                "category": "suspicious",
                "pattern": "you\\s+are\\s+now",
                "description": "Suspicious: partial prompt injection indicator",
                "risk_weight": 30,
                "updated_at": "2025-01-15T10:30:00Z",
            },
            {
                "pattern_id": "sus-encoding-1",
                "category": "suspicious",
                "pattern": "%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}",
                "description": "Suspicious: unusual URL encoding sequences",
                "risk_weight": 20,
                "updated_at": "2025-01-15T10:30:00Z",
            },
            {
                "pattern_id": "sus-length-1",
                "category": "suspicious",
                "pattern": ".{5000,}",
                "description": "Suspicious: anomalous input length (>5000 chars)",
                "risk_weight": 25,
                "updated_at": "2025-01-15T10:30:00Z",
            },
        ]

        for idx, tp in enumerate(threat_pattern_seeds):
            ddb_item = {
                "pattern_id": {"S": tp["pattern_id"]},
                "category": {"S": tp["category"]},
                "pattern": {"S": tp["pattern"]},
                "description": {"S": tp["description"]},
                "risk_weight": {"N": str(tp["risk_weight"])},
                "updated_at": {"S": tp["updated_at"]},
            }
            cr.AwsCustomResource(
                self,
                f"ThreatPatternSeed{idx}",
                on_create=cr.AwsSdkCall(
                    service="DynamoDB",
                    action="putItem",
                    parameters={
                        "TableName": self.threat_patterns_table.table_name,
                        "Item": ddb_item,
                    },
                    physical_resource_id=cr.PhysicalResourceId.of(
                        f"ThreatPatternSeed{idx}"
                    ),
                ),
                policy=cr.AwsCustomResourcePolicy.from_statements([
                    iam.PolicyStatement(
                        actions=["dynamodb:PutItem"],
                        resources=[self.threat_patterns_table.table_arn],
                    ),
                ]),
            )

        # Seed ControlMappingTable from sample_data files
        control_mapping_dir = os.path.join(
            os.path.dirname(__file__), "sample_data", "control_mapping"
        )

        all_mappings = []
        for filename in ["iso42001_mappings.json", "nist_ai_rmf_mappings.json"]:
            filepath = os.path.join(control_mapping_dir, filename)
            with open(filepath) as f:
                data = json.load(f)
            for m in data.get("mappings", []):
                composite_id = f"{m['control_id']}#{m['implementation_component']}"
                all_mappings.append({
                    "control_id": composite_id,
                    "framework": data["framework"],
                    "control_name": m["control_name"],
                    "implementation_component": m["implementation_component"],
                    "evidence_generated": m["evidence_generated"],
                })

        for idx, cm in enumerate(all_mappings):
            ddb_item = {
                "control_id": {"S": cm["control_id"]},
                "framework": {"S": cm["framework"]},
                "control_name": {"S": cm["control_name"]},
                "implementation_component": {"S": cm["implementation_component"]},
                "evidence_generated": {"S": cm["evidence_generated"]},
            }
            cr.AwsCustomResource(
                self,
                f"ControlMappingSeed{idx}",
                on_create=cr.AwsSdkCall(
                    service="DynamoDB",
                    action="putItem",
                    parameters={
                        "TableName": self.control_mapping_table.table_name,
                        "Item": ddb_item,
                    },
                    physical_resource_id=cr.PhysicalResourceId.of(
                        f"ControlMappingSeed{idx}"
                    ),
                ),
                policy=cr.AwsCustomResourcePolicy.from_statements([
                    iam.PolicyStatement(
                        actions=["dynamodb:PutItem"],
                        resources=[self.control_mapping_table.table_arn],
                    ),
                ]),
            )
