import json
import os

from aws_cdk import (
    RemovalPolicy,
    Duration,
    aws_s3_deployment as s3deploy,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_bedrock as bedrock,
    aws_logs as logs,
)
from constructs import Construct


class BedrockAgentConstruct(Construct):
    """Bedrock Agent, action groups, schemas, scope enforcer, and kill switch."""

    def __init__(self, scope: Construct, construct_id: str, *, storage, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        stack = scope
        stack_dir = os.path.dirname(os.path.dirname(__file__))

        # --- Action Group Lambda ---

        self.action_group_lambda_role = iam.Role(
            self,
            "ActionGroupLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                ),
            ],
            permissions_boundary=storage.scope_1_boundary,
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
                os.path.join(stack_dir, "lambdas", "action_group")
            ),
            timeout=Duration.seconds(60),
            memory_size=512,
            tracing=_lambda.Tracing.ACTIVE,
            role=self.action_group_lambda_role,
            environment={
                "DATA_BUCKET_NAME": storage.data_bucket.bucket_name,
                "PENDING_TABLE_NAME": storage.pending_table.table_name,
                "LOG_GROUP_NAME": self.agent_log_group.log_group_name,
            },
        )

        storage.data_bucket.grant_read_write(self.action_group_lambda)
        storage.pending_table.grant_read_write_data(self.action_group_lambda)
        self.agent_log_group.grant_write(self.action_group_lambda)

        # --- Bedrock Agent ---

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
                                f"arn:aws:bedrock:{stack.region}::foundation-model/amazon.nova-micro-v1:0",
                                f"arn:aws:bedrock:{stack.region}::foundation-model/amazon.nova-lite-v1:0",
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

        schemas_dir = os.path.join(stack_dir, "schemas")

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
            destination_bucket=storage.data_bucket,
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

        # --- Scope Enforcer Lambda ---

        scope_boundary_arns = json.dumps({
            "1": storage.scope_1_boundary.managed_policy_arn,
            "2": storage.scope_2_boundary.managed_policy_arn,
            "3": storage.scope_3_boundary.managed_policy_arn,
            "4": storage.scope_4_boundary.managed_policy_arn,
        })

        self.scope_enforcer_lambda = _lambda.Function(
            self,
            "ScopeEnforcerLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                os.path.join(stack_dir, "lambdas", "scope_enforcer")
            ),
            timeout=Duration.seconds(90),
            memory_size=256,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "AGENT_ID": self.bedrock_agent.attr_agent_id,
                "AGENT_ALIAS_ID": self.bedrock_agent_alias.attr_agent_alias_id,
                "SCOPE_TABLE_NAME": storage.scope_table.table_name,
                "ACTION_GROUP_LAMBDA_ROLE_NAME": self.action_group_lambda_role.role_name,
                "SCOPE_BOUNDARY_ARNS": scope_boundary_arns,
            },
        )

        storage.scope_table.grant_read_write_data(self.scope_enforcer_lambda)
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
                    "bedrock-agent:InvokeAgent",
                ],
                resources=["*"],
            )
        )

        # --- Kill Switch Lambda ---

        self.kill_switch_lambda = _lambda.Function(
            self,
            "KillSwitchLambda",
            runtime=_lambda.Runtime.PYTHON_3_12,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                os.path.join(stack_dir, "lambdas", "kill_switch")
            ),
            timeout=Duration.seconds(30),
            memory_size=128,
            tracing=_lambda.Tracing.ACTIVE,
            environment={
                "SCOPE_TABLE_NAME": storage.scope_table.table_name,
                "ACTION_GROUP_LAMBDA_ROLE_NAME": self.action_group_lambda_role.role_name,
            },
        )

        storage.scope_table.grant_write_data(self.kill_switch_lambda)
        self.kill_switch_lambda.add_to_role_policy(
            iam.PolicyStatement(
                actions=["iam:PutRolePolicy"],
                resources=[self.action_group_lambda_role.role_arn],
            )
        )
