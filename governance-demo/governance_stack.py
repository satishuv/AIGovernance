import os

from aws_cdk import (
    Stack,
    RemovalPolicy,
    Duration,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    aws_dynamodb as dynamodb,
    custom_resources as cr,
    aws_iam as iam,
    aws_lambda as _lambda,
    aws_logs as logs,
    aws_cloudtrail as cloudtrail,
)
from constructs import Construct


class AgenticGovernanceDemoStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- S3 Buckets ---

        # Data Bucket: used by the agent for reading/writing data objects
        self.data_bucket = s3.Bucket(
            self,
            "DataBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        # CloudTrail log delivery bucket
        self.trail_bucket = s3.Bucket(
            self,
            "TrailBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        # Upload sample data to the Data Bucket
        s3deploy.BucketDeployment(
            self,
            "DeploySampleData",
            sources=[
                s3deploy.Source.asset(
                    os.path.join(os.path.dirname(__file__), "sample_data")
                )
            ],
            destination_bucket=self.data_bucket,
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

        # Scope 1: Read-only access to Data Bucket
        self.scope_1_boundary = iam.ManagedPolicy(
            self,
            "Scope1Boundary",
            managed_policy_name="scope-1-boundary",
            statements=[
                iam.PolicyStatement(
                    actions=["s3:GetObject"],
                    resources=[self.data_bucket.arn_for_objects("*")],
                ),
            ],
        )

        # Scope 2: Read Data Bucket + write to Pending Table
        self.scope_2_boundary = iam.ManagedPolicy(
            self,
            "Scope2Boundary",
            managed_policy_name="scope-2-boundary",
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

        # Scope 3: Read/write Data Bucket + read/write Scope Table
        self.scope_3_boundary = iam.ManagedPolicy(
            self,
            "Scope3Boundary",
            managed_policy_name="scope-3-boundary",
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

        # Scope 4: Full access to all demo resources
        self.scope_4_boundary = iam.ManagedPolicy(
            self,
            "Scope4Boundary",
            managed_policy_name="scope-4-boundary",
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

        # --- Scope Table Initialization ---

        # Initialize Scope Table with default scope_level=1 for demo-agent
        cr.AwsCustomResource(
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
                        "updated_at": {"S": "1970-01-01T00:00:00Z"},
                        "updated_by": {"S": "cdk-init"},
                    },
                },
                physical_resource_id=cr.PhysicalResourceId.of(
                    "ScopeTableInitResource"
                ),
            ),
            policy=cr.AwsCustomResourcePolicy.from_statements(
                [
                    iam.PolicyStatement(
                        actions=["dynamodb:PutItem"],
                        resources=[self.scope_table.table_arn],
                    )
                ]
            ),
        )

        # --- Lambda Execution Roles ---

        # Agent Lambda execution role with Scope 1 boundary by default
        self.agent_role = iam.Role(
            self,
            "AgentLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            permissions_boundary=self.scope_1_boundary,
        )
        self.agent_role.add_to_policy(
            iam.PolicyStatement(
                actions=["bedrock:InvokeModel"],
                resources=["arn:aws:bedrock:*:*:model/*"],
            )
        )

        # Scope Enforcer Lambda execution role
        self.scope_enforcer_role = iam.Role(
            self,
            "ScopeEnforcerLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        )
        # Basic Lambda execution permissions (CloudWatch Logs)
        self.scope_enforcer_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=["arn:aws:logs:*:*:*"],
            )
        )
        # Read access to Scope Table
        self.scope_enforcer_role.add_to_policy(
            iam.PolicyStatement(
                actions=["dynamodb:GetItem"],
                resources=[self.scope_table.table_arn],
            )
        )
        # Write access to Pending Table
        self.scope_enforcer_role.add_to_policy(
            iam.PolicyStatement(
                actions=["dynamodb:PutItem"],
                resources=[self.pending_table.table_arn],
            )
        )
        # Invoke access to Agent Lambda (tightened after function creation via grant_invoke)
        # iam:PutRolePolicy scoped to Agent Lambda's role
        self.scope_enforcer_role.add_to_policy(
            iam.PolicyStatement(
                actions=["iam:PutRolePolicy"],
                resources=[self.agent_role.role_arn],
            )
        )

        # Kill Switch Lambda execution role
        self.kill_switch_role = iam.Role(
            self,
            "KillSwitchLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
        )
        # Basic Lambda execution permissions (CloudWatch Logs)
        self.kill_switch_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "logs:CreateLogGroup",
                    "logs:CreateLogStream",
                    "logs:PutLogEvents",
                ],
                resources=["arn:aws:logs:*:*:*"],
            )
        )
        # Write access to Scope Table
        self.kill_switch_role.add_to_policy(
            iam.PolicyStatement(
                actions=["dynamodb:PutItem", "dynamodb:UpdateItem"],
                resources=[self.scope_table.table_arn],
            )
        )
        # iam:PutRolePolicy scoped to Agent Lambda's role
        self.kill_switch_role.add_to_policy(
            iam.PolicyStatement(
                actions=["iam:PutRolePolicy"],
                resources=[self.agent_role.role_arn],
            )
        )

        # --- Lambda Functions ---

        # Agent Lambda: invokes Bedrock for reasoning, operates under permission boundary
        self.agent_function = _lambda.Function(
            self,
            "AgentFunction",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                os.path.join(os.path.dirname(__file__), "lambdas/agent")
            ),
            role=self.agent_role,
            timeout=Duration.seconds(60),
            memory_size=512,
            environment={
                "DATA_BUCKET_NAME": self.data_bucket.bucket_name,
                "AGENT_ID": "demo-agent",
                "BEDROCK_MODEL_ID": "anthropic.claude-3-haiku-20240307-v1:0",
            },
        )

        # Scope Enforcer Lambda: validates scope level before forwarding requests
        self.scope_enforcer_function = _lambda.Function(
            self,
            "ScopeEnforcerFunction",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                os.path.join(os.path.dirname(__file__), "lambdas/scope_enforcer")
            ),
            role=self.scope_enforcer_role,
            timeout=Duration.seconds(30),
            memory_size=256,
            environment={
                "SCOPE_TABLE_NAME": self.scope_table.table_name,
                "PENDING_TABLE_NAME": self.pending_table.table_name,
                "AGENT_FUNCTION_NAME": self.agent_function.function_name,
                "AGENT_ROLE_NAME": self.agent_role.role_name,
                "SCOPE_1_BOUNDARY_ARN": self.scope_1_boundary.managed_policy_arn,
                "SCOPE_2_BOUNDARY_ARN": self.scope_2_boundary.managed_policy_arn,
                "SCOPE_3_BOUNDARY_ARN": self.scope_3_boundary.managed_policy_arn,
                "SCOPE_4_BOUNDARY_ARN": self.scope_4_boundary.managed_policy_arn,
            },
        )

        # Kill Switch Lambda: emergency revocation of agent permissions
        self.kill_switch_function = _lambda.Function(
            self,
            "KillSwitchFunction",
            runtime=_lambda.Runtime.PYTHON_3_9,
            handler="index.handler",
            code=_lambda.Code.from_asset(
                os.path.join(os.path.dirname(__file__), "lambdas/kill_switch")
            ),
            role=self.kill_switch_role,
            timeout=Duration.seconds(10),
            memory_size=128,
            environment={
                "SCOPE_TABLE_NAME": self.scope_table.table_name,
                "AGENT_ROLE_NAME": self.agent_role.role_name,
            },
        )

        # Tighten Scope Enforcer's lambda:InvokeFunction to target Agent Lambda only
        self.agent_function.grant_invoke(self.scope_enforcer_role)

        # --- Audit Logging ---

        self.agent_log_group = logs.LogGroup(
            self,
            "AgentActionsLogGroup",
            log_group_name="/governance-demo/agent-actions",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY,
        )
        self.agent_log_group.grant_write(self.agent_role)

        # CloudTrail trail for S3 and DynamoDB data events
        # Set context flag "skip_cloudtrail" to "true" to skip trail creation
        # (useful for accounts/regions where CloudTrail is not supported)
        skip_trail = self.node.try_get_context("skip_cloudtrail") == "true"

        if not skip_trail:
            self.trail = cloudtrail.Trail(
                self,
                "GovernanceTrail",
                bucket=self.trail_bucket,
                is_multi_region_trail=False,
            )

            # S3 data events for the Data Bucket
            self.trail.add_s3_event_selector(
                [cloudtrail.S3EventSelector(bucket=self.data_bucket)],
                read_write_type=cloudtrail.ReadWriteType.ALL,
            )

            # DynamoDB data events for Scope and Pending tables
            # CDK L2 Trail only supports S3/Lambda data resource types,
            # so we use the L1 escape hatch to append a DynamoDB event selector.
            cfn_trail = self.trail.node.default_child
            cfn_trail.add_property_override(
                "EventSelectors.1",
                {
                    "ReadWriteType": "All",
                    "DataResources": [
                        {
                            "Type": "AWS::DynamoDB::Table",
                            "Values": [
                                self.scope_table.table_arn,
                                self.pending_table.table_arn,
                            ],
                        }
                    ],
                },
            )

