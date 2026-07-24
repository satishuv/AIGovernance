import os

from aws_cdk import (
    RemovalPolicy,
    aws_s3 as s3,
    aws_s3_deployment as s3deploy,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_sns as sns,
    aws_kms as kms,
)
from constructs import Construct


class StorageConstruct(Construct):
    """S3 buckets, DynamoDB tables, permission boundaries, and SNS topics."""

    def __init__(self, scope: Construct, construct_id: str, *, retention_days: int = 365, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- S3 Buckets ---

        self.data_bucket = s3.Bucket(
            self,
            "DataBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        self.policy_bucket = s3.Bucket(
            self,
            "PolicyBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        self.evidence_bucket = s3.Bucket(
            self,
            "EvidenceBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            removal_policy=RemovalPolicy.DESTROY,
            auto_delete_objects=True,
        )

        # Immutable evidence bucket: COMPLIANCE-mode Object Lock makes objects
        # WORM (undeletable until retention expires), so the stack must RETAIN
        # the bucket on delete. A DESTROY policy is self-contradictory here --
        # `cdk destroy` would fail because CloudFormation cannot delete a bucket
        # whose objects are locked -- so we retain it as the production setting.
        self.immutable_evidence_bucket = s3.Bucket(
            self,
            "ImmutableEvidenceBucket",
            encryption=s3.BucketEncryption.S3_MANAGED,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            versioned=True,
            object_lock_enabled=True,
            removal_policy=RemovalPolicy.RETAIN,
            auto_delete_objects=False,
        )

        cfn_bucket = self.immutable_evidence_bucket.node.default_child
        cfn_bucket.add_property_override(
            "ObjectLockConfiguration",
            {
                "ObjectLockEnabled": "Enabled",
                "Rule": {
                    "DefaultRetention": {
                        "Mode": "COMPLIANCE",
                        "Days": retention_days,
                    }
                },
            },
        )

        # --- Evidence signing key (AARM R5/R6) ---
        # Asymmetric ECC key for offline-verifiable, non-repudiable signatures
        # over evidence receipts. Public key is exportable via kms:GetPublicKey
        # for offline verification; the private key never leaves KMS. RETAIN so
        # historical receipts stay verifiable even if the stack is torn down.
        self.evidence_signing_key = kms.Key(
            self,
            "EvidenceSigningKey",
            description="AARM R5/R6 evidence receipt signing key (ECDSA P-256)",
            key_spec=kms.KeySpec.ECC_NIST_P256,
            key_usage=kms.KeyUsage.SIGN_VERIFY,
            removal_policy=RemovalPolicy.RETAIN,
        )

        # --- DynamoDB Tables ---

        self.scope_table = dynamodb.Table(
            self,
            "ScopeTable",
            partition_key=dynamodb.Attribute(
                name="agent_id", type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )

        self.pending_table = dynamodb.Table(
            self,
            "PendingTable",
            partition_key=dynamodb.Attribute(
                name="request_id", type=dynamodb.AttributeType.STRING
            ),
            removal_policy=RemovalPolicy.DESTROY,
        )

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

        # Auditor decision-trace store: signed, per-decision "why" rationale.
        self.decision_trace_table = dynamodb.Table(
            self,
            "DecisionTraceTable",
            partition_key=dynamodb.Attribute(
                name="decision_id", type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,
        )

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

        # --- IAM Permission Boundaries ---

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

        self.scope_4_boundary = iam.ManagedPolicy(
            self,
            "Scope4Boundary",
            statements=[
                iam.PolicyStatement(
                    actions=[
                        "s3:GetObject",
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "s3:ListBucket",
                    ],
                    resources=[
                        self.data_bucket.bucket_arn,
                        self.data_bucket.arn_for_objects("*"),
                    ],
                ),
                iam.PolicyStatement(
                    actions=[
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:UpdateItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:Query",
                        "dynamodb:Scan",
                    ],
                    resources=[
                        self.scope_table.table_arn,
                        self.pending_table.table_arn,
                    ],
                ),
                iam.PolicyStatement(
                    actions=[
                        "logs:CreateLogGroup",
                        "logs:CreateLogStream",
                        "logs:PutLogEvents",
                        "logs:DescribeLogStreams",
                    ],
                    resources=[
                        "arn:aws:logs:*:*:log-group:/governance-demo-bedrock/*",
                    ],
                ),
            ],
        )

        # --- SNS Topic ---

        self.operator_alerts_topic = sns.Topic(
            self,
            "OperatorAlertsTopic",
            display_name="Governance Operator Alerts",
        )

        # --- S3 Deployments ---

        stack_dir = os.path.dirname(os.path.dirname(__file__))

        sample_data_dir = os.path.join(stack_dir, "sample_data")
        self.sample_data_deployment = s3deploy.BucketDeployment(
            self,
            "SampleDataDeployment",
            sources=[s3deploy.Source.asset(sample_data_dir)],
            destination_bucket=self.data_bucket,
        )

        policies_dir = os.path.join(stack_dir, "sample_data", "policies")
        self.policy_deployment = s3deploy.BucketDeployment(
            self,
            "PolicyDeployment",
            sources=[s3deploy.Source.asset(policies_dir)],
            destination_bucket=self.policy_bucket,
            destination_key_prefix="policies/",
        )

        compliance_dir = os.path.join(stack_dir, "sample_data", "compliance")
        self.compliance_deployment = s3deploy.BucketDeployment(
            self,
            "ComplianceDeployment",
            sources=[s3deploy.Source.asset(compliance_dir)],
            destination_bucket=self.evidence_bucket,
            destination_key_prefix="compliance/",
        )
