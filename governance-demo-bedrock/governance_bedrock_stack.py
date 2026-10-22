from aws_cdk import Stack, CfnOutput
from aws_cdk import aws_lambda as _lambda
from constructs import Construct

from governance_constructs import (
    StorageConstruct,
    BedrockAgentConstruct,
    GovernanceEngineConstruct,
    MonitoringConstruct,
    ApiConstruct,
    SeedDataConstruct,
)
from governance_constructs import scanner_exceptions

# S3 server access logs are delivered through the log bucket's policy, not an ACL, so the log
# bucket can keep BucketOwnerEnforced object ownership.
S3_ACCESS_LOGS_USE_BUCKET_POLICY = "@aws-cdk/aws-s3:serverAccessLogsUseBucketPolicy"


class GovernanceBedrockStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        self.node.set_context(S3_ACCESS_LOGS_USE_BUCKET_POLICY, True)

        skip_cloudtrail = self.node.try_get_context("skip_cloudtrail")
        environment = self.node.try_get_context("environment") or "demo"
        retention_days = 2555 if environment == "production" else 365

        self.storage = StorageConstruct(
            self, "Storage", retention_days=retention_days
        )

        self.bedrock_agent = BedrockAgentConstruct(
            self, "BedrockAgent", storage=self.storage
        )

        self.governance_engine = GovernanceEngineConstruct(
            self, "GovernanceEngine",
            storage=self.storage,
            bedrock_agent=self.bedrock_agent,
        )

        self.monitoring = MonitoringConstruct(
            self, "Monitoring",
            storage=self.storage,
            skip_cloudtrail=skip_cloudtrail,
        )

        self.api = ApiConstruct(
            self, "Api",
            governance_engine=self.governance_engine,
            storage=self.storage,
        )

        self.seed_data = SeedDataConstruct(
            self, "SeedData", storage=self.storage
        )

        # --- Optional live delegated-authority demo (off by default) ---
        # With -c delegated_demo_operator=<principal ARN>, the operator can
        # assume a demo agent runtime role that may call ONLY the agent-plane
        # authority routes, and the authority Lambda adds an IAM probe to show
        # that a grant's credential cannot read any other object.
        demo_operator = self.node.try_get_context("delegated_demo_operator")
        if demo_operator:
            from aws_cdk import aws_iam as iam
            api = self.api.approval_api
            agent_runtime = iam.Role(
                self, "DemoAgentRuntimeRole",
                assumed_by=iam.ArnPrincipal(demo_operator),
                description="Demo only: acts as procurement-agent's runtime identity",
            )
            agent_runtime.add_to_policy(iam.PolicyStatement(
                actions=["execute-api:Invoke"],
                resources=[api.arn_for_execute_api("POST", "/authority/requests", "prod"),
                           api.arn_for_execute_api("POST", "/authority-grants/mint", "prod"),
                           api.arn_for_execute_api("POST", "/authority-grants/*/execute", "prod"),
                           api.arn_for_execute_api("GET", "/authority-grants/*", "prod")],
            ))
            # The probe object sits under reports/approved/, which the execution
            # ROLE may read; only the grant's SESSION POLICY forbids it. A denial
            # therefore isolates the session policy's narrowing effect.
            self.governance_engine.authority_lambda.add_environment(
                "DEMO_ENFORCEMENT_PROBE_KEY", "reports/approved/vendor-contacts-2026.csv")
            CfnOutput(self, "DemoAgentRuntimeRoleArn", value=agent_runtime.role_arn)

        # --- Outputs ---

        CfnOutput(self, "AgentId", value=self.bedrock_agent.bedrock_agent.attr_agent_id)
        CfnOutput(self, "AgentAliasId", value=self.bedrock_agent.bedrock_agent_alias.attr_agent_alias_id)
        CfnOutput(self, "KillSwitchApiUrl", value=self.api.kill_switch_api.url)
        CfnOutput(self, "ApprovalApiUrl", value=self.api.approval_api.url)
        CfnOutput(self, "DashboardName", value=self.monitoring.governance_dashboard.dashboard_name)
        CfnOutput(self, "DelegatedExecutionRoleArn",
                  value=self.governance_engine.delegated_execution_role.role_arn)
        CfnOutput(self, "DelegatedAuthorityFunctionName",
                  value=self.governance_engine.authority_lambda.function_name)
        CfnOutput(self, "DataBucketName", value=self.storage.data_bucket.bucket_name)

        self._encrypt_function_environments()
        scanner_exceptions.apply(self)

    def _encrypt_function_environments(self) -> None:
        """Encrypt every function's environment with the data key.

        The action group function is left out: its role is capped by an agent scope permission
        boundary that grants no KMS action, so it could not decrypt its own environment.
        """
        capped = {self.bedrock_agent.action_group_lambda}
        for function in self.node.find_all():
            if not isinstance(function, _lambda.Function) or function in capped:
                continue
            cfn = function.node.default_child
            if cfn.environment is None:
                continue
            cfn.kms_key_arn = self.storage.data_key.key_arn
            self.storage.data_key.grant_decrypt(function)
