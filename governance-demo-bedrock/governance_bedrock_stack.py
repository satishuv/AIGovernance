from aws_cdk import Stack, CfnOutput
from constructs import Construct

from governance_constructs import (
    StorageConstruct,
    BedrockAgentConstruct,
    GovernanceEngineConstruct,
    MonitoringConstruct,
    ApiConstruct,
    SeedDataConstruct,
)


class GovernanceBedrockStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

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
            self.governance_engine.authority_lambda.add_environment(
                "DEMO_ENFORCEMENT_PROBE_KEY", "reports/restricted/salary-bands.csv")
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
