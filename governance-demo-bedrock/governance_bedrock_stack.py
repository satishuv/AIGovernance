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

        self.storage = StorageConstruct(self, "Storage")

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

        # --- Outputs ---

        CfnOutput(self, "AgentId", value=self.bedrock_agent.bedrock_agent.attr_agent_id)
        CfnOutput(self, "AgentAliasId", value=self.bedrock_agent.bedrock_agent_alias.attr_agent_alias_id)
        CfnOutput(self, "KillSwitchApiUrl", value=self.api.kill_switch_api.url)
        CfnOutput(self, "ApprovalApiUrl", value=self.api.approval_api.url)
        CfnOutput(self, "DashboardName", value=self.monitoring.governance_dashboard.dashboard_name)
