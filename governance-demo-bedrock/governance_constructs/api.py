from aws_cdk import (
    aws_apigateway as apigw,
)
from constructs import Construct


class ApiConstruct(Construct):
    """API Gateway endpoints for kill switch and approval workflow."""

    def __init__(
        self, scope: Construct, construct_id: str, *, governance_engine, **kwargs
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # --- Kill Switch API ---

        self.kill_switch_api = apigw.RestApi(
            self,
            "KillSwitchApi",
            rest_api_name="GovernanceKillSwitchAPI",
            description="API Gateway for Kill Switch activate/deactivate",
            deploy_options=apigw.StageOptions(
                stage_name="prod",
                tracing_enabled=True,
            ),
        )

        kill_switch_resource = self.kill_switch_api.root.add_resource("kill-switch")
        activate_resource = kill_switch_resource.add_resource("activate")
        deactivate_resource = kill_switch_resource.add_resource("deactivate")

        kill_switch_integration = apigw.LambdaIntegration(
            governance_engine.kill_switch_phase1c_lambda,
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

        # --- Approval API ---

        self.approval_api = apigw.RestApi(
            self,
            "ApprovalApi",
            rest_api_name="GovernanceApprovalAPI",
            description="API Gateway for approval workflow and decision history",
            deploy_options=apigw.StageOptions(
                stage_name="prod",
                tracing_enabled=True,
            ),
        )

        governance_integration = apigw.LambdaIntegration(
            governance_engine.governance_engine_lambda,
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

        # Decision History endpoints
        decisions_resource = self.approval_api.root.add_resource("decisions")
        decisions_agent_resource = decisions_resource.add_resource("{agent_id}")

        decisions_agent_resource.add_method(
            "GET",
            governance_integration,
            authorization_type=apigw.AuthorizationType.IAM,
        )
