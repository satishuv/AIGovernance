"""CDK assertion tests for GovernanceBedrockStack.

Validates: Requirements 16.1, 16.2, 16.3, 16.4, 16.5, 16.6, 16.7
"""

import aws_cdk as cdk
from aws_cdk.assertions import Template, Match
import pytest
import sys
import os

# Add the project root to the path so we can import the stack
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from governance_bedrock_stack import GovernanceBedrockStack


@pytest.fixture(scope="module")
def template():
    """Synthesize the stack once and return the Template for all tests."""
    app = cdk.App(context={"skip_cloudtrail": False})
    stack = GovernanceBedrockStack(app, "TestStack",
        env=cdk.Environment(region="us-east-1"),
    )
    return Template.from_stack(stack)


# --- Requirement 16.1: Bedrock Agent with correct foundation model ---

class TestBedrockAgent:
    """Validates: Requirement 16.1"""

    def test_bedrock_agent_exists_with_correct_model(self, template):
        template.has_resource_properties("AWS::Bedrock::Agent", {
            "FoundationModel": "anthropic.claude-3-haiku-20240307-v1:0",
        })

    def test_bedrock_agent_has_instruction(self, template):
        template.has_resource_properties("AWS::Bedrock::Agent", {
            "Instruction": Match.string_like_regexp("Software Deployment Pipeline Agent"),
        })

    def test_bedrock_agent_idle_timeout(self, template):
        template.has_resource_properties("AWS::Bedrock::Agent", {
            "IdleSessionTTLInSeconds": 600,
        })

    def test_bedrock_agent_alias_exists(self, template):
        template.resource_count_is("AWS::Bedrock::AgentAlias", 1)



# --- Requirement 16.2: All four action groups defined ---

class TestActionGroups:
    """Validates: Requirement 16.2"""

    def test_four_action_groups_defined(self, template):
        template.has_resource_properties("AWS::Bedrock::Agent", {
            "ActionGroups": Match.array_with([
                Match.object_like({"ActionGroupName": "ReadPipelineStatus"}),
                Match.object_like({"ActionGroupName": "ProposeChanges"}),
                Match.object_like({"ActionGroupName": "StagingDeployment"}),
                Match.object_like({"ActionGroupName": "ProductionDeployment"}),
            ]),
        })

    def test_read_pipeline_status_action_group(self, template):
        template.has_resource_properties("AWS::Bedrock::Agent", {
            "ActionGroups": Match.array_with([
                Match.object_like({
                    "ActionGroupName": "ReadPipelineStatus",
                    "ActionGroupExecutor": Match.object_like({
                        "Lambda": Match.any_value(),
                    }),
                }),
            ]),
        })

    def test_propose_changes_action_group(self, template):
        template.has_resource_properties("AWS::Bedrock::Agent", {
            "ActionGroups": Match.array_with([
                Match.object_like({
                    "ActionGroupName": "ProposeChanges",
                    "ActionGroupExecutor": Match.object_like({
                        "Lambda": Match.any_value(),
                    }),
                }),
            ]),
        })

    def test_staging_deployment_action_group(self, template):
        template.has_resource_properties("AWS::Bedrock::Agent", {
            "ActionGroups": Match.array_with([
                Match.object_like({
                    "ActionGroupName": "StagingDeployment",
                    "ActionGroupExecutor": Match.object_like({
                        "Lambda": Match.any_value(),
                    }),
                }),
            ]),
        })

    def test_production_deployment_action_group(self, template):
        template.has_resource_properties("AWS::Bedrock::Agent", {
            "ActionGroups": Match.array_with([
                Match.object_like({
                    "ActionGroupName": "ProductionDeployment",
                    "ActionGroupExecutor": Match.object_like({
                        "Lambda": Match.any_value(),
                    }),
                }),
            ]),
        })



# --- Requirement 16.3: Action Group Lambda with correct config ---

class TestActionGroupLambda:
    """Validates: Requirement 16.3"""

    def test_action_group_lambda_runtime(self, template):
        template.has_resource_properties("AWS::Lambda::Function", {
            "Runtime": "python3.9",
            "Timeout": 60,
            "MemorySize": 512,
        })


# --- Requirement 16.4: Four Permission Boundary managed policies ---

class TestPermissionBoundaries:
    """Validates: Requirement 16.4"""

    def test_scope1_boundary_s3_get_only(self, template):
        template.has_resource_properties("AWS::IAM::ManagedPolicy", {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": "s3:GetObject",
                        "Effect": "Allow",
                    }),
                ]),
            },
        })

    def test_scope2_boundary_s3_get_and_dynamodb_put(self, template):
        template.has_resource_properties("AWS::IAM::ManagedPolicy", {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": "s3:GetObject",
                        "Effect": "Allow",
                    }),
                    Match.object_like({
                        "Action": "dynamodb:PutItem",
                        "Effect": "Allow",
                    }),
                ]),
            },
        })

    def test_scope3_boundary_s3_rw_and_dynamodb_multi(self, template):
        template.has_resource_properties("AWS::IAM::ManagedPolicy", {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": ["s3:GetObject", "s3:PutObject"],
                        "Effect": "Allow",
                    }),
                    Match.object_like({
                        "Action": [
                            "dynamodb:PutItem",
                            "dynamodb:UpdateItem",
                            "dynamodb:GetItem",
                        ],
                        "Effect": "Allow",
                    }),
                ]),
            },
        })

    def test_scope4_boundary_full_access(self, template):
        template.has_resource_properties("AWS::IAM::ManagedPolicy", {
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": "s3:*",
                        "Effect": "Allow",
                    }),
                    Match.object_like({
                        "Action": "dynamodb:*",
                        "Effect": "Allow",
                    }),
                    Match.object_like({
                        "Action": "logs:*",
                        "Effect": "Allow",
                    }),
                ]),
            },
        })

    def test_four_managed_policies_exist(self, template):
        """Verify at least 4 managed policies exist (the 4 scope boundaries)."""
        template.resource_count_is("AWS::IAM::ManagedPolicy", 4)


# --- Requirement 16.5: Kill Switch Lambda exists ---

class TestKillSwitchLambda:
    """Validates: Requirement 16.5"""

    def test_kill_switch_lambda_exists(self, template):
        template.has_resource_properties("AWS::Lambda::Function", {
            "Runtime": "python3.9",
            "Timeout": 10,
            "MemorySize": 128,
        })


# --- Requirement 16.6: Scope Enforcer Lambda exists ---

class TestScopeEnforcerLambda:
    """Validates: Requirement 16.6"""

    def test_scope_enforcer_lambda_exists(self, template):
        template.has_resource_properties("AWS::Lambda::Function", {
            "Runtime": "python3.9",
            "Timeout": 90,
            "MemorySize": 256,
        })


# --- Requirement 16.7: CloudWatch log group and CloudTrail trail ---

class TestAuditResources:
    """Validates: Requirement 16.7"""

    def test_cloudwatch_log_group_exists(self, template):
        template.has_resource_properties("AWS::Logs::LogGroup", {
            "LogGroupName": "/governance-demo-bedrock/agent-actions",
            "RetentionInDays": 30,
        })

    def test_cloudtrail_trail_exists(self, template):
        template.resource_count_is("AWS::CloudTrail::Trail", 1)

    def test_cloudtrail_trail_properties(self, template):
        template.has_resource_properties("AWS::CloudTrail::Trail", {
            "IsLogging": True,
            "TrailName": "governance-demo-bedrock-trail",
        })
