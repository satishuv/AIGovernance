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
            "FoundationModel": "amazon.nova-micro-v1:0",
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
            "Runtime": "python3.12",
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
                        "Action": Match.array_with(["s3:GetObject", "s3:PutObject"]),
                        "Effect": "Allow",
                    }),
                    Match.object_like({
                        "Action": Match.array_with(["dynamodb:GetItem", "dynamodb:PutItem"]),
                        "Effect": "Allow",
                    }),
                    Match.object_like({
                        "Action": Match.array_with(["logs:CreateLogGroup"]),
                        "Effect": "Allow",
                    }),
                ]),
            },
        })

    def test_scope_boundary_managed_policies_exist(self, template):
        """Verify at least 4 managed policies exist (the 4 scope boundaries + service role policies)."""
        template.resource_count_is("AWS::IAM::ManagedPolicy", 7)


# --- Requirement 16.5: Kill Switch Lambda exists ---

class TestKillSwitchLambda:
    """Validates: Requirement 16.5"""

    def test_kill_switch_lambda_exists(self, template):
        template.has_resource_properties("AWS::Lambda::Function", {
            "Runtime": "python3.12",
            "Timeout": 30,
            "MemorySize": 128,
        })


# --- Requirement 16.6: Scope Enforcer Lambda exists ---

class TestScopeEnforcerLambda:
    """Validates: Requirement 16.6"""

    def test_scope_enforcer_lambda_exists(self, template):
        template.has_resource_properties("AWS::Lambda::Function", {
            "Runtime": "python3.12",
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



# --- Delegated authority (hall pass) resources ---

class TestDelegatedAuthorityResources:
    """Grant store, signing key, per-grant execution role and IAM-only routes."""

    def test_grant_table_has_ttl_and_agent_index(self, template):
        template.has_resource_properties("AWS::DynamoDB::Table", {
            "KeySchema": [{"AttributeName": "grant_id", "KeyType": "HASH"}],
            "TimeToLiveSpecification": {"AttributeName": "ttl_expiry", "Enabled": True},
            "GlobalSecondaryIndexes": [Match.object_like({"IndexName": "ByAgentId"})],
        })

    def test_request_path_lookups_have_indexes(self, template):
        """P0-18: caller, model-usage and tool-chain lookups are index queries."""
        for table_key, index in (("agent_id", "ByRuntimePrincipal"), ("entry_id", "ByIdentity"),
                                 ("pk", "ByLookupKey")):
            template.has_resource_properties("AWS::DynamoDB::Table", {
                "KeySchema": Match.array_with([{"AttributeName": table_key, "KeyType": "HASH"}]),
                "GlobalSecondaryIndexes": [Match.object_like({"IndexName": index})],
            })

    def test_spend_ledger_table_exists(self, template):
        template.has_resource_properties("AWS::DynamoDB::Table", {
            "KeySchema": [{"AttributeName": "ledger_key", "KeyType": "HASH"}],
        })

    def test_grant_signing_key_is_asymmetric_and_separate(self, template):
        keys = template.find_resources("AWS::KMS::Key", {
            "Properties": {"KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"}})
        assert len(keys) == 2  # evidence signing key + grant signing key

    def test_authority_lambda_is_dedicated(self, template):
        template.has_resource_properties("AWS::Lambda::Function", {
            "Handler": "authority_api.lambda_handler",
            "Environment": {"Variables": Match.object_like({
                "PROVIDER_MODE": "mock", "AWS_PROVIDER_MODE": "live",
                "DELEGATED_EXECUTION_ROLE_ARN": Match.any_value(),
                "GRANT_SIGNING_KEY_ID": Match.any_value(),
            })},
        })

    def test_execution_role_trusts_only_the_authority_lambda(self, template):
        roles = template.find_resources("AWS::IAM::Role", {
            "Properties": {"Description": "Assumed per Delegated Authority Grant with a grant-derived session policy"}})
        assert len(roles) == 1
        statements = list(roles.values())[0]["Properties"]["AssumeRolePolicyDocument"]["Statement"]
        principals = {str(s["Principal"]) for s in statements}
        assert len(principals) == 1 and "DelegatedAuthorityLambdaServiceRole" in principals.pop()

    def test_all_api_methods_require_iam(self, template):
        methods = template.find_resources("AWS::ApiGateway::Method")
        assert methods and all(m["Properties"]["AuthorizationType"] == "AWS_IAM" for m in methods.values())
