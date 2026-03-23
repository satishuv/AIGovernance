"""CDK template assertion tests for AgenticGovernanceDemoStack.

Validates: Requirements 1.1, 1.2, 2.1, 4.2, 4.3, 4.4, 4.5, 5.1, 5.4, 6.1, 7.1, 9.1, 9.2, 9.3, 10.1
"""

import sys
import os
import json
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import aws_cdk as cdk
from aws_cdk.assertions import Template, Match
from governance_stack import AgenticGovernanceDemoStack


@pytest.fixture(scope="module")
def template():
    """Synthesize the stack and return a Template for assertions."""
    app = cdk.App()
    stack = AgenticGovernanceDemoStack(app, "TestStack",
        env=cdk.Environment(region="us-east-1")
    )
    return Template.from_stack(stack)


# ---------------------------------------------------------------------------
# Resource count tests
# ---------------------------------------------------------------------------

class TestResourceCounts:
    """Verify the stack contains the expected number of each resource type."""

    def test_lambda_function_count(self, template):
        """At least 3 Lambda functions (CDK adds helpers for BucketDeployment/AutoDelete)."""
        resources = template.find_resources("AWS::Lambda::Function")
        assert len(resources) >= 3

    def test_dynamodb_table_count(self, template):
        template.resource_count_is("AWS::DynamoDB::Table", 2)

    def test_s3_bucket_count(self, template):
        """At least 2 S3 buckets (CDK adds helper buckets)."""
        resources = template.find_resources("AWS::S3::Bucket")
        assert len(resources) >= 2

    def test_managed_policy_count(self, template):
        template.resource_count_is("AWS::IAM::ManagedPolicy", 4)

    def test_log_group_count(self, template):
        """At least 1 CloudWatch log group."""
        resources = template.find_resources("AWS::Logs::LogGroup")
        assert len(resources) >= 1

    def test_cloudtrail_trail_count(self, template):
        template.resource_count_is("AWS::CloudTrail::Trail", 1)


# ---------------------------------------------------------------------------
# Agent Lambda configuration tests
# ---------------------------------------------------------------------------

class TestAgentLambda:
    """Verify Agent Lambda has correct runtime, timeout, and memory."""

    def test_agent_lambda_runtime(self, template):
        template.has_resource_properties("AWS::Lambda::Function", {
            "Runtime": "python3.9",
            "Timeout": 60,
            "MemorySize": 512,
        })

    def test_agent_lambda_timeout(self, template):
        template.has_resource_properties("AWS::Lambda::Function", {
            "Timeout": 60,
        })

    def test_agent_lambda_memory(self, template):
        template.has_resource_properties("AWS::Lambda::Function", {
            "MemorySize": 512,
        })


# ---------------------------------------------------------------------------
# Data Bucket configuration tests
# ---------------------------------------------------------------------------

class TestDataBucket:
    """Verify Data Bucket has SSE-S3, public access blocked, versioning enabled."""

    def test_data_bucket_encryption(self, template):
        template.has_resource_properties("AWS::S3::Bucket", {
            "BucketEncryption": {
                "ServerSideEncryptionConfiguration": Match.array_with([
                    {
                        "ServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "AES256",
                        },
                    },
                ]),
            },
        })

    def test_data_bucket_public_access_blocked(self, template):
        template.has_resource_properties("AWS::S3::Bucket", {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "BlockPublicPolicy": True,
                "IgnorePublicAcls": True,
                "RestrictPublicBuckets": True,
            },
        })

    def test_data_bucket_versioning(self, template):
        template.has_resource_properties("AWS::S3::Bucket", {
            "VersioningConfiguration": {
                "Status": "Enabled",
            },
        })


# ---------------------------------------------------------------------------
# CloudWatch log group tests
# ---------------------------------------------------------------------------

class TestCloudWatchLogGroup:
    """Verify CloudWatch log group name and retention."""

    def test_log_group_name(self, template):
        template.has_resource_properties("AWS::Logs::LogGroup", {
            "LogGroupName": "/governance-demo/agent-actions",
        })

    def test_log_group_retention(self, template):
        template.has_resource_properties("AWS::Logs::LogGroup", {
            "RetentionInDays": 30,
        })


# ---------------------------------------------------------------------------
# DynamoDB table tests
# ---------------------------------------------------------------------------

class TestDynamoDBTables:
    """Verify Scope Table and Pending Table partition keys."""

    def test_scope_table_partition_key(self, template):
        template.has_resource_properties("AWS::DynamoDB::Table", {
            "KeySchema": Match.array_with([
                {"AttributeName": "agent_id", "KeyType": "HASH"},
            ]),
        })

    def test_pending_table_partition_key(self, template):
        template.has_resource_properties("AWS::DynamoDB::Table", {
            "KeySchema": Match.array_with([
                {"AttributeName": "request_id", "KeyType": "HASH"},
            ]),
        })


# ---------------------------------------------------------------------------
# Permission boundary policy tests
# ---------------------------------------------------------------------------

class TestPermissionBoundaries:
    """Verify the four permission boundary policies exist with correct names."""

    def test_scope_1_boundary_exists(self, template):
        template.has_resource_properties("AWS::IAM::ManagedPolicy", {
            "ManagedPolicyName": "scope-1-boundary",
        })

    def test_scope_2_boundary_exists(self, template):
        template.has_resource_properties("AWS::IAM::ManagedPolicy", {
            "ManagedPolicyName": "scope-2-boundary",
        })

    def test_scope_3_boundary_exists(self, template):
        template.has_resource_properties("AWS::IAM::ManagedPolicy", {
            "ManagedPolicyName": "scope-3-boundary",
        })

    def test_scope_4_boundary_exists(self, template):
        template.has_resource_properties("AWS::IAM::ManagedPolicy", {
            "ManagedPolicyName": "scope-4-boundary",
        })

    def test_scope_1_boundary_actions(self, template):
        """Scope 1 boundary allows only s3:GetObject on Data Bucket."""
        template.has_resource_properties("AWS::IAM::ManagedPolicy", {
            "ManagedPolicyName": "scope-1-boundary",
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": "s3:GetObject",
                        "Effect": "Allow",
                    }),
                ]),
            },
        })

    def test_scope_2_boundary_actions(self, template):
        """Scope 2 boundary allows s3:GetObject + dynamodb:PutItem."""
        template.has_resource_properties("AWS::IAM::ManagedPolicy", {
            "ManagedPolicyName": "scope-2-boundary",
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

    def test_scope_3_boundary_actions(self, template):
        """Scope 3 boundary allows s3:Get/Put + dynamodb:Put/Update/Get."""
        template.has_resource_properties("AWS::IAM::ManagedPolicy", {
            "ManagedPolicyName": "scope-3-boundary",
            "PolicyDocument": {
                "Statement": Match.array_with([
                    Match.object_like({
                        "Action": Match.array_with(["s3:GetObject", "s3:PutObject"]),
                        "Effect": "Allow",
                    }),
                    Match.object_like({
                        "Action": Match.array_with([
                            "dynamodb:PutItem",
                            "dynamodb:UpdateItem",
                            "dynamodb:GetItem",
                        ]),
                        "Effect": "Allow",
                    }),
                ]),
            },
        })

    def test_scope_4_boundary_actions(self, template):
        """Scope 4 boundary allows s3:*, dynamodb:*, logs:*."""
        template.has_resource_properties("AWS::IAM::ManagedPolicy", {
            "ManagedPolicyName": "scope-4-boundary",
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
