"""Reviewed exceptions to the infrastructure scanners, each with its reason.

cdk-nag 3 (the AWS Solutions rules) reads acknowledgements recorded with
``Validations.of(scope).acknowledge``. cfn-nag and checkov read the resource's CloudFormation
``Metadata`` (``cfn_nag.rules_to_suppress`` and ``checkov.skip``). ``accept`` records one exception
for each scanner that reports the same issue, so a reason is written once, and the synthesized
template carries it (cdk-nag's acknowledgements as ``Metadata.cdk_nag``, written by
``WriteNagSuppressionsToCloudFormationAspect``).

tests/test_scanner_exceptions.py fails on any cdk-nag finding without an acknowledgement, on any
exception without a reason, and on any ``Resource: "*"`` statement whose actions are not the ones the
reasons below name.

ASH (Automated Security Helper) runs cdk-nag on a copy of the template included with CfnInclude.
That path reads neither the acknowledgements nor the template metadata, so ASH lists these cdk-nag
exceptions again; its cfn-nag and checkov runs honour the metadata.
"""

from typing import Sequence

import aws_cdk as cdk
import cdk_nag
import jsii
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_lambda as _lambda
from constructs import IConstruct

# Actions that are allowed on Resource "*" because they have no resource-level permissions.
STAR_ACTIONS = {
    "xray:PutTraceSegments", "xray:PutTelemetryRecords",          # X-Ray trace upload
    "cloudwatch:PutMetricData",                                    # condition: cloudwatch:namespace
    "logs:CreateLogDelivery", "logs:GetLogDelivery", "logs:UpdateLogDelivery", "logs:DeleteLogDelivery",
    "logs:ListLogDeliveries", "logs:PutResourcePolicy", "logs:DescribeResourcePolicies",
    "logs:DescribeLogGroups",                                      # Step Functions log delivery
}


def accept(scope: IConstruct, reason: str, *, cdk_nag_rules: Sequence[str] = (), cfn_nag: Sequence[str] = (),
           checkov: Sequence[str] = (), types: Sequence[str] = ()) -> None:
    """Record a reviewed exception on ``scope`` and every resource under it (of ``types``, if given)."""
    if not reason or not reason.strip():
        raise ValueError("every accepted finding needs a reason")
    for rule in cdk_nag_rules:
        cdk.Validations.of(scope).acknowledge(cdk.Acknowledgment(id=f"AwsSolutions::{rule}", reason=reason))
    if cfn_nag or checkov:
        cdk.Aspects.of(scope).add(_TemplateMetadata(reason, tuple(cfn_nag), tuple(checkov), tuple(types)))


@jsii.implements(cdk.IAspect)
class _TemplateMetadata:
    """Writes cfn-nag and checkov exceptions at synthesis, so resources CDK adds late (overflow managed
    policies, singleton handlers) carry them too."""

    def __init__(self, reason: str, cfn_nag: Sequence[str], checkov: Sequence[str], types: Sequence[str]):
        self.reason, self.cfn_nag, self.checkov, self.types = reason, cfn_nag, checkov, types

    def visit(self, node: IConstruct) -> None:
        if not isinstance(node, cdk.CfnResource) or (self.types and node.cfn_resource_type not in self.types):
            return
        if self.cfn_nag:
            _merge(node, "cfn_nag", "rules_to_suppress", [{"id": r, "reason": self.reason} for r in self.cfn_nag])
        if self.checkov:
            _merge(node, "checkov", "skip", [{"id": r, "comment": self.reason} for r in self.checkov])


def _merge(resource: cdk.CfnResource, tool: str, key: str, entries) -> None:
    metadata = dict(resource.get_metadata(tool) or {})
    current = list(metadata.get(key, []))
    known = {entry["id"] for entry in current}
    current.extend(entry for entry in entries if entry["id"] not in known)
    metadata[key] = current
    resource.add_metadata(tool, metadata)


def _region(stack: cdk.Stack) -> str:
    """The Region as cdk-nag prints it in a finding id."""
    return "<AWS::Region>" if cdk.Token.is_unresolved(stack.region) else stack.region


def _arn_wildcard(stack: cdk.Stack, construct: IConstruct, suffix: str) -> str:
    return f"AwsSolutions-IAM5[Resource::<{stack.get_logical_id(construct.node.default_child)}.Arn>{suffix}]"


def apply(stack) -> None:
    """The reviewed exceptions for GovernanceBedrockStack (``stack``, with its constructs as attributes)."""
    storage, engine, agent = stack.storage, stack.governance_engine, stack.bedrock_agent
    cdk.Aspects.of(stack).add(cdk_nag.WriteNagSuppressionsToCloudFormationAspect())
    lambda_function = ("AWS::Lambda::Function",)

    # ------------------------------------------------------------------ API Gateway
    api = stack.api
    accept(api, "Every method uses AWS_IAM (SigV4) authorization and a Lambda integration; the handlers "
                "validate each request body and path parameter.", cdk_nag_rules=["AwsSolutions-APIG2"])
    accept(api, "Only SigV4-signed requests from IAM principals of this account reach an integration; a web "
                "ACL is a per-deployment choice.", cdk_nag_rules=["AwsSolutions-APIG3"])
    accept(api, "Access logs record every request (caller, source IP, method, path, status) in a log group "
                "encrypted with the data key; execution logging would write to an API Gateway-managed log "
                "group outside that key and retention.", cdk_nag_rules=["AwsSolutions-APIG6"])
    accept(api, "Callers are IAM principals (agent runtimes and operators) authenticated with SigV4, not "
                "Cognito users.", cdk_nag_rules=["AwsSolutions-COG4"])
    accept(api, "Callers are IAM principals; usage plans meter API keys, which these APIs do not use.",
           cfn_nag=["W64", "W68"])
    accept(api, "Approval, kill-switch and grant responses must never be served from a cache.",
           checkov=["CKV_AWS_120"])

    # ------------------------------------------------------------------ IAM
    accept(stack, "AWS managed basic execution policy: CloudWatch Logs write access only (logs:CreateLogGroup, "
                  "logs:CreateLogStream, logs:PutLogEvents).",
           cdk_nag_rules=["AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/"
                          "AWSLambdaBasicExecutionRole]"])
    accept(stack, "AWS managed policy that API Gateway requires for the account's CloudWatch Logs role "
                  "(access logs).",
           cdk_nag_rules=["AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/"
                          "AmazonAPIGatewayPushToCloudWatchLogs]"])
    accept(stack, "Resource \"*\" only for actions without resource-level permissions: X-Ray trace upload, "
                  "cloudwatch:PutMetricData (limited by condition to the AGCP/Governance namespace) and the "
                  "Step Functions log delivery actions. tests/test_scanner_exceptions.py fails on any other.",
           cdk_nag_rules=["AwsSolutions-IAM5[Resource::*]"], cfn_nag=["W11", "W12", "W13"],
           types=("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role"))
    accept(stack, "Policy complexity reflects one resource-scoped statement per table, bucket and key grant.",
           cfn_nag=["W76"], types=("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"))
    tables = [c for c in storage.node.children if isinstance(c, dynamodb.Table)]
    accept(stack, "CDK table grant: the indexes of this one table (ARN suffix /index/*).",
           cdk_nag_rules=[_arn_wildcard(stack, t, "/index/*") for t in tables])
    functions = [c for c in stack.node.find_all() if isinstance(c, _lambda.Function)]
    accept(stack, "lambda:InvokeFunction on this one function and its versions (CDK grant_invoke).",
           cdk_nag_rules=[_arn_wildcard(stack, f, ":*") for f in functions])
    accept(stack, "Publishing to the encrypted operator topic: kms:GenerateDataKey* and kms:Decrypt on the "
                  "data key only (CDK grant_publish).",
           cdk_nag_rules=["AwsSolutions-IAM5[Action::kms:GenerateDataKey*]"])
    function_buckets = [storage.data_bucket, storage.policy_bucket, storage.evidence_bucket,
                        storage.immutable_evidence_bucket]
    for scope in (engine, agent):
        accept(scope, "Object-level actions on the objects of one bucket; never delete "
                      "(StorageConstruct.grant_objects).",
               cdk_nag_rules=[_arn_wildcard(stack, b, "/*") for b in function_buckets])
    accept(engine.delegated_execution_role, "Read-only on the approved-reports prefix by design; each grant's "
                                            "session policy narrows it to the one object the grant names.",
           cdk_nag_rules=[_arn_wildcard(stack, storage.data_bucket, "/reports/approved/*")])
    for boundary in (storage.scope_1_boundary, storage.scope_2_boundary, storage.scope_3_boundary,
                     storage.scope_4_boundary):
        accept(boundary, "Permission boundary for an agent scope: it caps the action group role at the data "
                         "bucket's objects; the scope in force picks the actions.",
               cdk_nag_rules=[_arn_wildcard(stack, storage.data_bucket, "/*")])
    accept(storage.scope_4_boundary, "Scope 4 may write the demo's own log groups (/governance-demo-bedrock/*) "
                                     "in this account and Region.",
           cdk_nag_rules=[f"AwsSolutions-IAM5[Resource::arn:<AWS::Partition>:logs:{_region(stack)}:<AWS::AccountId>"
                          ":log-group:/governance-demo-bedrock/*]"])
    deployment = stack.node.try_find_child("Custom::CDKBucketDeployment8693BB64968944B69AAFB0CC9EB8756C")
    if deployment is not None:
        accept(deployment, "CDK BucketDeployment handler, run only by CloudFormation: it reads the CDK asset "
                           "bucket and syncs sample data, policies and compliance mappings, deleting objects "
                           "under its own prefixes that left the source.",
               cdk_nag_rules=[f"AwsSolutions-IAM5[Action::s3:{a}]" for a in
                              ("Abort*", "DeleteObject*", "GetBucket*", "GetObject*", "List*")]
               + [_arn_wildcard(stack, b, "/*") for b in (storage.data_bucket, storage.policy_bucket,
                                                         storage.evidence_bucket)]
               + ["AwsSolutions-IAM5[Resource::arn:<AWS::Partition>:s3:::cdk-hnb659fds-assets-<AWS::AccountId>-"
                  f"{_region(stack)}/*]"])

    # ------------------------------------------------------------------ Lambda
    accept(stack, "Python 3.12 is a supported Lambda runtime until Oct 31, 2028 (AWS Lambda runtimes table) and "
                  "is the version the code and CI are tested on; CDK's own handlers use the runtime "
                  "aws-cdk-lib sets.", cdk_nag_rules=["AwsSolutions-L1"])
    accept(stack, "The execution role carries the AWS managed basic execution policy (CloudWatch Logs write "
                  "access), which cfn-nag does not read.", cfn_nag=["W58"], types=lambda_function)
    accept(stack, "No VPC in the demo stack: the functions call AWS service endpoints only, over TLS.",
           cfn_nag=["W89"], checkov=["CKV_AWS_117"], types=lambda_function)
    accept(stack, "No reserved concurrency in the demo stack: Lambda keeps at least 100 unreserved concurrent "
                  "executions per account and Region, so any reservation fails in an account with a lower "
                  "quota. The AgentCore deployment reserves concurrency per function.",
           cfn_nag=["W92"], checkov=["CKV_AWS_115"], types=lambda_function)
    async_functions = {engine.governance_engine_lambda, engine.post_decision_lambda}
    for function in functions:
        if function not in async_functions:
            accept(function, "Invoked synchronously (API Gateway, Amazon Bedrock Agents, Step Functions, another "
                             "function, a custom resource or an operator); a dead-letter queue applies only to "
                             "asynchronous invocations.", checkov=["CKV_AWS_116"])
    accept(agent.action_group_lambda, "The scope permission boundary caps this role and grants no KMS action, "
                                      "so a customer managed key could not decrypt the environment; it holds "
                                      "a bucket, a table and a log group name.", checkov=["CKV_AWS_173"])
    for provider in stack.node.children:
        if provider.node.id.startswith(("Custom::S3AutoDeleteObjects", "AWS679f53fac002430cb0da5b7982bd2287",
                                        "Custom::CDKBucketDeployment")):
            accept(provider, "CDK-provided custom resource handler run by CloudFormation, which retries it and "
                             "reports failures as stack events.", checkov=["CKV_AWS_116"],
                   types=lambda_function)

    # ------------------------------------------------------------------ data
    accept(storage, "DynamoDB encrypts these tables at rest with an AWS owned key. A customer managed key "
                    "would need KMS actions in the agent scope permission boundaries; the AgentCore deployment "
                    "uses one.", cfn_nag=["W74"], checkov=["CKV_AWS_119"], types=("AWS::DynamoDB::Table",))
    accept(storage.access_log_bucket, "This is the server access log destination; logging it would log its own "
                                      "log deliveries.", cdk_nag_rules=["AwsSolutions-S1"], cfn_nag=["W35"],
           checkov=["CKV_AWS_18"], types=("AWS::S3::Bucket",))
    accept(storage.evidence_signing_key, "Asymmetric ECC_NIST_P256 signing key: AWS KMS does not rotate "
                                         "asymmetric keys automatically.", cfn_nag=["F19"])
    accept(storage.grant_signing_key, "Asymmetric ECC_NIST_P256 signing key: AWS KMS does not rotate asymmetric "
                                      "keys automatically.", cfn_nag=["F19"])

    # ------------------------------------------------------------------ monitoring and agent
    accept(stack.monitoring, "Fixed alarm names (AGCP-*) are referenced by docs/OPERATIONAL_RUNBOOK.md.",
           cfn_nag=["W28"], types=("AWS::CloudWatch::Alarm",))
    if getattr(stack.monitoring, "governance_trail", None) is not None:
        accept(stack.monitoring.governance_trail, "Single-Region trail of S3 data events on the demo data bucket; "
                                                  "account-wide management events belong to the account or "
                                                  "organization trail.", checkov=["CKV_AWS_67"])
    accept(agent.bedrock_agent, "The demo agent keeps Amazon Bedrock's default encryption (an AWS owned key).",
           checkov=["CKV_AWS_373"])
