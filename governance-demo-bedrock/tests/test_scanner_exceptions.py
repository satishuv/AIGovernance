"""Infrastructure findings from the ASH 3.7.1 container scan (2026-10-22) and the scanner exceptions.

The container ran every ASH scanner on the synthesized template, including cdk-nag, cfn-nag and
checkov, which had not evaluated it before. Fixed here, each asserted on the template:

- every Lambda function that wrote evidence held s3:DeleteObject* on the evidence buckets (Object
  Lock does not protect against delete markers, which hide evidence from every reader);
- eight tables were provisioned at 5 read and 5 write units, including the scope and tool
  authorization tables on the decision path, and no table had point-in-time recovery;
- buckets did not require TLS or log access, the operator alert topic was not encrypted, the API
  stages wrote no access logs, and the Express state machine (which keeps no execution history)
  logged nothing;
- an asynchronously invoked function (decision events, the monthly report) had no dead-letter
  queue, so a failed decision event and its evidence were dropped;
- the guardrail and agent invocation permissions used wildcards.

The remaining findings are reviewed exceptions in governance_constructs/scanner_exceptions.py; the
tests below fail on any cdk-nag finding that is not acknowledged and on any exception without a
reason.
"""

import json
import os
import sys

import aws_cdk as cdk
import cdk_nag
import pytest
from aws_cdk.assertions import Template

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

from governance_bedrock_stack import GovernanceBedrockStack  # noqa: E402
from governance_constructs.scanner_exceptions import STAR_ACTIONS  # noqa: E402

REGION = "us-east-1"


def _stack(context=None, outdir=None):
    app = cdk.App(context={"skip_cloudtrail": False, **(context or {})}, outdir=outdir)
    return app, GovernanceBedrockStack(app, "TestStack", env=cdk.Environment(region=REGION))


@pytest.fixture(scope="module")
def resources():
    _, stack = _stack()
    return Template.from_stack(stack).to_json()["Resources"]


def _of_type(resources, *cfn_types):
    return {lid: r for lid, r in resources.items() if r["Type"] in cfn_types}


POLICIES = ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy")  # CDK moves overflow statements to managed policies


def _logical_id(resources, prefix, cfn_type):
    matches = [lid for lid, r in resources.items() if lid.startswith(prefix) and r["Type"] == cfn_type]
    assert len(matches) == 1, (prefix, matches)
    return matches[0]


def _statements(resource):
    props = resource["Properties"]
    documents = [props.get("PolicyDocument")] + [p["PolicyDocument"] for p in props.get("Policies", [])]
    return [s for d in documents if d for s in d["Statement"]]


def _list(value):
    return value if isinstance(value, list) else [value]


# ----------------------------------------------------------------------------------- scanners
def test_cdk_nag_reports_nothing_unacknowledged(tmp_path):
    app, _ = _stack(outdir=str(tmp_path))
    cdk.Validations.of(app).add_plugins(cdk_nag.AwsSolutionsChecks(verbose=True))
    try:
        app.synth()
    except RuntimeError:
        pass  # synthesis raises when the plugin reports a violation; the report says which
    report = json.loads((tmp_path / "validation-report.json").read_text(encoding="utf-8"))
    violations = [(v["ruleName"], c["constructPath"]) for v in report["pluginReports"][0].get("violations", [])
                  for c in v.get("violatingConstructs", [])]
    assert violations == []


def test_every_exception_has_a_reason(resources):
    seen = 0
    for lid, resource in resources.items():
        metadata = resource.get("Metadata", {})
        entries = (metadata.get("cfn_nag", {}).get("rules_to_suppress", [])
                   + metadata.get("cdk_nag", {}).get("rules_to_suppress", []))
        for entry in entries:
            assert entry.get("id") and len(entry.get("reason", "").strip()) > 20, (lid, entry)
            seen += 1
        for entry in metadata.get("checkov", {}).get("skip", []):
            assert entry.get("id") and len(entry.get("comment", "").strip()) > 20, (lid, entry)
            seen += 1
    assert seen > 0


def test_resource_star_only_for_actions_without_resource_permissions(resources):
    for lid, resource in resources.items():
        if resource["Type"] not in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::Role"):
            continue
        for statement in _statements(resource):
            if statement["Effect"] == "Allow" and "*" in _list(statement.get("Resource", [])):
                actions = set(_list(statement["Action"]))
                assert actions <= STAR_ACTIONS, (lid, sorted(actions - STAR_ACTIONS))
                if "cloudwatch:PutMetricData" in actions:
                    assert statement["Condition"]["StringEquals"]["cloudwatch:namespace"] == "AGCP/Governance"


# ----------------------------------------------------------------------------------- evidence
def test_no_function_can_delete_or_hide_evidence(resources):
    evidence = [_logical_id(resources, p, "AWS::S3::Bucket")
                for p in ("StorageEvidenceBucket", "StorageImmutableEvidenceBucket")]
    for lid, policy in _of_type(resources, *POLICIES).items():
        if lid.startswith("CustomCDKBucketDeployment"):
            continue  # CloudFormation-run sync of the compliance/ reference data (scanner_exceptions)
        for statement in _statements(policy):
            text = json.dumps(statement.get("Resource"))
            if statement["Effect"] != "Allow" or not any(b in text for b in evidence):
                continue
            actions = set(_list(statement["Action"]))
            assert not {a for a in actions if a.startswith("s3:Delete") or a in ("s3:*", "s3:Abort*")}, (lid, actions)
            assert actions <= {"s3:GetObject", "s3:PutObject", "s3:PutObjectTagging", "s3:ListBucket"}, (lid, actions)


# ----------------------------------------------------------------------------------- data
def test_every_table_is_on_demand_with_point_in_time_recovery(resources):
    tables = _of_type(resources, "AWS::DynamoDB::Table")
    # 27 since the 2026-10-23 audit (run-2): GovernanceRecommendationTable holds guardian
    # recommendations and alerts for human review.
    assert len(tables) == 27
    for lid, table in tables.items():
        props = table["Properties"]
        assert props.get("BillingMode") == "PAY_PER_REQUEST", lid
        assert "ProvisionedThroughput" not in props, lid
        assert props["PointInTimeRecoverySpecification"] == {"PointInTimeRecoveryEnabled": True}, lid


def test_every_bucket_requires_tls_and_logs_access(resources):
    buckets = _of_type(resources, "AWS::S3::Bucket")
    log_bucket = _logical_id(resources, "StorageAccessLogBucket", "AWS::S3::Bucket")
    policies = {json.dumps(p["Properties"]["Bucket"]): p for p in _of_type(resources, "AWS::S3::BucketPolicy").values()}
    for lid, bucket in buckets.items():
        policy = policies[json.dumps({"Ref": lid})]
        assert any(s["Effect"] == "Deny" and s.get("Condition") == {"Bool": {"aws:SecureTransport": "false"}}
                   for s in policy["Properties"]["PolicyDocument"]["Statement"]), lid
        if lid != log_bucket:
            assert bucket["Properties"]["LoggingConfiguration"]["DestinationBucketName"] == {"Ref": log_bucket}, lid
    assert buckets[log_bucket]["Properties"]["BucketEncryption"]["ServerSideEncryptionConfiguration"][0][
        "ServerSideEncryptionByDefault"]["SSEAlgorithm"] == "AES256"


def test_operator_topic_is_encrypted_and_alarms_can_publish(resources):
    key = _logical_id(resources, "StorageDataKey", "AWS::KMS::Key")
    topic = resources[_logical_id(resources, "StorageOperatorAlertsTopic", "AWS::SNS::Topic")]
    assert topic["Properties"]["KmsMasterKeyId"] == {"Fn::GetAtt": [key, "Arn"]}
    statements = resources[key]["Properties"]["KeyPolicy"]["Statement"]
    cloudwatch = [s for s in statements if s.get("Principal") == {"Service": "cloudwatch.amazonaws.com"}]
    assert len(cloudwatch) == 1 and set(cloudwatch[0]["Action"]) == {"kms:Decrypt", "kms:GenerateDataKey*"}
    assert "kms:EncryptionContext:aws:sns:topicArn" in cloudwatch[0]["Condition"]["ArnLike"]
    alarms = _of_type(resources, "AWS::CloudWatch::Alarm")
    assert alarms and all(a["Properties"]["AlarmActions"] == [{"Ref": _logical_id(
        resources, "StorageOperatorAlertsTopic", "AWS::SNS::Topic")}] for a in alarms.values())


def test_trail_encrypts_with_the_data_key_and_the_key_allows_only_that_trail(resources):
    key = _logical_id(resources, "StorageDataKey", "AWS::KMS::Key")
    trail = next(iter(_of_type(resources, "AWS::CloudTrail::Trail").values()))
    assert trail["Properties"]["KMSKeyId"] == {"Fn::GetAtt": [key, "Arn"]}
    statements = [s for s in resources[key]["Properties"]["KeyPolicy"]["Statement"]
                  if s.get("Principal") == {"Service": "cloudtrail.amazonaws.com"}]
    assert {s["Action"] for s in statements} == {"kms:GenerateDataKey*", "kms:DescribeKey"}
    for statement in statements:
        assert "trail/governance-demo-bedrock-trail" in json.dumps(statement["Condition"]["StringEquals"])


def test_function_environments_are_encrypted_except_the_boundary_capped_role(resources):
    key = _logical_id(resources, "StorageDataKey", "AWS::KMS::Key")
    for lid, function in _of_type(resources, "AWS::Lambda::Function").items():
        if "Environment" not in function["Properties"]:
            continue
        if lid.startswith("BedrockAgentActionGroupLambda"):
            assert "KmsKeyArn" not in function["Properties"]
        else:
            assert function["Properties"]["KmsKeyArn"] == {"Fn::GetAtt": [key, "Arn"]}, lid


# ----------------------------------------------------------------------------------- logging
def test_api_stages_write_json_access_logs(resources):
    stages = _of_type(resources, "AWS::ApiGateway::Stage")
    assert len(stages) == 2
    for lid, stage in stages.items():
        settings = stage["Properties"]["AccessLogSetting"]
        assert "DestinationArn" in settings and '"status"' in settings["Format"], lid


def test_state_machine_logs_every_event_without_execution_data(resources):
    machine = next(iter(_of_type(resources, "AWS::StepFunctions::StateMachine").values()))
    logging = machine["Properties"]["LoggingConfiguration"]
    assert logging["Level"] == "ALL" and logging["IncludeExecutionData"] is False
    assert logging["Destinations"][0]["CloudWatchLogsLogGroup"]["LogGroupArn"]


def test_asynchronously_invoked_functions_have_a_dead_letter_queue_that_alarms(resources):
    queue = _logical_id(resources, "GovernanceEngineAsyncInvocationDeadLetterQueue", "AWS::SQS::Queue")
    for prefix in ("GovernanceEngineGovernanceEngineLambda", "GovernanceEnginePostDecisionLambda"):
        function = resources[_logical_id(resources, prefix, "AWS::Lambda::Function")]
        assert function["Properties"]["DeadLetterConfig"] == {"TargetArn": {"Fn::GetAtt": [queue, "Arn"]}}
    key = _logical_id(resources, "StorageDataKey", "AWS::KMS::Key")
    assert resources[queue]["Properties"]["KmsMasterKeyId"] == {"Fn::GetAtt": [key, "Arn"]}
    alarm = resources[_logical_id(resources, "GovernanceEngineAsyncInvocationDeadLetterAlarm",
                                  "AWS::CloudWatch::Alarm")]
    assert alarm["Properties"]["Dimensions"][0]["Value"] == {"Fn::GetAtt": [queue, "QueueName"]}


# ----------------------------------------------------------------------------------- scoping
def _actions_granted(resources, action):
    return [(lid, s) for lid, p in _of_type(resources, *POLICIES).items() for s in _statements(p)
            if s["Effect"] == "Allow" and action in _list(s["Action"])]


def test_guardrail_permission_exists_only_for_a_configured_guardrail(resources):
    assert _actions_granted(resources, "bedrock:ApplyGuardrail") == []
    _, stack = _stack({"bedrock_guardrail_id": "gr-example123"})
    granted = _actions_granted(Template.from_stack(stack).to_json()["Resources"], "bedrock:ApplyGuardrail")
    assert len(granted) == 1
    assert json.dumps(granted[0][1]["Resource"]).endswith(':guardrail/gr-example123"]]}')


def test_scope_enforcer_invokes_only_this_agent_alias(resources):
    alias = _logical_id(resources, "BedrockAgentBedrockAgentAlias", "AWS::Bedrock::AgentAlias")
    granted = _actions_granted(resources, "bedrock:InvokeAgent")
    assert len(granted) == 1 and granted[0][1]["Resource"] == {"Fn::GetAtt": [alias, "AgentAliasArn"]}
    assert _actions_granted(resources, "bedrock:InvokeModel") == []
