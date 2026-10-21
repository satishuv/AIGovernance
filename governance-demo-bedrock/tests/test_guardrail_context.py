"""The Bedrock Guardrail ID comes from CDK context, and a missing ID warns at synth."""
import os
import sys

import aws_cdk as cdk
import pytest
from aws_cdk.assertions import Annotations, Match, Template

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from governance_bedrock_stack import GovernanceBedrockStack  # noqa: E402

_WARNING = Match.string_like_regexp("bedrock_guardrail_id")


def _synth(context):
    app = cdk.App(context={"skip_cloudtrail": True, **context})
    stack = GovernanceBedrockStack(app, "GuardrailContextStack",
                                   env=cdk.Environment(region="us-east-1"))
    return stack, Template.from_stack(stack)


def _guardrail_ids(template):
    """BEDROCK_GUARDRAIL_ID of every Lambda function that sets it."""
    ids = []
    for res in template.find_resources("AWS::Lambda::Function").values():
        env = res.get("Properties", {}).get("Environment", {}).get("Variables", {})
        if "BEDROCK_GUARDRAIL_ID" in env:
            ids.append(env["BEDROCK_GUARDRAIL_ID"])
    return ids


@pytest.fixture(scope="module")
def without_context():
    return _synth({})


@pytest.fixture(scope="module")
def with_context():
    return _synth({"bedrock_guardrail_id": "exampleguardrail"})


def test_no_guardrail_id_is_hard_coded(without_context):
    _, template = without_context
    assert _guardrail_ids(template) == [""]


def test_missing_guardrail_id_warns_at_synth(without_context):
    stack, _ = without_context
    assert Annotations.from_stack(stack).find_warning("*", _WARNING)


def test_context_guardrail_id_reaches_the_lambda(with_context):
    _, template = with_context
    assert _guardrail_ids(template) == ["exampleguardrail"]


def test_configured_guardrail_id_does_not_warn(with_context):
    stack, _ = with_context
    assert not Annotations.from_stack(stack).find_warning("*", _WARNING)
