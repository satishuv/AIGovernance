"""Tests for EgressGovernor -- incident-2 class attack prevention.

Covers:
  - External account creation blocked
  - Free-email registration attempt blocked
  - Package publish to PyPI/npm blocked below scope 4
  - Package publish allowed at scope 4
  - Dependency confusion: package name in session instructions blocked
  - Registry URL in publish params blocked
  - Benign action passes through
  - Exception safety: bad input does not raise
"""

import pytest
from egress_governor import EgressGovernor


@pytest.fixture
def gov():
    return EgressGovernor()


class TestAccountCreation:
    def test_account_creation_action_blocked(self, gov):
        v = gov.evaluate(
            action_group="CreateAccount",
            scope_level=3,
            input_text="create a new account at example.com",
            tool_parameters={},
        )
        assert not v.allowed
        assert "external_account_creation_blocked" in v.checks_failed

    def test_free_email_registration_blocked(self, gov):
        v = gov.evaluate(
            action_group="CreateAccount",
            scope_level=3,
            input_text="register with email user@gmail.com",
            tool_parameters={"email": "user@gmail.com"},
        )
        assert not v.allowed
        assert "free_email_registration_attempt" in v.checks_failed

    def test_register_user_blocked(self, gov):
        v = gov.evaluate(
            action_group="RegisterUser",
            scope_level=4,
            input_text="register user on service",
            tool_parameters={},
        )
        assert not v.allowed
        assert "external_account_creation_blocked" in v.checks_failed


class TestPackagePublish:
    def test_pypi_publish_below_scope4_blocked(self, gov):
        v = gov.evaluate(
            action_group="PublishPackage",
            scope_level=2,
            input_text="upload my-lib to pypi.org",
            tool_parameters={"target": "https://upload.pypi.org/legacy/"},
        )
        assert not v.allowed
        assert any("publish_requires_scope" in c for c in v.checks_failed)

    def test_pypi_publish_blocked_by_registry_pattern(self, gov):
        v = gov.evaluate(
            action_group="PublishPackage",
            scope_level=4,
            input_text="publish package",
            tool_parameters={"target": "https://upload.pypi.org/legacy/"},
        )
        assert not v.allowed
        assert "publish_target_is_public_registry" in v.checks_failed

    def test_npm_publish_blocked(self, gov):
        v = gov.evaluate(
            action_group="NpmPublish",
            scope_level=3,
            input_text="npm publish",
            tool_parameters={"registry": "https://registry.npmjs.org"},
        )
        assert not v.allowed

    def test_internal_registry_allowed_at_scope4(self, gov):
        v = gov.evaluate(
            action_group="PublishPackage",
            scope_level=4,
            input_text="publish to internal nexus",
            tool_parameters={"target": "https://nexus.internal.corp/repo/"},
        )
        assert v.allowed

    def test_docker_push_to_ghcr_blocked(self, gov):
        v = gov.evaluate(
            action_group="DockerPush",
            scope_level=4,
            input_text="push image to ghcr.io/myorg/myimage:latest",
            tool_parameters={"repository": "ghcr.io/myorg/myimage"},
        )
        assert not v.allowed
        assert "publish_target_is_public_registry" in v.checks_failed


class TestDependencyConfusion:
    def test_package_name_in_session_instructions_blocked(self, gov):
        session = "Install requirements: pip install governance-sdk==1.2.3"
        v = gov.evaluate(
            action_group="PublishPackage",
            scope_level=4,
            input_text="publish governance-sdk",
            tool_parameters={"name": "governance-sdk"},
            session_instructions=session,
        )
        assert not v.allowed
        assert any("dependency_confusion" in c for c in v.checks_failed)

    def test_unrelated_package_name_not_blocked(self, gov):
        session = "Install requirements: pip install governance-sdk==1.2.3"
        v = gov.evaluate(
            action_group="PublishPackage",
            scope_level=4,
            input_text="publish my-internal-tool",
            tool_parameters={"name": "my-internal-tool"},
            session_instructions=session,
        )
        # No registry target, no confusion match -- only scope check (passes at 4)
        assert v.allowed


class TestBenignActions:
    def test_read_action_passes(self, gov):
        v = gov.evaluate(
            action_group="ReadPipelineStatus",
            scope_level=1,
            input_text="get build status",
            tool_parameters={},
        )
        assert v.allowed

    def test_production_deploy_not_blocked_by_egress(self, gov):
        # EgressGovernor only covers external-publish actions,
        # not production deploys (those are handled by scope enforcement + OPA)
        v = gov.evaluate(
            action_group="ProductionDeployment",
            scope_level=3,
            input_text="deploy service to prod",
            tool_parameters={},
        )
        assert v.allowed

    def test_empty_inputs_allowed(self, gov):
        v = gov.evaluate(
            action_group="",
            scope_level=1,
            input_text="",
            tool_parameters={},
        )
        assert v.allowed


class TestRiskDelta:
    def test_blocked_verdict_has_nonzero_risk_delta(self, gov):
        v = gov.evaluate(
            action_group="PublishPackage",
            scope_level=1,
            input_text="publish to pypi",
            tool_parameters={"target": "https://upload.pypi.org/legacy/"},
        )
        assert not v.allowed
        assert v.risk_delta > 0

    def test_allowed_verdict_has_zero_risk_delta(self, gov):
        v = gov.evaluate(
            action_group="ReadBuildResults",
            scope_level=2,
            input_text="get results",
            tool_parameters={},
        )
        assert v.allowed
        assert v.risk_delta == 0


class TestTraceExtra:
    def test_to_trace_extra_shape(self, gov):
        v = gov.evaluate(
            action_group="PublishPackage",
            scope_level=1,
            input_text="push",
            tool_parameters={},
        )
        extra = v.to_trace_extra()
        assert "egress_allowed" in extra
        assert "egress_checks_failed" in extra
        assert isinstance(extra["egress_checks_failed"], list)
