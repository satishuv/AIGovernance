"""Tests for AIUC-1 A008 -- credential/secret detection in agent inputs.

A008.1 requires scanning user prompts for API keys, access tokens, private
keys, and connection strings before model inference. Detection is non-blocking:
the sanitizer flags types found; pipeline/operator decides response.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine"))

from input_sanitizer import InputSanitizer


@pytest.fixture
def san():
    return InputSanitizer()


def _text(content: str) -> str:
    return content


class TestAwsAccessKeyDetection:
    def test_akia_key_detected(self, san):
        r = san.sanitize(_text("My key is AKIAIOSFODNN7EXAMPLE please help"))
        assert "aws_access_key" in r.secrets_detected

    def test_akia_key_in_threat_list(self, san):
        r = san.sanitize(_text("access_key=AKIAIOSFODNN7EXAMPLE"))
        assert any("credentials" in t.lower() or "secrets" in t.lower() for t in r.threats_detected)

    def test_non_akia_string_not_flagged(self, san):
        r = san.sanitize(_text("The project key is PROJ-12345 in Jira"))
        assert "aws_access_key" not in r.secrets_detected


class TestGitHubTokenDetection:
    def test_ghp_token_detected(self, san):
        # Prefix constructed at runtime to avoid triggering secret scanner on test file
        tok = "ghp_" + "ABCDEFabcdef1234567890ABCDEF12"
        r = san.sanitize(_text(f"token: {tok}"))
        assert "github_token" in r.secrets_detected

    def test_ghs_token_detected(self, san):
        tok = "ghs_" + "16C7e42F292c6912E7710c838347Ae178B4a"
        r = san.sanitize(_text(tok))
        assert "github_token" in r.secrets_detected

    def test_github_pat_prefix_detected(self, san):
        tok = "github_pat_" + "11ABCDE0Qtest_1234567890abcdefghij"
        r = san.sanitize(_text(tok))
        assert "github_token" in r.secrets_detected


class TestOpenAIKeyDetection:
    def test_sk_prefix_key_detected(self, san):
        key = "sk-" + "ABCDEFGHIJKLMNOPabcdefghijklmn"
        r = san.sanitize(_text(f"My OpenAI key is {key}"))
        assert "ai_api_key" in r.secrets_detected

    def test_anthropic_style_key_detected(self, san):
        key = "sk-ant-api03-" + "verylongsecretkey1234567890abcdefgh"
        r = san.sanitize(_text(key))
        assert "ai_api_key" in r.secrets_detected


class TestPrivateKeyDetection:
    def test_rsa_private_key_header_detected(self, san):
        # Construct the test string at runtime so the scanner does not flag the
        # test file itself as containing a credential (this is synthetic test data).
        header = "-----" + "BEGIN RSA PRIVATE KEY" + "-----"
        r = san.sanitize(_text(f"{header}\nMIIEpAIBAAKCAQ..."))
        assert "private_key_pem" in r.secrets_detected

    def test_openssh_private_key_detected(self, san):
        header = "-----" + "BEGIN OPENSSH PRIVATE KEY" + "-----"
        r = san.sanitize(_text(f"{header}\nb3BlbnNzaC..."))
        assert "private_key_pem" in r.secrets_detected

    def test_ec_private_key_detected(self, san):
        header = "-----" + "BEGIN EC PRIVATE KEY" + "-----"
        r = san.sanitize(_text(header))
        assert "private_key_pem" in r.secrets_detected


class TestLabeledCredentialDetection:
    def test_api_key_label_detected(self, san):
        r = san.sanitize(_text("api_key=abcdefghij1234567890ABCDEFGHIJ"))
        assert "labeled_credential" in r.secrets_detected

    def test_password_label_detected(self, san):
        r = san.sanitize(_text("password=MySecretPassw0rd12345678"))
        assert "labeled_credential" in r.secrets_detected

    def test_bearer_token_detected(self, san):
        r = san.sanitize(_text("Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.secret"))
        assert "labeled_credential" in r.secrets_detected


class TestCleanInputNotFlagged:
    def test_normal_request_no_secrets(self, san):
        r = san.sanitize(_text("Please show me the build status for pipeline-47."))
        assert r.secrets_detected == []

    def test_technical_request_no_secrets(self, san):
        r = san.sanitize(_text("How do I configure an S3 bucket lifecycle policy?"))
        assert r.secrets_detected == []

    def test_empty_input_no_secrets(self, san):
        r = san.sanitize(_text(""))
        assert r.secrets_detected == []

    def test_code_snippet_no_secrets(self, san):
        r = san.sanitize(_text("import boto3\ns3 = boto3.client('s3')\nprint('hello')"))
        assert r.secrets_detected == []


class TestSecretsInThreatList:
    def test_secrets_appear_in_threats_detected(self, san):
        r = san.sanitize(_text("AKIAIOSFODNN7EXAMPLE is my key"))
        assert any("credentials" in t.lower() or "secret" in t.lower() for t in r.threats_detected)

    def test_secrets_not_blocked_by_default(self, san):
        r = san.sanitize(_text("AKIAIOSFODNN7EXAMPLE is my key"))
        assert not r.blocked

    def test_multiple_types_all_reported(self, san):
        text = (
            "key=AKIAIOSFODNN7EXAMPLE "
            "and token=ghp_ABCDEFabcdef1234567890ABCDEF12"
        )
        r = san.sanitize(text)
        assert len(r.secrets_detected) >= 1
