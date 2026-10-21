"""Tests for scripts/pre_push_check.py: account-ID detection and private patterns."""
import importlib.util
import pathlib

import pytest

_PATH = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "pre_push_check.py"
_spec = importlib.util.spec_from_file_location("pre_push_check", _PATH)
guard = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(guard)

# Built at runtime so no literal account number appears in this file.
_REAL = "9" * 4 + "1" * 4 + "2" * 4


@pytest.mark.parametrize("line", [
    f"arn:aws:iam::{_REAL}:role/AdminRole",
    f'"account": "{_REAL}",',
    f"account_id: {_REAL}",
    f"arn:aws-cn:s3:cn-north-1:{_REAL}:accesspoint/x",
])
def test_real_account_ids_are_found(line):
    assert guard.real_account_ids(line) == [_REAL]


@pytest.mark.parametrize("line", [
    "arn:aws:iam::111122223333:role/AdminRole",
    '"account": "123456789012",',
    "arn:aws:s3:::my-bucket/key",          # S3 ARNs carry no account
    "latency_ms: 123412341234",            # 12 digits outside an ARN or account field
])
def test_placeholders_and_non_account_numbers_pass(line):
    assert guard.real_account_ids(line) == []


def test_scan_reports_real_account_as_high(tmp_path):
    f = tmp_path / "config.json"
    f.write_text(f'{{"account": "{_REAL}"}}\n', encoding="utf-8")
    findings = guard._scan_file(str(f))
    assert [(label, sev) for _, label, sev, _ in findings] == [("AWS_ACCOUNT_ID", "HIGH")]


def test_private_patterns_load_and_match(tmp_path):
    (tmp_path / guard.PRIVATE_PATTERNS_FILE).write_text(
        "# comment\n\nsecret-system-name\n[unclosed\n", encoding="utf-8")
    rules = guard.load_private_rules(tmp_path)
    assert len(rules) == 1                      # comment, blank and invalid lines skipped
    f = tmp_path / "notes.md"
    f.write_text("deployed on Secret-System-Name today\n", encoding="utf-8")
    findings = guard._scan_file(str(f), rules)
    assert [sev for _, _, sev, _ in findings] == ["HIGH"]


def test_missing_private_patterns_file_adds_no_rules(tmp_path):
    assert guard.load_private_rules(tmp_path) == []


def test_private_patterns_file_is_a_blocked_path():
    assert guard._check_paths([".pre-push-patterns", "docs/readme.md"]) == [
        (".pre-push-patterns", r"(^|/)\.pre-push-patterns$")]
