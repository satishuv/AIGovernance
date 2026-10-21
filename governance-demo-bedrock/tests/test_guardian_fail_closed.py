"""A required guardian check that does not run fails closed (P0-15)."""
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine"))

from guardian_monitor import GuardianMonitor  # noqa: E402


class _FailingClient:
    def converse(self, **_):
        raise RuntimeError("model unavailable")


class _ReplyClient:
    def __init__(self, text):
        self._text = text

    def converse(self, **_):
        return {"output": {"message": {"content": [{"text": self._text}]}}}


def _live(client):
    guardian = GuardianMonitor(mode="live")
    guardian._client = client
    return guardian


def _summary(verdict):
    return verdict.safe, verdict.recommended_action, verdict.evaluated


@pytest.mark.parametrize("required, expected", [
    (False, (True, "allow", False)),
    (True, (False, "escalate", False)),
])
def test_disabled_guardian(required, expected):
    assert _summary(GuardianMonitor(mode="disabled").evaluate("text", required=required)) == expected


@pytest.mark.parametrize("required, expected", [
    (False, (True, "allow", False)),
    (True, (False, "escalate", False)),
])
def test_failed_guardian_call(required, expected):
    assert _summary(_live(_FailingClient()).evaluate("text", required=required)) == expected


@pytest.mark.parametrize("reply", ["not json at all", '{"confidence": 0.9}', '{"safe": "yes"}'])
def test_unreadable_answer_fails_closed_when_required(reply):
    assert _summary(_live(_ReplyClient(reply)).evaluate("text", required=True)) == (False, "escalate", False)


def test_unreadable_answer_is_marked_unevaluated_when_optional():
    verdict = _live(_ReplyClient('{"confidence": 0.9}')).evaluate("text")
    assert verdict.safe is True and verdict.evaluated is False


def test_unsafe_verdict_is_reported_as_evaluated():
    reply = '{"safe": false, "confidence": 0.8, "categories_flagged": ["PROMPT_LEAK"], "reason": "leak"}'
    verdict = _live(_ReplyClient(reply)).evaluate("text", required=True)
    assert _summary(verdict) == (False, "block", True)
    assert verdict.to_dict()["evaluated"] is True


def test_safe_verdict_passes_a_required_check():
    reply = 'Result: {"safe": true, "confidence": 0.9, "recommended_action": "allow"}'
    assert _summary(_live(_ReplyClient(reply)).evaluate("text", required=True)) == (True, "allow", True)
