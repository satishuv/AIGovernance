"""Tests for information-flow / provenance control (applied IFC).

Covers source-trust labeling, sink-privilege classification, the core tainted
untrusted -> privileged flow (same turn AND across turns in a session), the
strict/escalate signal split, fail-safe defaults, explicit declassification,
and the trace-extra shape used to record data lineage in the signed trace.
"""
import os
import sys

import pytest

_LD = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine"))
if _LD not in sys.path:
    sys.path.insert(0, _LD)

import information_flow as ifc
from information_flow import (
    FlowTracker, classify_source_trust, is_privileged_sink,
    TRUST_TRUSTED, TRUST_UNTRUSTED,
)


class _MemTable:
    """Minimal DynamoDB-like table supporting the update/get/delete IFC uses."""
    def __init__(self):
        self.items = {}

    def update_item(self, Key=None, UpdateExpression=None, ExpressionAttributeValues=None, **kw):
        pk = Key["agent_id"]
        rec = self.items.setdefault(pk, {"agent_id": pk, "untrusted_sources": []})
        # Emulate list_append(if_not_exists(untrusted_sources, :e), :s).
        rec["untrusted_sources"] = rec.get("untrusted_sources", []) + list(ExpressionAttributeValues.get(":s", []))

    def get_item(self, Key=None):
        it = self.items.get(Key["agent_id"])
        return {"Item": it} if it else {}

    def delete_item(self, Key=None):
        self.items.pop(Key["agent_id"], None)


@pytest.fixture(autouse=True)
def _clear_mem():
    """Isolate the process-local fallback between tests."""
    FlowTracker._MEM.clear()
    yield
    FlowTracker._MEM.clear()


# --- source trust labeling -------------------------------------------------
def test_trusted_sources_labeled_trusted():
    for s in ("user_prompt", "operator", "system", "registered_config"):
        assert classify_source_trust(s) == TRUST_TRUSTED


def test_untrusted_sources_labeled_untrusted():
    for s in ("tool_response", "retrieved_document", "web", "email", "mcp_response"):
        assert classify_source_trust(s) == TRUST_UNTRUSTED


def test_unknown_source_fails_safe_to_untrusted():
    assert classify_source_trust("some_new_channel") == TRUST_UNTRUSTED
    assert classify_source_trust("") == TRUST_UNTRUSTED


# --- sink privilege --------------------------------------------------------
def test_state_changing_actions_are_privileged_sinks():
    for a in ("ProposeChanges", "ProductionDeployment", "SendEmail", "TransferFunds"):
        assert is_privileged_sink(a) is True


def test_readonly_action_is_not_privileged_by_default():
    assert is_privileged_sink("ReadPipelineStatus") is False


def test_sensitive_read_is_privileged_sink():
    # Reading restricted/confidential data is itself a privileged (exfil) sink.
    assert is_privileged_sink("ReadPipelineStatus", data_sensitivity="restricted") is True
    assert is_privileged_sink("ReadPipelineStatus", data_sensitivity="confidential") is True


def test_external_output_makes_sink_privileged():
    assert is_privileged_sink("ReadPipelineStatus", has_external_output=True) is True


# --- core flow: same turn --------------------------------------------------
def test_trusted_source_to_privileged_sink_is_clean():
    t = FlowTracker()
    v = t.check_flow("sess1", "user_prompt", "ProductionDeployment")
    assert v.tainted_sink is False
    assert v.signal == ""


def test_untrusted_source_to_privileged_sink_same_turn_is_tainted():
    t = FlowTracker()
    v = t.check_flow("sess1", "tool_response", "ProductionDeployment")
    assert v.tainted_sink is True
    assert v.signal == "escalate"          # default (non-strict)
    assert "privileged sink" in v.reason


def test_untrusted_source_to_readonly_sink_is_not_tainted():
    t = FlowTracker()
    v = t.check_flow("sess1", "tool_response", "ReadPipelineStatus")
    assert v.tainted_sink is False
    assert v.signal == ""


# --- core flow: ACROSS turns (the case per-request checks miss) ------------
def test_cross_turn_taint_persists_in_session():
    table = _MemTable()
    t = FlowTracker(table)
    # Turn 1: untrusted data enters on a harmless read.
    v1 = t.check_flow("sessX", "retrieved_document", "ReadPipelineStatus")
    assert v1.tainted_sink is False
    # Turn 2 (fresh tracker, same session/table): trusted-looking prompt, but
    # the session already ingested untrusted data -> privileged action is tainted.
    t2 = FlowTracker(table)
    v2 = t2.check_flow("sessX", "user_prompt", "ProductionDeployment")
    assert v2.tainted_sink is True
    assert v2.signal == "escalate"
    assert "retrieved_document" in v2.reason


def test_cross_turn_taint_uses_memory_fallback_without_table():
    t = FlowTracker()  # no table -> process-local _MEM
    t.check_flow("memSess", "web", "ReadPipelineStatus")
    v = t.check_flow("memSess", "user_prompt", "ProposeChanges")
    assert v.tainted_sink is True


# --- strict mode -----------------------------------------------------------
def test_strict_mode_denies_instead_of_escalates(monkeypatch):
    monkeypatch.setattr(ifc, "INFORMATION_FLOW_STRICT", True)
    t = FlowTracker()
    v = t.check_flow("sessS", "tool_response", "ProductionDeployment")
    assert v.tainted_sink is True
    assert v.signal == "deny"


# --- declassification ------------------------------------------------------
def test_declassify_clears_session_taint():
    table = _MemTable()
    t = FlowTracker(table)
    t.check_flow("sessD", "web", "ReadPipelineStatus")
    assert t.check_flow("sessD", "user_prompt", "ProductionDeployment").tainted_sink is True
    t.declassify("sessD")
    v = t.check_flow("sessD", "user_prompt", "ProductionDeployment")
    assert v.tainted_sink is False


# --- trace lineage shape ---------------------------------------------------
def test_trace_extra_carries_data_lineage():
    t = FlowTracker()
    v = t.check_flow("sessL", "tool_response", "ProductionDeployment")
    extra = v.to_trace_extra()
    assert extra["source_trust"] == TRUST_UNTRUSTED
    assert extra["privileged_sink"] is True
    assert extra["tainted_flow"] is True
    assert "tool_response" in extra["untrusted_sources"]


# --- fail-open guarantee ---------------------------------------------------
def test_no_session_id_does_not_crash_and_labels_source():
    t = FlowTracker()
    v = t.check_flow("", "tool_response", "ProductionDeployment")
    # With no session there is no cross-turn memory, but same-turn untrusted
    # source is still seen, so the privileged sink is still flagged.
    assert v.source_trust == TRUST_UNTRUSTED
    assert v.privileged_sink is True
