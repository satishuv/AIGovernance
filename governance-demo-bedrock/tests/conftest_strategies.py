"""Comprehensive tests for the Governance Engine - all optional test tasks.
Covers Phase 1a, 1b, and 1c optional unit and property-based tests.
Uses unittest.mock to mock AWS services. Uses pytest and Hypothesis.
"""
import hashlib
import json
import logging
import os
import sys
import time
import uuid
from datetime import date, datetime, timezone
from io import BytesIO
from unittest.mock import MagicMock, patch

import pytest
from hypothesis import given, settings, HealthCheck
from hypothesis import strategies as st

LAMBDAS = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "lambdas", "governance_engine"))
if LAMBDAS not in sys.path:
    sys.path.insert(0, LAMBDAS)

from models import (
    AgentIdentity, AgentRegistryEntry, ControlTrace, EvidenceRecord,
    GovernanceDecision, GovernanceRoleAssignment, LatencyMetric,
    PolicyConditions, PolicyDefinition, PolicyEvaluationResult,
    PolicyVersion, RiskAssessment, ThreatPattern, ToolModelRegistryEntry,
    ValidationResult,
)
from policy_engine import PolicyEngine
from risk_scoring import RiskScoringEngine
from decision_engine import DecisionEngine
from fail_safe import safe_evaluate_policy, safe_compute_risk, safe_write_evidence
from latency import LatencyTracker
from kill_switch import KillSwitchManager
from evidence_pipeline import EvidencePipeline
from agent_identity import AgentIdentityManager
from agent_registry import AgentRegistry
from tool_model_registry import ToolModelRegistry
from separation_of_duties import SeparationOfDuties
from environment_isolation import EnvironmentIsolation
from control_trace import ControlTraceManager
from evidence_integrity import EvidenceIntegrity
from threat_detector import ThreatDetector
from validation_suite import MinimumValidationSuite
from policy_lifecycle import PolicyLifecycle

# ---------- Hypothesis strategies ----------
_tx = st.text(alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z")), min_size=1, max_size=40)
_sid = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=20)
_ts = st.just("2024-01-15T12:00:00+00:00")
_oc = st.sampled_from(["allow", "deny", "escalate", "modify", "defer"])
_ev = st.sampled_from(["dev", "staging", "prod"])
_ct = st.sampled_from(["model", "tool_connector", "data_source"])


@st.composite
def gen_pc(draw):
    return PolicyConditions(draw(st.integers(0, 4)), draw(_sid), draw(_sid), {"start": "08:00", "end": "17:00"})


@st.composite
def gen_pd(draw):
    return PolicyDefinition(
        draw(_sid), draw(st.integers(1, 50)), draw(_tx), draw(_tx),
        draw(st.integers(0, 50)), draw(gen_pc()), draw(_oc), draw(_sid),
        draw(st.sampled_from(["approved", "pending"])), draw(_ts), draw(_ts),
    )


@st.composite
def gen_gd(draw):
    return GovernanceDecision(
        draw(_sid), draw(_sid), draw(_sid),
        {"policy_id": draw(_sid), "outcome": draw(_oc)},
        draw(st.floats(0, 100, allow_nan=False, allow_infinity=False)),
        draw(_oc), draw(_tx), draw(st.lists(_sid, max_size=2)), draw(_ts),
        {"pe": draw(st.floats(0, 200, allow_nan=False, allow_infinity=False))},
    )


@st.composite
def gen_are(draw):
    return AgentRegistryEntry(
        draw(_sid), draw(_tx), draw(_sid),
        draw(st.lists(_sid, min_size=1, max_size=2)),
        draw(st.lists(_sid, max_size=2)),
        draw(st.integers(1, 4)), draw(_ev),
    )


@st.composite
def gen_tmre(draw):
    return ToolModelRegistryEntry(
        draw(_sid), draw(_ct), draw(_tx), draw(_sid),
        draw(st.sampled_from(["pending", "approved", "revoked"])),
        draw(_sid), draw(_ts),
    )


@st.composite
def gen_er(draw):
    return EvidenceRecord(
        draw(_sid), draw(_sid), draw(_sid), draw(_sid), draw(_sid),
        draw(st.floats(0, 100, allow_nan=False, allow_infinity=False)),
        draw(_oc), draw(_ts), draw(st.lists(_sid, max_size=2)),
        draw(_ev), draw(_sid), draw(_sid),
        draw(st.sampled_from(["standard", "extended"])),
    )


@st.composite
def gen_ct(draw):
    return ControlTrace(draw(_sid), draw(_tx), draw(_sid), draw(_sid), draw(_ts))


# ---------- Mock DynamoDB table ----------
class _MT:
    def __init__(self, k="agent_id"):
        self._d = {}
        self._k = k

    def put_item(self, Item=None, **kw):
        self._d[Item[self._k]] = dict(Item)

    def get_item(self, Key=None, **kw):
        i = self._d.get(Key[self._k])
        return {"Item": dict(i)} if i else {}

    def update_item(self, Key=None, UpdateExpression="",
                    ExpressionAttributeValues=None, ExpressionAttributeNames=None, **kw):
        k = Key[self._k]
        if k not in self._d:
            self._d[k] = {self._k: k}
        if UpdateExpression.startswith("SET "):
            for p in UpdateExpression[4:].split(","):
                p = p.strip()
                l, r = p.split("=")
                l, r = l.strip(), r.strip()
                n = (ExpressionAttributeNames or {}).get(l, l)
                v = (ExpressionAttributeValues or {}).get(r, r)
                self._d[k][n] = v

    def scan(self, FilterExpression=None, ExpressionAttributeValues=None, **kw):
        items = list(self._d.values())
        if ExpressionAttributeValues:
            uid = ExpressionAttributeValues.get(":uid", "")
            if uid:
                items = [i for i in items if i.get("user_id") == uid]
        return {"Items": items}

    def query(self, **kw):
        return {"Items": list(self._d.values())}

    def batch_writer(self):
        return _BW(self)


class _BW:
    def __init__(self, t):
        self._t = t

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def put_item(self, Item=None):
        self._t.put_item(Item=Item)
