"""Information-flow / provenance control for agent actions (applied IFC).

Plain idea: label each input by WHERE it came from (trusted vs untrusted), label
each action by how dangerous its SINK is, and flag when untrusted data can flow
to a privileged sink -- including ACROSS turns in a session, the case that
per-request checks and content inspection structurally miss. This is taint
tracking adapted to agents: we track provenance (source of data), not string
copies, because an LLM reworders/summarizes untrusted content so literal
string-matching taint washes off.

Why this is distinct from the research frontier (NeuroTaint, LLMbda, GIF): those
prove/track information flow on synthetic benchmarks. Here the flow verdict is
recorded as a stage in the existing KMS-signed, hash-chained decision trace, so
an auditor can verify the data lineage of any action from a tamper-evident
record produced by a deployed system. Provenance, signed and control-mapped.

Design discipline (matches llm_judge.py):
- OFF by default (INFORMATION_FLOW_ENABLED=false). Enabling it only adds a
  non-blocking FLAG/escalation signal; it never changes an allow into an
  execution it would not otherwise reach.
- Fail-open: any error leaves the verdict unchanged (a provenance-tracking
  outage must never manufacture a denial or break the pipeline).
- Pure classifiers (no AWS) so the labeling is unit-testable in isolation; the
  cross-session tracker takes an optional table and falls back to in-memory.
"""

import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

from data_sensitivity import sensitivity_rank

logger = logging.getLogger(__name__)

INFORMATION_FLOW_ENABLED = os.environ.get("INFORMATION_FLOW_ENABLED", "false").lower() == "true"
# In strict mode a tainted -> privileged flow biases toward deny; otherwise it
# escalates for human review (the safer default: a human decides).
INFORMATION_FLOW_STRICT = os.environ.get("INFORMATION_FLOW_STRICT", "false").lower() == "true"

# --- Source trust labels (provenance) --------------------------------------
TRUST_TRUSTED = "trusted"      # direct operator/user prompt, registered config
TRUST_UNTRUSTED = "untrusted"  # tool responses, retrieved docs, external/web, unknown-origin memory

# Sources whose content is attacker-influenceable. These are the indirect-
# injection channels: the agent did not author them and neither did the operator.
_UNTRUSTED_SOURCES = frozenset({
    "tool_response", "retrieved_document", "web", "external",
    "email", "memory_untrusted", "mcp_response",
})
# Sources under operator/system control.
_TRUSTED_SOURCES = frozenset({
    "user_prompt", "operator", "system", "registered_config",
})


def classify_source_trust(source: str) -> str:
    """Label a data source's trust. Unknown sources fail safe to UNTRUSTED.

    Failing safe to untrusted means an unrecognized channel is treated as
    attacker-influenceable rather than trusted, so a new/unlabeled source can
    never silently gain trusted authority.
    """
    if not source:
        return TRUST_UNTRUSTED
    s = source.strip().lower()
    if s in _TRUSTED_SOURCES:
        return TRUST_TRUSTED
    if s in _UNTRUSTED_SOURCES:
        return TRUST_UNTRUSTED
    return TRUST_UNTRUSTED


# --- Sink privilege (how dangerous is the action) --------------------------
# Action groups that produce external side effects / state changes = privileged.
_PRIVILEGED_ACTIONS = frozenset({
    "ProposeChanges", "StagingDeployment", "ProductionDeployment",
    "WriteDeploymentConfig", "SendEmail", "TransferFunds", "DeleteResource",
})
# Read-only actions are low-privilege sinks.
_READONLY_ACTIONS = frozenset({
    "ReadPipelineStatus", "ReadDeploymentConfig", "ReadBuildResults",
    "ReadTestResults",
})
# Data sensitivity at/above this rank makes a sink privileged even for a read
# (reading restricted data and returning it is itself an exfiltration sink).
_PRIVILEGED_SENSITIVITY = "confidential"


def is_privileged_sink(action_group: str, data_sensitivity: str = "",
                       has_external_output: bool = False) -> bool:
    """True when the action is a privileged sink (side-effect or sensitive read).

    Privileged if it is a known state-changing action, produces external output
    (exfiltration surface), or touches data at/above the confidential rank.
    """
    if action_group in _PRIVILEGED_ACTIONS:
        return True
    if has_external_output:
        return True
    if data_sensitivity and sensitivity_rank(data_sensitivity) >= sensitivity_rank(_PRIVILEGED_SENSITIVITY):
        return True
    return False


@dataclass
class FlowVerdict:
    """Outcome of the information-flow check for one action.

    tainted_sink: untrusted data is present in the session AND this action is a
      privileged sink -> the flow that IFC exists to catch.
    signal: "" (no action), "escalate", or "deny" (strict mode).
    """
    tainted_sink: bool
    signal: str
    source_trust: str
    privileged_sink: bool
    reason: str = ""
    untrusted_sources: List[str] = field(default_factory=list)

    def to_trace_extra(self) -> Dict[str, Any]:
        """Fields to attach to the signed decision-trace stage (data lineage)."""
        return {
            "source_trust": self.source_trust,
            "privileged_sink": self.privileged_sink,
            "tainted_flow": self.tainted_sink,
            "untrusted_sources": sorted(set(self.untrusted_sources)),
        }


class FlowTracker:
    """Tracks per-session provenance and detects untrusted -> privileged flows.

    Session taint persists across turns: once an untrusted source is seen in a
    session, later privileged actions in that session are checked against it.
    Uses a DynamoDB table when given (same pattern as ProbeDetector/IntentStore)
    and falls back to a process-local dict for tests / table-less runs.
    """

    _MEM: Dict[str, Dict[str, Any]] = {}

    def __init__(self, table=None) -> None:
        self._table = table

    def _key(self, session_id: str) -> Dict[str, str]:
        return {"agent_id": f"__ifc_taint__{session_id}"}

    def record_source(self, session_id: str, source: str) -> str:
        """Record a data source for the session; returns its trust label.

        Untrusted sources are persisted so a privileged action later in the
        session can be checked against them (cross-turn taint).
        """
        trust = classify_source_trust(source)
        if trust != TRUST_UNTRUSTED or not session_id:
            return trust
        try:
            if self._table is not None:
                self._table.update_item(
                    Key=self._key(session_id),
                    UpdateExpression="SET untrusted_sources = list_append(if_not_exists(untrusted_sources, :e), :s), updated_at = :t",
                    ExpressionAttributeValues={
                        ":s": [source], ":e": [],
                        ":t": datetime.now(timezone.utc).isoformat(),
                    },
                )
            else:
                rec = self._MEM.setdefault(session_id, {"untrusted_sources": []})
                rec["untrusted_sources"].append(source)
        except Exception as exc:
            logger.warning(json.dumps({
                "event": "ifc_record_source_error", "error": str(exc)[:120],
            }))
        return trust

    def _get_untrusted(self, session_id: str) -> List[str]:
        if not session_id:
            return []
        try:
            if self._table is not None:
                resp = self._table.get_item(Key=self._key(session_id))
                item = resp.get("Item") or {}
                return list(item.get("untrusted_sources", []))
            return list(self._MEM.get(session_id, {}).get("untrusted_sources", []))
        except Exception as exc:
            logger.warning(json.dumps({
                "event": "ifc_get_untrusted_error", "error": str(exc)[:120],
            }))
            return []

    def check_flow(self, session_id: str, current_source: str, action_group: str,
                   data_sensitivity: str = "", has_external_output: bool = False) -> FlowVerdict:
        """Record the current source, then decide if this is a tainted flow.

        A tainted flow = the session has seen untrusted data (now or earlier)
        AND the current action is a privileged sink. Signal is escalate by
        default, deny under strict mode. Never raises.
        """
        source_trust = self.record_source(session_id, current_source)
        seen = self._get_untrusted(session_id)
        if source_trust == TRUST_UNTRUSTED and current_source:
            seen = seen + [current_source]
        privileged = is_privileged_sink(action_group, data_sensitivity, has_external_output)
        tainted = bool(seen) and privileged
        signal = ""
        reason = ""
        if tainted:
            signal = "deny" if INFORMATION_FLOW_STRICT else "escalate"
            reason = (
                f"untrusted data in session ({', '.join(sorted(set(seen))[:4])}) "
                f"flowing to privileged sink '{action_group or data_sensitivity}'"
            )
        return FlowVerdict(
            tainted_sink=tainted,
            signal=signal,
            source_trust=source_trust,
            privileged_sink=privileged,
            reason=reason,
            untrusted_sources=seen,
        )

    def declassify(self, session_id: str) -> None:
        """Clear session taint (explicit, auditable declassification).

        The one legitimate way to lower authority: an explicit reclassification,
        never a silent side effect. Callers should record this in the trace.
        """
        try:
            if self._table is not None:
                self._table.delete_item(Key=self._key(session_id))
            else:
                self._MEM.pop(session_id, None)
        except Exception as exc:
            logger.warning(json.dumps({
                "event": "ifc_declassify_error", "error": str(exc)[:120],
            }))
