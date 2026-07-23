"""Central governance verdict constants and AARM mapping.

The internal verdict domain is five plain strings. They are kept as bare
strings (not an Enum) so existing DynamoDB serialization, JSON round-trips,
and ``verdict == "allow"`` comparisons throughout the codebase continue to
work unchanged.

AARM (Autonomous Action Runtime Management, CSA spec v1.0) R4 requires a
system capable of exactly five authorization decisions: ALLOW, DENY, MODIFY,
STEP_UP, DEFER. This project's internal ``escalate`` verdict IS AARM's
STEP_UP (human approval required); the mapping is applied only at the AARM
receipt/telemetry serialization boundary via ``to_aarm``.
"""

# Internal verdict tokens (canonical, used everywhere in the pipeline).
ALLOW = "allow"
DENY = "deny"
ESCALATE = "escalate"   # == AARM STEP_UP
MODIFY = "modify"       # execute a sanitized/transformed version of the action
DEFER = "defer"         # suspend pending more context; timeout -> deny

# The complete set of recognized internal verdicts.
VALID_VERDICTS = (ALLOW, DENY, ESCALATE, MODIFY, DEFER)

# Internal verdict -> AARM R4 decision name. Applied only at the AARM
# receipt/telemetry boundary, never in internal branching.
AARM_VERDICT_MAP = {
    ALLOW: "ALLOW",
    DENY: "DENY",
    MODIFY: "MODIFY",
    ESCALATE: "STEP_UP",
    DEFER: "DEFER",
}


def is_valid(verdict: str) -> bool:
    """Return True if ``verdict`` is one of the five recognized tokens."""
    return verdict in VALID_VERDICTS


def to_aarm(verdict: str) -> str:
    """Map an internal verdict to its AARM R4 decision name.

    Unrecognized verdicts map to ``DENY`` (fail closed).
    """
    return AARM_VERDICT_MAP.get(verdict, "DENY")
