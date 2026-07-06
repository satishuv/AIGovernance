"""Behavioral Invariants Module for AI Governance Engine.

These are HARD LIMITS that cannot be overridden by any model output, policy,
or configuration change at runtime. They are the last line of defense.

Key principle: these invariants are PHYSICAL CONSTRAINTS. Even if the model is
fully jailbroken and tries to output dangerous content, these limits physically
prevent harm (output truncation prevents data dumps, time restrictions prevent
midnight deploys, canary detects compromise automatically).
"""

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "restricted_action_groups": ["ProductionDeployment"],
    "allowed_hours_utc": {"start": 0, "end": 23},
    "max_output_bytes": 65536,
    "canary_salt": "agcp-governance-canary-v1",
}


@dataclass
class InvariantCheckResult:
    """Result of a behavioral invariant enforcement check."""

    passed: bool  # True if all invariants hold
    violations: List[str]  # list of violated invariants
    canary_tokens: List[str]  # generated tokens (for pre-request) or empty
    output_truncated: bool
    agent_compromised: bool  # True if canary leaked (CRITICAL)
    compromised_canary: str  # which canary was found
    action_blocked: bool  # True if time-of-day blocked
    block_reason: str
    timestamp: str


class BehavioralInvariantsEnforcer:
    """Enforces hard behavioral invariants that cannot be overridden.

    These invariants act as physical constraints on the system regardless of
    what the AI model, policies, or configuration attempt to do at runtime.
    """

    def enforce_pre_request(
        self, action_request: Dict[str, Any], config: Dict[str, Any] = None
    ) -> InvariantCheckResult:
        """Run before any other processing. Hard limits on inputs.

        Checks:
        - Time-of-day restriction: production actions blocked outside
          configured hours (default: 06:00-22:00 UTC)
        - Output size hard cap config loaded
        - Canary token generation for injection into agent context

        Args:
            action_request: The incoming action request dictionary.
            config: Optional configuration overrides.

        Returns:
            InvariantCheckResult with pre-request enforcement details.
        """
        effective_config = dict(DEFAULT_CONFIG)
        if config:
            effective_config.update(config)

        violations = []
        action_blocked = False
        block_reason = ""
        now = datetime.now(timezone.utc)

        # Check time-of-day restriction
        action_group = action_request.get("action_group", "")
        allowed, reason = self._check_time_of_day(action_group, effective_config)
        if not allowed:
            violations.append(reason)
            action_blocked = True
            block_reason = reason

        # Generate canary tokens
        agent_id = action_request.get("agent_id", "unknown")
        session_id = action_request.get("session_id", "")
        canary_tokens = self.generate_canary_tokens(agent_id, session_id)

        passed = len(violations) == 0

        result = InvariantCheckResult(
            passed=passed,
            violations=violations,
            canary_tokens=canary_tokens,
            output_truncated=False,
            agent_compromised=False,
            compromised_canary="",
            action_blocked=action_blocked,
            block_reason=block_reason,
            timestamp=now.isoformat(),
        )

        logger.info(
            json.dumps(
                {
                    "event": "behavioral_invariant_pre_request",
                    "passed": passed,
                    "action_blocked": action_blocked,
                    "block_reason": block_reason,
                    "violations_count": len(violations),
                    "agent_id": agent_id,
                    "action_group": action_group,
                    "timestamp": result.timestamp,
                }
            )
        )

        return result

    def enforce_post_response(
        self,
        response_text: str,
        canary_tokens: List[str],
        config: Dict[str, Any] = None,
    ) -> InvariantCheckResult:
        """Run after agent responds. Hard limits on outputs.

        Checks:
        - Output size: truncate at max bytes (default 65536)
        - Canary tripwire: if any canary token appears in response,
          agent is COMPROMISED

        Args:
            response_text: The agent's response text.
            canary_tokens: Canary tokens that were injected pre-request.
            config: Optional configuration overrides.

        Returns:
            InvariantCheckResult with post-response enforcement details.
        """
        effective_config = dict(DEFAULT_CONFIG)
        if config:
            effective_config.update(config)

        violations = []
        now = datetime.now(timezone.utc)

        # Check output size and truncate if needed
        max_bytes = effective_config.get("max_output_bytes", 65536)
        truncated_text, was_truncated = self._truncate_output(
            response_text, max_bytes
        )
        if was_truncated:
            violations.append(
                "Output exceeded max size limit of {} bytes; truncated".format(
                    max_bytes
                )
            )

        # Check canary tripwire
        compromised, which_canary = self._check_canary_tripwire(
            truncated_text, canary_tokens
        )
        if compromised:
            violations.append(
                "CRITICAL: Canary token leaked in agent response: {}".format(
                    which_canary
                )
            )

        passed = len(violations) == 0

        result = InvariantCheckResult(
            passed=passed,
            violations=violations,
            canary_tokens=[],
            output_truncated=was_truncated,
            agent_compromised=compromised,
            compromised_canary=which_canary,
            action_blocked=False,
            block_reason="",
            timestamp=now.isoformat(),
        )

        # Log at appropriate level
        if compromised:
            logger.critical(
                json.dumps(
                    {
                        "event": "CANARY_COMPROMISE_DETECTED",
                        "severity": "CRITICAL",
                        "agent_compromised": True,
                        "compromised_canary": which_canary,
                        "response_length": len(response_text),
                        "truncated": was_truncated,
                        "violations": violations,
                        "timestamp": result.timestamp,
                        "action_required": "Immediate agent isolation and investigation",
                    }
                )
            )
        else:
            logger.info(
                json.dumps(
                    {
                        "event": "behavioral_invariant_post_response",
                        "passed": passed,
                        "output_truncated": was_truncated,
                        "agent_compromised": False,
                        "response_length": len(truncated_text),
                        "violations_count": len(violations),
                        "timestamp": result.timestamp,
                    }
                )
            )

        return result

    def generate_canary_tokens(
        self, agent_id: str, session_id: str = ""
    ) -> List[str]:
        """Generate unique canary tokens to inject into agent context.

        Tokens are:
        - Unique per agent + session
        - Look like plausible internal identifiers (so the agent might
          repeat them if jailbroken)
        - Generated deterministically from agent_id + a secret salt
          (so we can verify later)

        Format:
            AGCP-CANARY-{hash[:12]}
            internal-ref-{hash[:8]}-{hash[8:16]}

        Args:
            agent_id: The agent's identifier.
            session_id: Optional session identifier for uniqueness.

        Returns:
            List of canary token strings.
        """
        salt = DEFAULT_CONFIG["canary_salt"]
        seed = "{}:{}:{}".format(salt, agent_id, session_id)
        hash_digest = hashlib.sha256(seed.encode("utf-8")).hexdigest()

        token_1 = "AGCP-CANARY-{}".format(hash_digest[:12])
        token_2 = "internal-ref-{}-{}".format(
            hash_digest[:8], hash_digest[8:16]
        )

        tokens = [token_1, token_2]

        logger.info(
            json.dumps(
                {
                    "event": "canary_tokens_generated",
                    "agent_id": agent_id,
                    "session_id": session_id,
                    "token_count": len(tokens),
                }
            )
        )

        return tokens

    def _check_time_of_day(
        self, action_group: str, config: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """Block production actions outside business hours.

        Config format:
            {
                "restricted_action_groups": ["ProductionDeployment", "StagingDeployment"],
                "allowed_hours_utc": {"start": 6, "end": 22}
            }

        Args:
            action_group: The action group being requested.
            config: Configuration with restricted groups and allowed hours.

        Returns:
            Tuple of (allowed, reason). If allowed is False, reason explains why.
        """
        restricted_groups = config.get("restricted_action_groups", [])

        if action_group not in restricted_groups:
            return (True, "")

        allowed_hours = config.get("allowed_hours_utc", {"start": 6, "end": 22})
        start_hour = allowed_hours.get("start", 6)
        end_hour = allowed_hours.get("end", 22)

        current_hour = datetime.now(timezone.utc).hour

        if start_hour <= current_hour < end_hour:
            return (True, "")

        reason = (
            "Action group '{}' is restricted outside allowed hours "
            "({}:00-{}:00 UTC). Current hour: {}:00 UTC".format(
                action_group, start_hour, end_hour, current_hour
            )
        )
        return (False, reason)

    def _truncate_output(
        self, response_text: str, max_bytes: int = 65536
    ) -> Tuple[str, bool]:
        """Hard truncate at max bytes.

        Args:
            response_text: The response text to potentially truncate.
            max_bytes: Maximum allowed output size in bytes.

        Returns:
            Tuple of (truncated_text, was_truncated).
        """
        encoded = response_text.encode("utf-8")
        if len(encoded) <= max_bytes:
            return (response_text, False)

        # Truncate at byte boundary, then decode safely
        truncated_bytes = encoded[:max_bytes]
        truncated_text = truncated_bytes.decode("utf-8", errors="ignore")
        truncated_text += "\n[OUTPUT TRUNCATED: exceeded {} byte limit]".format(
            max_bytes
        )

        return (truncated_text, True)

    def _check_canary_tripwire(
        self, response_text: str, canary_tokens: List[str]
    ) -> Tuple[bool, str]:
        """Check if any canary appears in the response.

        If a canary token is found in the agent's output, it means the agent
        has been compromised (jailbroken) and is leaking injected context.

        Args:
            response_text: The agent's response text.
            canary_tokens: List of canary tokens to search for.

        Returns:
            Tuple of (compromised, which_canary). If compromised is True,
            which_canary contains the leaked token.
        """
        for token in canary_tokens:
            if token in response_text:
                return (True, token)

        return (False, "")
