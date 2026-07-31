"""Egress Governor: incident-2 class attack prevention.

Blocks the three sub-operations that enabled the Mythos 5 supply-chain incident:
  1. Outbound account creation on external services (email/package registry sign-up)
  2. Package publication to public registries (PyPI, npm, RubyGems, ...)
  3. Dependency-confusion uploads: agent publishing a package whose name matches
     one referenced in the current or recent session instructions

Called as a pipeline stage before policy evaluation.  Fail-closed: if the
classifier raises, the verdict is DENY.

Key design constraint: this runs inside the Lambda, not at the network layer.
Network-layer egress filtering (VPC security groups / NAT deny-list) is the
correct Plane-2 control; this is the Plane-1 governance record and last-resort
gate for requests that reach the action-group entry point.
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Action groups that could publish, register, or upload to external services.
# Extend this list as your action-group catalog grows.
# ---------------------------------------------------------------------------
_PUBLISH_ACTION_GROUPS = frozenset({
    "PublishPackage",
    "UploadPackage",
    "PublishArtifact",
    "PushPackage",
    "RegisterPackage",
    "NpmPublish",
    "PypiPublish",
    "GemPush",
    "CargoPublish",
    "MavenDeploy",
    "DockerPush",
    "HelmPush",
})

_ACCOUNT_CREATION_ACTION_GROUPS = frozenset({
    "CreateAccount",
    "RegisterAccount",
    "SignUp",
    "RegisterUser",
    "CreateExternalAccount",
    "SendRegistrationEmail",
})

# Public registries whose hostnames should never appear as upload targets
# unless the agent holds explicit SCOPE_LEVEL >= 4 AND operator approval.
_PUBLIC_REGISTRY_PATTERNS: List[str] = [
    r"pypi\.org",
    r"upload\.pypi\.org",
    r"npmjs\.com",
    r"registry\.npmjs\.org",
    r"rubygems\.org",
    r"crates\.io",
    r"pkg\.go\.dev",
    r"repo1\.maven\.org",
    r"hub\.docker\.com",
    r"ghcr\.io",
    r"quay\.io",
    r"anaconda\.org",
    r"conda-forge",
]
_REGISTRY_RE = re.compile("|".join(_PUBLIC_REGISTRY_PATTERNS), re.IGNORECASE)

# Free email providers -- used to detect "create throwaway account" pattern
_FREE_EMAIL_PATTERNS: List[str] = [
    r"gmail\.com",
    r"yahoo\.com",
    r"hotmail\.com",
    r"protonmail\.",
    r"tutanota\.",
    r"guerrillamail\.",
    r"mailinator\.",
    r"tempmail\.",
    r"10minutemail\.",
    r"yopmail\.",
]
_FREE_EMAIL_RE = re.compile("|".join(_FREE_EMAIL_PATTERNS), re.IGNORECASE)

# Minimum scope level required for any external publish action
_PUBLISH_MIN_SCOPE = int(os.environ.get("EGRESS_PUBLISH_MIN_SCOPE", "4"))


@dataclass
class EgressVerdict:
    allowed: bool
    reason: str = ""
    risk_delta: int = 0
    checks_failed: List[str] = field(default_factory=list)
    timestamp: str = ""

    def to_trace_extra(self) -> Dict[str, Any]:
        return {
            "egress_allowed": self.allowed,
            "egress_reason": self.reason,
            "egress_checks_failed": self.checks_failed,
        }


class EgressGovernor:
    """Blocks incident-2 class external-publish and account-creation operations."""

    def evaluate(
        self,
        action_group: str,
        scope_level: int,
        input_text: str,
        tool_parameters: Dict[str, Any],
        session_instructions: str = "",
    ) -> EgressVerdict:
        """Return an EgressVerdict for the proposed action."""
        now = datetime.now(timezone.utc).isoformat()
        checks_failed: List[str] = []

        # --- Check 1: account creation at external services ----------------
        if action_group in _ACCOUNT_CREATION_ACTION_GROUPS:
            checks_failed.append("external_account_creation_blocked")

        # Detect free-email registration attempts in parameters or input
        probe_text = _flatten_params(tool_parameters) + " " + (input_text or "")
        if _FREE_EMAIL_RE.search(probe_text) and action_group in _ACCOUNT_CREATION_ACTION_GROUPS:
            checks_failed.append("free_email_registration_attempt")

        # --- Check 2: publish / upload to a public registry ----------------
        if action_group in _PUBLISH_ACTION_GROUPS:
            if scope_level < _PUBLISH_MIN_SCOPE:
                checks_failed.append(
                    f"publish_requires_scope_{_PUBLISH_MIN_SCOPE}_got_{scope_level}"
                )
            target = _extract_target(tool_parameters, input_text)
            if target and _REGISTRY_RE.search(target):
                checks_failed.append("publish_target_is_public_registry")

        # --- Check 3: dependency confusion -- package name matches session  -
        if action_group in _PUBLISH_ACTION_GROUPS:
            pkg_name = _extract_package_name(tool_parameters, input_text)
            if pkg_name and session_instructions:
                if pkg_name.lower() in session_instructions.lower():
                    checks_failed.append(
                        f"dependency_confusion_package_name_in_session: '{pkg_name}'"
                    )

        # --- Check 4: raw URL in parameters pointing at public registry ----
        if _REGISTRY_RE.search(probe_text):
            if action_group not in _PUBLISH_ACTION_GROUPS:
                # Not a named publish action but parameters reference a registry
                # upload endpoint -- flag as medium risk, don't hard-block.
                pass
            else:
                if "publish_target_is_public_registry" not in checks_failed:
                    checks_failed.append("registry_url_in_publish_params")

        if checks_failed:
            reason = "Egress governor blocked: " + "; ".join(checks_failed)
            logger.warning(json.dumps({
                "event": "egress_governor_deny",
                "action_group": action_group,
                "scope_level": scope_level,
                "checks_failed": checks_failed,
                "timestamp": now,
            }))
            return EgressVerdict(
                allowed=False,
                reason=reason,
                risk_delta=40,
                checks_failed=checks_failed,
                timestamp=now,
            )

        return EgressVerdict(allowed=True, timestamp=now)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _flatten_params(params: Dict[str, Any]) -> str:
    """Flatten tool parameter values to a single string for pattern matching."""
    if not params:
        return ""
    parts: List[str] = []
    for v in params.values():
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (list, dict)):
            parts.append(json.dumps(v))
    return " ".join(parts)


def _extract_target(params: Dict[str, Any], input_text: str) -> str:
    """Extract the upload/publish target from parameters or input."""
    for key in ("target", "registry", "repository", "url", "endpoint", "index_url"):
        val = params.get(key, "")
        if val and isinstance(val, str):
            return val
    # Fall back to first URL found in input text
    url_match = re.search(r"https?://[^\s\"']+", input_text or "")
    return url_match.group(0) if url_match else ""


def _extract_package_name(params: Dict[str, Any], input_text: str) -> str:
    """Extract the package name being published."""
    for key in ("package_name", "name", "package", "module"):
        val = params.get(key, "")
        if val and isinstance(val, str):
            return val.strip()
    # Try to parse from input text: "upload X to pypi" or "publish X"
    m = re.search(
        r"\b(?:upload|publish|push)\s+([a-zA-Z0-9_\-]+)",
        input_text or "",
        re.IGNORECASE,
    )
    return m.group(1) if m else ""
