"""Governance Versioning and Instant Rollback.

If a policy change, threshold adjustment, or configuration update breaks
governance (causes mass false positives, blocks all traffic, etc.), this
module provides instant rollback to the last known-good state.

Every governance state mutation (policy, threshold, scope config, rules)
is versioned. Operators can rollback to any previous version in <1 second.

Versioned state:
- OPA/Rego policies
- Risk scoring thresholds (escalation_threshold, deny_threshold)
- Behavioral invariant limits (tool call cap, output size, time window)
- Input sanitizer patterns (threat patterns in DynamoDB)
- Tool allowlists
- Scope configurations

NOT versioned (infrastructure state, not governance logic):
- Agent registrations (those are lifecycle, not config)
- Evidence records (immutable, never rolled back)
- Decision history (audit trail, never rolled back)
"""

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

MAX_VERSIONS = 50


@dataclass
class GovernanceVersion:
    version_id: str
    version_number: int
    created_at: str
    created_by: str
    description: str
    state_snapshot: Dict[str, Any]
    is_active: bool = False
    rollback_from: str = ""


class GovernanceRollbackManager:
    """Manages versioned governance state with instant rollback capability.

    Every mutation to governance configuration creates a new version.
    Rollback restores the complete governance state to any previous version.
    """

    def __init__(self, version_table=None):
        self._version_table = version_table
        self._current_version: Optional[GovernanceVersion] = None
        self._version_history: List[GovernanceVersion] = []
        self._next_version_number = 1

    def capture_current_state(
        self,
        policies: Dict[str, Any],
        thresholds: Dict[str, Any],
        behavioral_limits: Dict[str, Any],
        threat_patterns: List[Dict[str, Any]],
        tool_allowlist: List[str],
        scope_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Capture the complete current governance state as a snapshot."""
        return {
            "policies": policies,
            "thresholds": thresholds,
            "behavioral_limits": behavioral_limits,
            "threat_patterns": threat_patterns,
            "tool_allowlist": tool_allowlist,
            "scope_config": scope_config,
        }

    def create_version(
        self,
        state_snapshot: Dict[str, Any],
        created_by: str,
        description: str,
    ) -> GovernanceVersion:
        """Create a new governance version from the current state.

        Called automatically before any governance configuration change.
        """
        version = GovernanceVersion(
            version_id=str(uuid.uuid4()),
            version_number=self._next_version_number,
            created_at=datetime.now(timezone.utc).isoformat(),
            created_by=created_by,
            description=description,
            state_snapshot=state_snapshot,
            is_active=True,
        )

        if self._current_version:
            self._current_version.is_active = False

        self._current_version = version
        self._version_history.append(version)
        self._next_version_number += 1

        if len(self._version_history) > MAX_VERSIONS:
            self._version_history = self._version_history[-MAX_VERSIONS:]

        if self._version_table:
            try:
                self._version_table.put_item(Item={
                    "version_id": version.version_id,
                    "version_number": version.version_number,
                    "created_at": version.created_at,
                    "created_by": version.created_by,
                    "description": version.description,
                    "state_snapshot": json.dumps(version.state_snapshot),
                    "is_active": version.is_active,
                })
            except Exception as e:
                logger.error(json.dumps({
                    "event": "version_write_failed",
                    "version_id": version.version_id,
                    "error": str(e),
                }))

        logger.info(json.dumps({
            "event": "governance_version_created",
            "version_id": version.version_id,
            "version_number": version.version_number,
            "created_by": created_by,
            "description": description,
            "timestamp": version.created_at,
        }))

        return version

    def rollback_to_version(
        self, target_version_number: int, operator_id: str, reason: str
    ) -> Dict[str, Any]:
        """Instantly rollback governance to a previous version.

        Args:
            target_version_number: The version to rollback to.
            operator_id: Who is performing the rollback.
            reason: Why the rollback is needed.

        Returns:
            Dict with rollback result and the restored state snapshot.
        """
        target = None
        for v in self._version_history:
            if v.version_number == target_version_number:
                target = v
                break

        if target is None:
            return {
                "success": False,
                "error": f"Version {target_version_number} not found in history",
                "available_versions": [v.version_number for v in self._version_history],
            }

        previous_version = self._current_version
        if previous_version:
            previous_version.is_active = False

        rollback_version = GovernanceVersion(
            version_id=str(uuid.uuid4()),
            version_number=self._next_version_number,
            created_at=datetime.now(timezone.utc).isoformat(),
            created_by=operator_id,
            description=f"ROLLBACK to v{target_version_number}: {reason}",
            state_snapshot=target.state_snapshot,
            is_active=True,
            rollback_from=previous_version.version_id if previous_version else "",
        )

        self._current_version = rollback_version
        self._version_history.append(rollback_version)
        self._next_version_number += 1

        if self._version_table:
            try:
                self._version_table.put_item(Item={
                    "version_id": rollback_version.version_id,
                    "version_number": rollback_version.version_number,
                    "created_at": rollback_version.created_at,
                    "created_by": operator_id,
                    "description": rollback_version.description,
                    "state_snapshot": json.dumps(rollback_version.state_snapshot),
                    "is_active": True,
                    "rollback_from": rollback_version.rollback_from,
                })
            except Exception as e:
                logger.error(json.dumps({
                    "event": "rollback_version_write_failed",
                    "error": str(e),
                }))

        logger.warning(json.dumps({
            "event": "governance_rollback_executed",
            "from_version": previous_version.version_number if previous_version else 0,
            "to_version": target_version_number,
            "new_version": rollback_version.version_number,
            "operator_id": operator_id,
            "reason": reason,
            "timestamp": rollback_version.created_at,
        }))

        return {
            "success": True,
            "rolled_back_to": target_version_number,
            "new_version_number": rollback_version.version_number,
            "version_id": rollback_version.version_id,
            "state_snapshot": target.state_snapshot,
            "operator_id": operator_id,
            "reason": reason,
            "timestamp": rollback_version.created_at,
        }

    def get_version_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent governance version history."""
        recent = self._version_history[-limit:]
        return [
            {
                "version_number": v.version_number,
                "version_id": v.version_id,
                "created_at": v.created_at,
                "created_by": v.created_by,
                "description": v.description,
                "is_active": v.is_active,
                "is_rollback": bool(v.rollback_from),
            }
            for v in reversed(recent)
        ]

    def get_current_version(self) -> Optional[Dict[str, Any]]:
        """Get the currently active governance version."""
        if self._current_version is None:
            return None
        return {
            "version_number": self._current_version.version_number,
            "version_id": self._current_version.version_id,
            "created_at": self._current_version.created_at,
            "created_by": self._current_version.created_by,
            "description": self._current_version.description,
            "is_rollback": bool(self._current_version.rollback_from),
        }

    def diff_versions(self, version_a: int, version_b: int) -> Dict[str, Any]:
        """Compare two governance versions to show what changed."""
        va = vb = None
        for v in self._version_history:
            if v.version_number == version_a:
                va = v
            if v.version_number == version_b:
                vb = v

        if va is None or vb is None:
            return {"error": "One or both versions not found"}

        changes = {}
        for key in set(list(va.state_snapshot.keys()) + list(vb.state_snapshot.keys())):
            val_a = va.state_snapshot.get(key)
            val_b = vb.state_snapshot.get(key)
            if val_a != val_b:
                changes[key] = {
                    "version_a": val_a,
                    "version_b": val_b,
                }

        return {
            "version_a": version_a,
            "version_b": version_b,
            "changed_keys": list(changes.keys()),
            "changes": changes,
        }
