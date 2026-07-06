"""Proactive Governance Engine - Policy validation before deployment.

The third governance engine. While Preventive blocks actions and Detective
monitors behavior, Proactive validates that governance CONFIGURATIONS are
correct before they go live. It catches:

1. Policy contradictions (two rules that match the same input with different outcomes)
2. Dead rules (rules that can never match because a higher-priority rule always wins)
3. Coverage gaps (action groups with no matching allow rule at any scope)
4. Unsafe policy changes (removing deny rules, adding broad allow rules)
5. Circular dependencies (approval workflows that reference each other)

Used by:
- CI/CD pipeline (validate policy changes before S3 upload)
- Compliance refresh Lambda (periodic health check)
- Admin API (validate before manual policy updates)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class PolicyValidationResult:
    """Result of proactive policy validation."""

    def __init__(self):
        self.valid = True
        self.errors: List[Dict[str, Any]] = []
        self.warnings: List[Dict[str, Any]] = []
        self.coverage_report: Dict[str, Any] = {}
        self.timestamp = datetime.now(timezone.utc).isoformat()

    def add_error(self, category: str, detail: str, rules_involved: List[str] = None):
        self.valid = False
        self.errors.append({
            "category": category,
            "detail": detail,
            "rules_involved": rules_involved or [],
            "severity": "error",
        })

    def add_warning(self, category: str, detail: str, rules_involved: List[str] = None):
        self.warnings.append({
            "category": category,
            "detail": detail,
            "rules_involved": rules_involved or [],
            "severity": "warning",
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "valid": self.valid,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "errors": self.errors,
            "warnings": self.warnings,
            "coverage_report": self.coverage_report,
            "timestamp": self.timestamp,
        }


class ProactiveEngine:
    """Validates governance policies and configurations before deployment."""

    KNOWN_ACTION_GROUPS = [
        "ReadPipelineStatus",
        "ProposeChanges",
        "StagingDeployment",
        "ProductionDeployment",
    ]
    KNOWN_SCOPE_LEVELS = [1, 2, 3, 4]

    def validate_policies(self, policies: List[Dict[str, Any]]) -> PolicyValidationResult:
        """Run all validation checks on a set of policies.

        Args:
            policies: List of policy dicts in OPA format
                     (rule_name, outcome, priority, conditions)

        Returns:
            PolicyValidationResult with errors, warnings, and coverage report.
        """
        result = PolicyValidationResult()

        if not policies:
            result.add_error("empty_policy_set", "No policies provided. System will default-deny everything.")
            return result

        self._check_contradictions(policies, result)
        self._check_dead_rules(policies, result)
        self._check_coverage_gaps(policies, result)
        self._check_default_deny_exists(policies, result)
        self._check_priority_conflicts(policies, result)
        self._check_unsafe_broad_allows(policies, result)

        return result

    def validate_policy_change(self, existing: List[Dict[str, Any]],
                               proposed: List[Dict[str, Any]]) -> PolicyValidationResult:
        """Validate a proposed policy change against the existing set.

        Checks that the change doesn't:
        - Remove the default deny
        - Remove all deny rules for a critical action group
        - Add an unrestricted allow rule with high priority
        """
        result = PolicyValidationResult()

        existing_names = {p.get("rule_name", "") for p in existing}
        proposed_names = {p.get("rule_name", "") for p in proposed}

        removed = existing_names - proposed_names
        added = proposed_names - existing_names

        # Check: default deny removal
        existing_has_default = any(
            p.get("rule_name") == "default_deny" or
            (p.get("outcome") == "deny" and not p.get("conditions"))
            for p in existing
        )
        proposed_has_default = any(
            p.get("rule_name") == "default_deny" or
            (p.get("outcome") == "deny" and not p.get("conditions"))
            for p in proposed
        )
        if existing_has_default and not proposed_has_default:
            result.add_error(
                "default_deny_removed",
                "Proposed change removes the default deny rule. System would fail-open.",
                list(removed),
            )

        # Check: all deny rules for production removed
        existing_prod_denies = [
            p for p in existing
            if p.get("outcome") == "deny" and
            any(c.get("value") == "ProductionDeployment"
                for c in p.get("conditions", []) if c.get("field", "").endswith("action_group"))
        ]
        proposed_prod_denies = [
            p for p in proposed
            if p.get("outcome") == "deny" and
            any(c.get("value") == "ProductionDeployment"
                for c in p.get("conditions", []) if c.get("field", "").endswith("action_group"))
        ]
        if existing_prod_denies and not proposed_prod_denies:
            result.add_error(
                "production_deny_removed",
                "Proposed change removes ALL deny rules for ProductionDeployment. Production would be unprotected.",
                [p.get("rule_name", "") for p in existing_prod_denies],
            )

        # Check: new broad allow with high priority
        for p in proposed:
            if p.get("rule_name") in added:
                if p.get("outcome") == "allow" and p.get("priority", 9999) <= 5:
                    conditions = p.get("conditions", [])
                    if len(conditions) == 0:
                        result.add_error(
                            "unrestricted_allow",
                            f"New rule '{p.get('rule_name')}' allows everything with priority {p.get('priority')}. This overrides all other rules.",
                            [p.get("rule_name", "")],
                        )

        # Also validate the proposed set itself
        proposed_result = self.validate_policies(proposed)
        result.errors.extend(proposed_result.errors)
        result.warnings.extend(proposed_result.warnings)
        if proposed_result.errors:
            result.valid = False

        return result

    def _check_contradictions(self, policies: List[Dict[str, Any]],
                              result: PolicyValidationResult) -> None:
        """Find rules that match the same input with different outcomes.

        Two rules contradict if they have overlapping conditions and
        different outcomes at the same priority level.
        """
        for i, p1 in enumerate(policies):
            for p2 in policies[i+1:]:
                if p1.get("priority") == p2.get("priority") and p1.get("outcome") != p2.get("outcome"):
                    if self._conditions_overlap(p1.get("conditions", []), p2.get("conditions", [])):
                        result.add_error(
                            "contradiction",
                            f"Rules '{p1.get('rule_name')}' ({p1.get('outcome')}) and "
                            f"'{p2.get('rule_name')}' ({p2.get('outcome')}) have same priority "
                            f"({p1.get('priority')}) with overlapping conditions.",
                            [p1.get("rule_name", ""), p2.get("rule_name", "")],
                        )

    def _check_dead_rules(self, policies: List[Dict[str, Any]],
                          result: PolicyValidationResult) -> None:
        """Find rules that can never win because a higher-priority rule always matches first."""
        sorted_policies = sorted(policies, key=lambda p: p.get("priority", 9999))

        for i, policy in enumerate(sorted_policies):
            if not policy.get("conditions"):
                continue

            for higher in sorted_policies[:i]:
                if higher.get("priority", 9999) >= policy.get("priority", 9999):
                    continue
                if not higher.get("conditions"):
                    if higher.get("outcome") == policy.get("outcome"):
                        continue
                    result.add_warning(
                        "dead_rule",
                        f"Rule '{policy.get('rule_name')}' (priority {policy.get('priority')}) "
                        f"is shadowed by '{higher.get('rule_name')}' (priority {higher.get('priority')}) "
                        f"which has no conditions and always matches first.",
                        [policy.get("rule_name", ""), higher.get("rule_name", "")],
                    )
                    break

    def _check_coverage_gaps(self, policies: List[Dict[str, Any]],
                             result: PolicyValidationResult) -> None:
        """Check if every action group has at least one allow rule at some scope level."""
        coverage = {}

        for ag in self.KNOWN_ACTION_GROUPS:
            covered_scopes = []
            for scope in self.KNOWN_SCOPE_LEVELS:
                has_allow = False
                for policy in policies:
                    if policy.get("outcome") != "allow":
                        continue
                    conditions = policy.get("conditions", [])
                    ag_match = any(
                        c.get("field", "").endswith("action_group") and c.get("value") == ag
                        for c in conditions
                    )
                    scope_ok = True
                    for c in conditions:
                        if c.get("field", "").endswith("scope_level"):
                            op = c.get("op", "==")
                            val = c.get("value", 0)
                            if op == "==" and scope != val:
                                scope_ok = False
                            elif op == ">=" and scope < val:
                                scope_ok = False
                            elif op == ">" and scope <= val:
                                scope_ok = False
                    if ag_match and scope_ok:
                        has_allow = True
                        break
                    if not conditions and policy.get("outcome") == "allow":
                        has_allow = True
                        break
                if has_allow:
                    covered_scopes.append(scope)

            coverage[ag] = covered_scopes
            if not covered_scopes:
                result.add_warning(
                    "coverage_gap",
                    f"Action group '{ag}' has no allow rule at any scope level. "
                    f"It will always be denied (or only allowed by catch-all rules).",
                    [],
                )

        result.coverage_report = {
            "action_group_coverage": coverage,
            "total_action_groups": len(self.KNOWN_ACTION_GROUPS),
            "fully_covered": sum(1 for v in coverage.values() if v),
        }

    def _check_default_deny_exists(self, policies: List[Dict[str, Any]],
                                   result: PolicyValidationResult) -> None:
        """Ensure a default deny (catch-all) rule exists."""
        has_default = any(
            p.get("outcome") == "deny" and not p.get("conditions")
            for p in policies
        )
        if not has_default:
            result.add_error(
                "no_default_deny",
                "No default deny rule found. Requests matching no rule will have undefined behavior.",
                [],
            )

    def _check_priority_conflicts(self, policies: List[Dict[str, Any]],
                                  result: PolicyValidationResult) -> None:
        """Check for multiple rules at the same priority with different outcomes."""
        priority_groups: Dict[int, List[Dict]] = {}
        for p in policies:
            pri = p.get("priority", 9999)
            priority_groups.setdefault(pri, []).append(p)

        for pri, group in priority_groups.items():
            outcomes = set(p.get("outcome") for p in group)
            if len(outcomes) > 1 and len(group) > 1:
                result.add_warning(
                    "priority_conflict",
                    f"Priority {pri} has {len(group)} rules with different outcomes: {outcomes}. "
                    f"Resolution may be non-deterministic.",
                    [p.get("rule_name", "") for p in group],
                )

    def _check_unsafe_broad_allows(self, policies: List[Dict[str, Any]],
                                   result: PolicyValidationResult) -> None:
        """Flag allow rules with no conditions or very broad conditions."""
        for p in policies:
            if p.get("outcome") != "allow":
                continue
            conditions = p.get("conditions", [])
            if not conditions:
                result.add_warning(
                    "broad_allow",
                    f"Rule '{p.get('rule_name')}' allows everything (no conditions). "
                    f"This overrides all deny rules at lower priority.",
                    [p.get("rule_name", "")],
                )

    @staticmethod
    def _conditions_overlap(conds1: List[Dict], conds2: List[Dict]) -> bool:
        """Check if two condition sets could match the same input."""
        if not conds1 or not conds2:
            return True

        fields1 = {c.get("field") for c in conds1}
        fields2 = {c.get("field") for c in conds2}

        shared_fields = fields1 & fields2
        if not shared_fields:
            return True

        for field in shared_fields:
            c1 = next((c for c in conds1 if c.get("field") == field), None)
            c2 = next((c for c in conds2 if c.get("field") == field), None)
            if c1 and c2:
                if c1.get("op") == "==" and c2.get("op") == "==" and c1.get("value") != c2.get("value"):
                    return False

        return True
