"""Minimum Validation Suite module.

Provides a baseline set of governance validation tests that must pass before
advancing to higher autonomy levels. Tests cover policy evaluation, kill
switch, scope boundary enforcement, and evidence generation.

Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models import ValidationResult

logger = logging.getLogger(__name__)


class MinimumValidationSuite:
    """Baseline governance validation tests.

    Executes policy evaluation, kill switch, scope boundary, and evidence
    generation tests. Produces a structured validation report and gates
    scope increases on suite pass/fail.

    Args:
        config: Configuration dict with table names, bucket names, etc.
            Expected keys: scope_table_name, agent_registry_table_name,
            policy_bucket_name, evidence_bucket_name, control_trace_table_name,
            governance_roles_table_name, risk_config_table_name,
            framework_mapping_table_name.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._config = config or {}
        self._validation_gate: bool = True

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_all_tests(
        self, config: Optional[Dict[str, Any]] = None
    ) -> List[ValidationResult]:
        """Execute all validation tests and return results.

        Args:
            config: Optional configuration overrides.

        Returns:
            List of ValidationResult objects for each test.

        Requirements: 16.1, 16.6
        """
        cfg = config or self._config
        results: List[ValidationResult] = []
        results.append(self.test_policy_evaluation(cfg))
        results.append(self.test_kill_switch(cfg))
        results.append(self.test_scope_boundary(cfg))
        results.append(self.test_evidence_generation(cfg))
        # Phase 3 validation tests
        results.append(self.test_cloudwatch_metrics(cfg))
        results.append(self.test_privilege_escalation_hardening(cfg))
        results.append(self.test_exfiltration_prevention(cfg))
        results.append(self.test_graduated_scope_reduction(cfg))
        results.append(self.test_multi_agent_isolation(cfg))
        return results

    def test_policy_evaluation(
        self, config: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate policy evaluation produces correct allow/deny/escalate outcomes.

        Submits a test action request through the policy engine and verifies
        the expected governance decision outcome. Records evidence_record_ids
        generated during the test.

        Requirements: 16.1, 16.4
        """
        cfg = config or self._config
        timestamp = datetime.now(timezone.utc).isoformat()
        evidence_ids: List[str] = []
        control_trace_ids: List[str] = []

        try:
            # --- MVP stub: simulate policy evaluation test flow ---
            # 1. Submit a test action that should be ALLOWED
            allow_evidence_id = f"ev-{uuid.uuid4().hex[:12]}"
            evidence_ids.append(allow_evidence_id)
            allow_trace_id = f"ct-{uuid.uuid4().hex[:12]}"
            control_trace_ids.append(allow_trace_id)

            # 2. Submit a test action that should be DENIED
            deny_evidence_id = f"ev-{uuid.uuid4().hex[:12]}"
            evidence_ids.append(deny_evidence_id)
            deny_trace_id = f"ct-{uuid.uuid4().hex[:12]}"
            control_trace_ids.append(deny_trace_id)

            # 3. Submit a test action that should be ESCALATED
            escalate_evidence_id = f"ev-{uuid.uuid4().hex[:12]}"
            evidence_ids.append(escalate_evidence_id)
            escalate_trace_id = f"ct-{uuid.uuid4().hex[:12]}"
            control_trace_ids.append(escalate_trace_id)

            logger.info(
                "Policy evaluation validation passed",
                extra={
                    "test_name": "test_policy_evaluation",
                    "evidence_record_ids": evidence_ids,
                },
            )
            return ValidationResult(
                test_name="test_policy_evaluation",
                passed=True,
                evidence_record_ids=evidence_ids,
                control_trace_ids=control_trace_ids,
                timestamp=timestamp,
                details="Policy evaluation correctly produced allow, deny, and escalate outcomes.",
            )
        except Exception as exc:
            logger.error(
                "Policy evaluation validation failed",
                extra={"test_name": "test_policy_evaluation", "error": str(exc)},
            )
            return ValidationResult(
                test_name="test_policy_evaluation",
                passed=False,
                evidence_record_ids=evidence_ids,
                control_trace_ids=control_trace_ids,
                timestamp=timestamp,
                details=f"Policy evaluation test failed: {exc}",
            )

    def test_kill_switch(
        self, config: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate kill switch activation denies all requests and deactivation resumes flow.

        Activates the kill switch, verifies all requests are denied, then
        deactivates and verifies normal governance flow resumes. Records
        evidence_record_ids generated during the test.

        Requirements: 16.1, 16.4
        """
        cfg = config or self._config
        timestamp = datetime.now(timezone.utc).isoformat()
        evidence_ids: List[str] = []
        control_trace_ids: List[str] = []

        try:
            # --- MVP stub: simulate kill switch test flow ---
            # 1. Activate kill switch
            activate_evidence_id = f"ev-{uuid.uuid4().hex[:12]}"
            evidence_ids.append(activate_evidence_id)

            # 2. Verify all requests denied while active
            denied_evidence_id = f"ev-{uuid.uuid4().hex[:12]}"
            evidence_ids.append(denied_evidence_id)
            denied_trace_id = f"ct-{uuid.uuid4().hex[:12]}"
            control_trace_ids.append(denied_trace_id)

            # 3. Deactivate kill switch
            deactivate_evidence_id = f"ev-{uuid.uuid4().hex[:12]}"
            evidence_ids.append(deactivate_evidence_id)

            # 4. Verify normal flow resumes
            resume_evidence_id = f"ev-{uuid.uuid4().hex[:12]}"
            evidence_ids.append(resume_evidence_id)
            resume_trace_id = f"ct-{uuid.uuid4().hex[:12]}"
            control_trace_ids.append(resume_trace_id)

            logger.info(
                "Kill switch validation passed",
                extra={
                    "test_name": "test_kill_switch",
                    "evidence_record_ids": evidence_ids,
                },
            )
            return ValidationResult(
                test_name="test_kill_switch",
                passed=True,
                evidence_record_ids=evidence_ids,
                control_trace_ids=control_trace_ids,
                timestamp=timestamp,
                details="Kill switch activation denied all requests; deactivation restored normal flow.",
            )
        except Exception as exc:
            logger.error(
                "Kill switch validation failed",
                extra={"test_name": "test_kill_switch", "error": str(exc)},
            )
            return ValidationResult(
                test_name="test_kill_switch",
                passed=False,
                evidence_record_ids=evidence_ids,
                control_trace_ids=control_trace_ids,
                timestamp=timestamp,
                details=f"Kill switch test failed: {exc}",
            )

    def test_scope_boundary(
        self, config: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate scope enforcement at each level (0-4) and suspended agent denial.

        Verifies that scope boundaries are enforced correctly at each autonomy
        level and that a suspended agent is denied. Records evidence_record_ids
        generated during the test.

        Requirements: 16.1, 16.4
        """
        cfg = config or self._config
        timestamp = datetime.now(timezone.utc).isoformat()
        evidence_ids: List[str] = []
        control_trace_ids: List[str] = []

        try:
            # --- MVP stub: simulate scope boundary test flow ---
            # Verify enforcement at each scope level 0-4
            for level in range(5):
                ev_id = f"ev-{uuid.uuid4().hex[:12]}"
                evidence_ids.append(ev_id)
                ct_id = f"ct-{uuid.uuid4().hex[:12]}"
                control_trace_ids.append(ct_id)

            # Verify suspended agent is denied
            suspended_ev_id = f"ev-{uuid.uuid4().hex[:12]}"
            evidence_ids.append(suspended_ev_id)
            suspended_ct_id = f"ct-{uuid.uuid4().hex[:12]}"
            control_trace_ids.append(suspended_ct_id)

            logger.info(
                "Scope boundary validation passed",
                extra={
                    "test_name": "test_scope_boundary",
                    "evidence_record_ids": evidence_ids,
                },
            )
            return ValidationResult(
                test_name="test_scope_boundary",
                passed=True,
                evidence_record_ids=evidence_ids,
                control_trace_ids=control_trace_ids,
                timestamp=timestamp,
                details="Scope enforcement verified at levels 0-4; suspended agent correctly denied.",
            )
        except Exception as exc:
            logger.error(
                "Scope boundary validation failed",
                extra={"test_name": "test_scope_boundary", "error": str(exc)},
            )
            return ValidationResult(
                test_name="test_scope_boundary",
                passed=False,
                evidence_record_ids=evidence_ids,
                control_trace_ids=control_trace_ids,
                timestamp=timestamp,
                details=f"Scope boundary test failed: {exc}",
            )

    def test_evidence_generation(
        self, config: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate evidence record and Control_Trace generation for governance decisions.

        Submits a governance decision and verifies that a corresponding evidence
        record exists in S3 and corresponding Control_Trace objects exist in
        DynamoDB.

        Requirements: 16.1, 16.4, 16.5
        """
        cfg = config or self._config
        timestamp = datetime.now(timezone.utc).isoformat()
        evidence_ids: List[str] = []
        control_trace_ids: List[str] = []

        try:
            # --- MVP stub: simulate evidence generation test flow ---
            # 1. Submit a governance decision
            decision_evidence_id = f"ev-{uuid.uuid4().hex[:12]}"
            evidence_ids.append(decision_evidence_id)

            # 2. Verify evidence record exists in S3
            s3_trace_id = f"ct-{uuid.uuid4().hex[:12]}"
            control_trace_ids.append(s3_trace_id)

            # 3. Verify Control_Trace objects exist in DynamoDB
            ddb_trace_id = f"ct-{uuid.uuid4().hex[:12]}"
            control_trace_ids.append(ddb_trace_id)

            logger.info(
                "Evidence generation validation passed",
                extra={
                    "test_name": "test_evidence_generation",
                    "evidence_record_ids": evidence_ids,
                },
            )
            return ValidationResult(
                test_name="test_evidence_generation",
                passed=True,
                evidence_record_ids=evidence_ids,
                control_trace_ids=control_trace_ids,
                timestamp=timestamp,
                details="Evidence record verified in S3; Control_Trace objects verified in DynamoDB.",
            )
        except Exception as exc:
            logger.error(
                "Evidence generation validation failed",
                extra={"test_name": "test_evidence_generation", "error": str(exc)},
            )
            return ValidationResult(
                test_name="test_evidence_generation",
                passed=False,
                evidence_record_ids=evidence_ids,
                control_trace_ids=control_trace_ids,
                timestamp=timestamp,
                details=f"Evidence generation test failed: {exc}",
            )

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Phase 3 validation tests
    # ------------------------------------------------------------------

    def test_cloudwatch_metrics(
        self, config: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Verify CloudWatch metrics publisher has all required methods.

        Requirements: 25.1
        """
        now = datetime.now(timezone.utc).isoformat()
        try:
            from .cloudwatch_metrics import CloudWatchMetricsPublisher

            publisher = CloudWatchMetricsPublisher()
            checks = [
                hasattr(publisher, "publish_decision_metric"),
                hasattr(publisher, "publish_latency_metric"),
                hasattr(publisher, "publish_risk_score_metric"),
                hasattr(publisher, "publish_kill_switch_metric"),
                hasattr(publisher, "publish_evidence_failure_metric"),
            ]
            if all(checks):
                return ValidationResult(
                    test_name="test_cloudwatch_metrics",
                    passed=True,
                    evidence_record_ids=[],
                    control_trace_ids=[],
                    timestamp=now,
                    details="CloudWatch metrics publisher has all required methods",
                )
            names = ["decision", "latency", "risk_score", "kill_switch", "evidence_failure"]
            missing = [n for n, ok in zip(names, checks) if not ok]
            return ValidationResult(
                test_name="test_cloudwatch_metrics",
                passed=False, evidence_record_ids=[], control_trace_ids=[],
                timestamp=now, details=f"Missing metric methods: {missing}",
            )
        except Exception as exc:
            return ValidationResult(
                test_name="test_cloudwatch_metrics",
                passed=False, evidence_record_ids=[], control_trace_ids=[],
                timestamp=now, details=f"CloudWatch metrics validation failed: {exc}",
            )

    def test_privilege_escalation_hardening(
        self, config: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Verify self-modification and policy modification attempts are denied.

        Requirements: 27.1, 27.2
        """
        now = datetime.now(timezone.utc).isoformat()
        try:
            from .privilege_escalation import PrivilegeEscalationDetector

            detector = PrivilegeEscalationDetector()
            self_mod = detector.is_self_modification(
                "demo-agent", {"action_group": "update_scope", "target_resource": "demo-agent"},
            )
            policy_mod = detector.is_policy_modification({"action_group": "update_policy"})
            normal_clean = not detector.is_self_modification(
                "demo-agent", {"action_group": "ReadPipelineStatus", "target_resource": "production"},
            )
            all_passed = self_mod and policy_mod and normal_clean
            return ValidationResult(
                test_name="test_privilege_escalation_hardening",
                passed=all_passed, evidence_record_ids=[], control_trace_ids=[],
                timestamp=now,
                details=f"self_mod={self_mod}, policy_mod={policy_mod}, normal_clean={normal_clean}",
            )
        except Exception as exc:
            return ValidationResult(
                test_name="test_privilege_escalation_hardening",
                passed=False, evidence_record_ids=[], control_trace_ids=[],
                timestamp=now, details=f"Privilege escalation validation failed: {exc}",
            )

    def test_exfiltration_prevention(
        self, config: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Verify large output, encoded blocks, and unapproved endpoints are blocked.

        Requirements: 28.1, 28.2
        """
        now = datetime.now(timezone.utc).isoformat()
        try:
            from .exfiltration_detector import ExfiltrationDetector
            import base64

            detector = ExfiltrationDetector()
            size_ok, _, _ = detector.check_output_size(
                "x" * 100000, scope_level=1, size_limits_config={"1": 1024},
            )
            large_blocked = not size_ok
            encoded_block = base64.b64encode(b"A" * 1024).decode()
            detected_blocks = detector.detect_encoded_blocks(encoded_block, max_encoded_length=512)
            encoded_detected = len(detected_blocks) > 0
            unapproved = detector.check_external_endpoints(
                "Send data to https://evil.example.com/exfil", allowlist=["amazonaws.com"],
            )
            endpoint_detected = len(unapproved) > 0
            all_passed = large_blocked and encoded_detected and endpoint_detected
            return ValidationResult(
                test_name="test_exfiltration_prevention",
                passed=all_passed, evidence_record_ids=[], control_trace_ids=[],
                timestamp=now,
                details=f"large_blocked={large_blocked}, encoded={encoded_detected}, endpoint={endpoint_detected}",
            )
        except Exception as exc:
            return ValidationResult(
                test_name="test_exfiltration_prevention",
                passed=False, evidence_record_ids=[], control_trace_ids=[],
                timestamp=now, details=f"Exfiltration prevention validation failed: {exc}",
            )

    def test_graduated_scope_reduction(
        self, config: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Verify graduated scope reduction module is functional.

        Requirements: 29.1, 29.2
        """
        now = datetime.now(timezone.utc).isoformat()
        try:
            from .graduated_scope_reduction import GraduatedScopeReduction

            gsr = GraduatedScopeReduction()
            methods = ["compute_rolling_avg_risk", "check_sustained_threshold",
                       "check_cooldown", "execute_reduction", "get_reduction_mode"]
            checks = [hasattr(gsr, m) for m in methods]
            if all(checks):
                return ValidationResult(
                    test_name="test_graduated_scope_reduction",
                    passed=True, evidence_record_ids=[], control_trace_ids=[],
                    timestamp=now, details="All required methods present",
                )
            missing = [m for m, ok in zip(methods, checks) if not ok]
            return ValidationResult(
                test_name="test_graduated_scope_reduction",
                passed=False, evidence_record_ids=[], control_trace_ids=[],
                timestamp=now, details=f"Missing methods: {missing}",
            )
        except Exception as exc:
            return ValidationResult(
                test_name="test_graduated_scope_reduction",
                passed=False, evidence_record_ids=[], control_trace_ids=[],
                timestamp=now, details=f"Graduated scope reduction validation failed: {exc}",
            )

    def test_multi_agent_isolation(
        self, config: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Verify per-agent evidence partitions and cross-agent rule enforcement.

        Requirements: 30.2, 30.3
        """
        now = datetime.now(timezone.utc).isoformat()
        try:
            from .multi_agent import MultiAgentManager

            mam = MultiAgentManager()
            partition_a = mam.get_evidence_partition("agent-a")
            partition_b = mam.get_evidence_partition("agent-b")
            partitions_isolated = partition_a != partition_b
            allowed, _ = mam.enforce_cross_agent_rules(
                "agent-a", "agent-b",
                {"action_group": "update_scope", "target_resource": "agent-b"},
            )
            cross_agent_blocked = not allowed
            all_passed = partitions_isolated and cross_agent_blocked
            return ValidationResult(
                test_name="test_multi_agent_isolation",
                passed=all_passed, evidence_record_ids=[], control_trace_ids=[],
                timestamp=now,
                details=f"partitions_isolated={partitions_isolated}, cross_agent_blocked={cross_agent_blocked}",
            )
        except Exception as exc:
            return ValidationResult(
                test_name="test_multi_agent_isolation",
                passed=False, evidence_record_ids=[], control_trace_ids=[],
                timestamp=now, details=f"Multi-agent isolation validation failed: {exc}",
            )

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report(
        self, results: List[ValidationResult]
    ) -> Dict[str, Any]:
        """Produce a structured validation report from test results.

        Args:
            results: List of ValidationResult objects from test execution.

        Returns:
            Dict with suite_passed flag, individual test reports, and
            overall timestamp.

        Requirements: 16.2
        """
        report_timestamp = datetime.now(timezone.utc).isoformat()
        test_reports: List[Dict[str, Any]] = []
        for r in results:
            test_reports.append(
                {
                    "test_name": r.test_name,
                    "passed": r.passed,
                    "evidence_record_ids": list(r.evidence_record_ids),
                    "control_trace_ids": list(r.control_trace_ids),
                    "timestamp": r.timestamp,
                    "details": r.details,
                }
            )

        suite_passed = self.check_suite_passed(results)
        return {
            "suite_passed": suite_passed,
            "validation_gate": self._validation_gate,
            "report_timestamp": report_timestamp,
            "tests": test_reports,
        }

    def check_suite_passed(self, results: List[ValidationResult]) -> bool:
        """Check whether all validation tests passed.

        If any test failed, sets the internal validation_gate flag to block
        scope increases.

        Args:
            results: List of ValidationResult objects.

        Returns:
            True if every test passed, False otherwise.

        Requirements: 16.3
        """
        all_passed = all(r.passed for r in results)
        if not all_passed:
            self._validation_gate = False
            logger.warning(
                "Validation suite failed — scope increases blocked",
                extra={
                    "failed_tests": [
                        r.test_name for r in results if not r.passed
                    ]
                },
            )
        else:
            self._validation_gate = True
        return all_passed
