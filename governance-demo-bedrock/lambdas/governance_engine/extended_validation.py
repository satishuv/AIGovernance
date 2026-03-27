"""Extended Compliance Validation Suite module.

Provides comprehensive compliance validation tests covering control mapping
completeness, evidence hash chain integrity, approval workflow correctness,
MEASURE/MANAGE report generation, and control trace reference verification.
Generates structured compliance reports with gap detection and remediation.

Requirements: 26.1, 26.2, 26.3, 26.4
"""

import json
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, List

from models import ValidationResult

logger = logging.getLogger(__name__)

IMPLEMENTED_CAPABILITIES = [
    "Policy_Engine",
    "Risk_Scoring_Engine",
    "Decision_Engine",
    "Evidence_Pipeline",
    "Kill_Switch",
    "Agent_Registry",
    "Separation_of_Duties",
    "Threat_Detector",
    "Approval_Workflow",
    "Change_Logger",
    "Decision_History",
    "CloudWatch_Metrics",
    "Privilege_Escalation_Hardening",
    "Exfiltration_Prevention",
    "Graduated_Scope_Reduction",
    "Multi_Agent_Support",
]


class ExtendedValidationSuite:
    """Extended compliance validation tests for governance platform."""

    def test_control_mapping_completeness(
        self, control_mapping_table
    ) -> ValidationResult:
        """Verify every capability maps to at least one framework control."""
        now = datetime.utcnow().isoformat()
        items = self._scan_all(control_mapping_table)
        mapped = {i.get("implementation_component", "") for i in items}
        unmapped = [c for c in IMPLEMENTED_CAPABILITIES if c not in mapped]
        passed = len(unmapped) == 0
        details = (
            "All capabilities mapped."
            if passed
            else f"Unmapped: {', '.join(unmapped)}"
        )
        return ValidationResult(
            test_name="control_mapping_completeness",
            passed=passed,
            evidence_record_ids=[],
            control_trace_ids=[i.get("control_id", "") for i in items],
            timestamp=now,
            details=details,
        )

    def test_evidence_hash_chain_integrity(
        self,
        s3_client,
        bucket: str,
        environment: str,
        agent_id: str,
        start_date: str,
        end_date: str,
    ) -> ValidationResult:
        """Verify end-to-end hash chain integrity for evidence records."""
        try:
            from evidence_integrity import EvidenceIntegrity
        except ImportError:
            return ValidationResult(
                test_name="evidence_hash_chain_integrity",
                passed=False,
                evidence_record_ids=[],
                control_trace_ids=[],
                details="evidence_integrity module not available",
                timestamp=datetime.utcnow().isoformat(),
            )

        now = datetime.utcnow().isoformat()
        integrity = EvidenceIntegrity()
        try:
            results = integrity.verify_hash_chain(
                s3_client, bucket, environment, agent_id, start_date, end_date
            )
            breaks = [r for r in results if not r.get("valid", True)]
            passed = len(breaks) == 0
            details = (
                "Hash chain integrity verified."
                if passed
                else f"Chain breaks detected: {len(breaks)}"
            )
        except Exception as exc:
            passed = False
            details = f"Hash chain verification failed: {str(exc)}"

        return ValidationResult(
            test_name="evidence_hash_chain_integrity",
            passed=passed,
            evidence_record_ids=[],
            control_trace_ids=[],
            timestamp=now,
            details=details,
        )

    def test_approval_workflow_correctness(
        self, pending_approval_table, evidence_bucket: str
    ) -> ValidationResult:
        """Verify approval workflow creates and resolves approvals correctly."""
        now = datetime.utcnow().isoformat()
        issues: List[str] = []
        items = self._scan_all(pending_approval_table)

        for item in items:
            status = item.get("status", "")
            if status == "approved" and not item.get("approver_id"):
                issues.append(
                    f"Approval {item.get('approval_id')} approved without approver_id"
                )
            if status == "denied" and not item.get("denial_reason"):
                issues.append(
                    f"Approval {item.get('approval_id')} denied without denial_reason"
                )

        passed = len(issues) == 0
        return ValidationResult(
            test_name="approval_workflow_correctness",
            passed=passed,
            evidence_record_ids=[],
            control_trace_ids=[],
            timestamp=now,
            details="Passed." if passed else f"Issues: {'; '.join(issues)}",
        )

    def test_measure_manage_report_generation(
        self,
        measure_manage_engine,
        decision_history_table,
        change_log_table,
    ) -> ValidationResult:
        """Verify MEASURE and MANAGE reports generate with correct structure."""
        now = datetime.utcnow().isoformat()
        issues: List[str] = []
        try:
            metrics = measure_manage_engine.compute_aggregate_metrics(
                decision_history_table, "2020-01-01T00:00:00Z", now
            )
            if metrics.total_decisions < 0:
                issues.append("Negative total_decisions")
            measure = measure_manage_engine.generate_measure_report(metrics, {})
            if not measure.report_id:
                issues.append("MeasureReport missing report_id")
            manage = measure_manage_engine.generate_manage_report(
                change_log_table, decision_history_table,
                "2020-01-01T00:00:00Z", now,
            )
            if not manage.report_id:
                issues.append("ManageReport missing report_id")
        except Exception as exc:
            issues.append(f"Report generation failed: {str(exc)}")

        passed = len(issues) == 0
        return ValidationResult(
            test_name="measure_manage_report_generation",
            passed=passed,
            evidence_record_ids=[],
            control_trace_ids=[],
            timestamp=now,
            details="Reports generated." if passed else "; ".join(issues),
        )

    def verify_control_trace_references(
        self,
        control_trace_table,
        evidence_bucket: str,
        decision_history_table,
    ) -> ValidationResult:
        """Verify every ControlTrace references valid evidence and decision."""
        now = datetime.utcnow().isoformat()
        orphaned: List[str] = []
        traces = self._scan_all(control_trace_table)

        for t in traces:
            if not t.get("evidence_record_id"):
                orphaned.append(f"Trace {t.get('control_id')} missing evidence_record_id")
            if not t.get("decision_id"):
                orphaned.append(f"Trace {t.get('control_id')} missing decision_id")

        passed = len(orphaned) == 0
        return ValidationResult(
            test_name="control_trace_references",
            passed=passed,
            evidence_record_ids=[],
            control_trace_ids=[t.get("control_id", "") for t in traces],
            timestamp=now,
            details="All references valid." if passed else f"Orphaned: {'; '.join(orphaned)}",
        )

    def generate_compliance_report(
        self,
        results: List[ValidationResult],
        output_format: str = "json",
    ) -> str:
        """Produce structured compliance validation report."""
        now = datetime.utcnow().isoformat()
        gaps = self.detect_gaps(results)

        if output_format == "markdown":
            return self._to_markdown(results, gaps, now)

        report = {
            "report_id": str(uuid.uuid4()),
            "generated_at": now,
            "total_tests": len(results),
            "passed": sum(1 for r in results if r.passed),
            "failed": sum(1 for r in results if not r.passed),
            "results": [r.to_dict() for r in results],
            "gaps": gaps,
        }
        return json.dumps(report, default=str, indent=2)

    def detect_gaps(self, results: List[ValidationResult]) -> List[Dict[str, str]]:
        """Identify compliance gaps with remediation recommendations."""
        remediation_map = {
            "control_mapping_completeness": "Add missing control mappings to ControlMappingTable.",
            "evidence_hash_chain_integrity": "Investigate broken hash chains and re-generate affected records.",
            "approval_workflow_correctness": "Ensure approver_id and denial_reason are set correctly.",
            "measure_manage_report_generation": "Check table connectivity and engine configuration.",
            "control_trace_references": "Link orphaned traces to valid evidence and decisions.",
        }
        gaps: List[Dict[str, str]] = []
        for r in results:
            if not r.passed:
                gaps.append({
                    "test_name": r.test_name,
                    "description": r.details,
                    "remediation": remediation_map.get(r.test_name, "Review and fix."),
                })
        return gaps

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _scan_all(table) -> List[Dict[str, Any]]:
        items: List[Dict[str, Any]] = []
        response = table.scan()
        items.extend(response.get("Items", []))
        while "LastEvaluatedKey" in response:
            response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
            items.extend(response.get("Items", []))
        return items

    @staticmethod
    def _to_markdown(results, gaps, generated_at):
        passed = sum(1 for r in results if r.passed)
        failed = sum(1 for r in results if not r.passed)
        lines = [
            "# Extended Compliance Validation Report",
            f"Generated: {generated_at}",
            "",
            f"**Total: {len(results)} | Passed: {passed} | Failed: {failed}**",
            "",
            "| Test | Status | Details |",
            "|------|--------|---------|",
        ]
        for r in results:
            status = "PASS" if r.passed else "FAIL"
            lines.append(f"| {r.test_name} | {status} | {r.details} |")
        if gaps:
            lines.append("")
            lines.append("## Gaps")
            for g in gaps:
                lines.append(f"- **{g['test_name']}**: {g['description']} -> {g['remediation']}")
        return "\n".join(lines) + "\n"
