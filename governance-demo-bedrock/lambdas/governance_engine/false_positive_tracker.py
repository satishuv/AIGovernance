"""False Positive Rate Tracking.

Measures how often the governance pipeline INCORRECTLY blocks legitimate
requests. At enterprise scale, even 2% false positive rate means thousands
of frustrated users per day.

Mechanisms:
1. Operator override tracking: When an operator approves a previously-denied
   request, that denial is reclassified as a false positive.
2. Appeal workflow: Users can flag a denial as incorrect. Appeals reviewed
   by operators feed back into FP rate.
3. Statistical tracking: FP rate per detection module, per rule, per agent.
4. SLA enforcement: Alert if FP rate exceeds configurable threshold.
5. Auto-tuning signals: High-FP rules flagged for threshold adjustment.
"""

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

FP_RATE_SLA_THRESHOLD = 0.02
FP_RATE_WARNING_THRESHOLD = 0.01


@dataclass
class FalsePositiveRecord:
    decision_id: str
    agent_id: str
    action_requested: str
    denial_reason: str
    denial_module: str
    denial_rule: str
    reclassified_by: str
    reclassified_at: str
    classification: str = "false_positive"


@dataclass
class ModuleStats:
    module_name: str
    total_denials: int = 0
    confirmed_fp: int = 0
    pending_review: int = 0
    fp_rate: float = 0.0


class FalsePositiveTracker:
    """Tracks and measures false positive rates across the governance pipeline.

    Every denial that is later overridden (via operator approval, appeal,
    or allowlist addition) counts as a false positive against the module
    that triggered the denial.
    """

    def __init__(self, fp_table=None, sla_threshold: float = FP_RATE_SLA_THRESHOLD):
        self._fp_table = fp_table
        self._sla_threshold = sla_threshold
        self._module_stats: Dict[str, ModuleStats] = {}
        self._recent_fps: List[FalsePositiveRecord] = []
        self._total_denials = 0
        self._total_fps = 0

    def record_denial(self, decision_id: str, module: str, rule: str = "") -> None:
        """Record a denial for FP rate tracking."""
        self._total_denials += 1

        if module not in self._module_stats:
            self._module_stats[module] = ModuleStats(module_name=module)
        self._module_stats[module].total_denials += 1

    def reclassify_as_false_positive(
        self,
        decision_id: str,
        agent_id: str,
        action_requested: str,
        denial_reason: str,
        denial_module: str,
        denial_rule: str,
        reclassified_by: str,
    ) -> FalsePositiveRecord:
        """Reclassify a denial as a false positive.

        Called when:
        - An operator overrides a denial
        - A user appeal is approved
        - A rule is identified as overly aggressive
        """
        record = FalsePositiveRecord(
            decision_id=decision_id,
            agent_id=agent_id,
            action_requested=action_requested,
            denial_reason=denial_reason,
            denial_module=denial_module,
            denial_rule=denial_rule,
            reclassified_by=reclassified_by,
            reclassified_at=datetime.now(timezone.utc).isoformat(),
        )

        self._total_fps += 1
        self._recent_fps.append(record)

        if denial_module in self._module_stats:
            stats = self._module_stats[denial_module]
            stats.confirmed_fp += 1
            stats.fp_rate = (
                stats.confirmed_fp / stats.total_denials
                if stats.total_denials > 0 else 0.0
            )

        if self._fp_table:
            try:
                self._fp_table.put_item(Item={
                    "decision_id": decision_id,
                    "agent_id": agent_id,
                    "action_requested": action_requested,
                    "denial_reason": denial_reason,
                    "denial_module": denial_module,
                    "denial_rule": denial_rule,
                    "reclassified_by": reclassified_by,
                    "reclassified_at": record.reclassified_at,
                    "classification": "false_positive",
                })
            except Exception as e:
                logger.error(json.dumps({
                    "event": "fp_record_write_failed",
                    "decision_id": decision_id,
                    "error": str(e),
                }))

        self._check_sla_breach(denial_module)

        logger.info(json.dumps({
            "event": "false_positive_recorded",
            "decision_id": decision_id,
            "denial_module": denial_module,
            "denial_rule": denial_rule,
            "reclassified_by": reclassified_by,
            "module_fp_rate": round(
                self._module_stats.get(denial_module, ModuleStats(module_name="")).fp_rate, 4
            ),
            "overall_fp_rate": round(self.overall_fp_rate, 4),
            "timestamp": record.reclassified_at,
        }))

        return record

    @property
    def overall_fp_rate(self) -> float:
        """Overall false positive rate across all modules."""
        if self._total_denials == 0:
            return 0.0
        return self._total_fps / self._total_denials

    def _check_sla_breach(self, module: str) -> None:
        """Check if FP rate exceeds SLA threshold."""
        overall = self.overall_fp_rate

        if overall >= self._sla_threshold:
            logger.error(json.dumps({
                "event": "fp_rate_sla_breach",
                "overall_fp_rate": round(overall, 4),
                "sla_threshold": self._sla_threshold,
                "action": "alert_operators",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

        elif overall >= FP_RATE_WARNING_THRESHOLD:
            logger.warning(json.dumps({
                "event": "fp_rate_warning",
                "overall_fp_rate": round(overall, 4),
                "warning_threshold": FP_RATE_WARNING_THRESHOLD,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

        if module in self._module_stats:
            stats = self._module_stats[module]
            if stats.fp_rate >= self._sla_threshold and stats.total_denials >= 10:
                logger.error(json.dumps({
                    "event": "module_fp_rate_critical",
                    "module": module,
                    "fp_rate": round(stats.fp_rate, 4),
                    "total_denials": stats.total_denials,
                    "confirmed_fp": stats.confirmed_fp,
                    "recommendation": "review_and_tune_thresholds",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }))

    def get_high_fp_rules(self, threshold: float = 0.05) -> List[Dict[str, Any]]:
        """Get modules with FP rate above threshold (candidates for tuning)."""
        high_fp = []
        for name, stats in self._module_stats.items():
            if stats.fp_rate >= threshold and stats.total_denials >= 5:
                high_fp.append({
                    "module": name,
                    "fp_rate": round(stats.fp_rate, 4),
                    "total_denials": stats.total_denials,
                    "confirmed_fp": stats.confirmed_fp,
                    "recommendation": "tune_thresholds",
                })
        return sorted(high_fp, key=lambda x: x["fp_rate"], reverse=True)

    def get_report(self) -> Dict[str, Any]:
        """Generate FP rate report for dashboards."""
        return {
            "overall_fp_rate": round(self.overall_fp_rate, 4),
            "total_denials": self._total_denials,
            "total_false_positives": self._total_fps,
            "sla_threshold": self._sla_threshold,
            "sla_met": self.overall_fp_rate < self._sla_threshold,
            "modules": {
                name: {
                    "fp_rate": round(stats.fp_rate, 4),
                    "total_denials": stats.total_denials,
                    "confirmed_fp": stats.confirmed_fp,
                }
                for name, stats in self._module_stats.items()
            },
            "high_fp_modules": self.get_high_fp_rules(),
            "recent_fps_count": len(self._recent_fps),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
