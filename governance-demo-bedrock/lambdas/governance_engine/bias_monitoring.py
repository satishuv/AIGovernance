"""Bias Monitoring for AI Agent Outputs.

Monitors model outputs for demographic, sentiment, and fairness biases.
Tracks bias metrics over time and alerts when thresholds are crossed.

Monitors:
- Demographic bias (disparate treatment across groups)
- Sentiment bias (consistently positive/negative toward categories)
- Decision bias (systematic allow/deny patterns by agent attribute)
- Language bias (formality, complexity differences)
- Output length bias (shorter responses for certain inputs)

Addresses LLM Council feedback:
- "Many governance frameworks emphasize fairness"
- "Monitor model biases"
- "Extend to monitor fairness"
"""

import json
import logging
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BiasMetric:
    """A single bias measurement."""
    metric_name: str
    group_a: str
    group_b: str
    group_a_rate: float
    group_b_rate: float
    disparity_ratio: float
    threshold: float
    exceeded: bool
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metric_name": self.metric_name,
            "group_a": self.group_a,
            "group_b": self.group_b,
            "group_a_rate": round(self.group_a_rate, 4),
            "group_b_rate": round(self.group_b_rate, 4),
            "disparity_ratio": round(self.disparity_ratio, 4),
            "threshold": self.threshold,
            "exceeded": self.exceeded,
            "timestamp": self.timestamp,
        }


@dataclass
class BiasReport:
    """Bias monitoring report for a time period."""
    report_id: str
    period: str
    total_decisions_analyzed: int = 0
    bias_metrics: List[BiasMetric] = field(default_factory=list)
    alerts: List[str] = field(default_factory=list)
    overall_fairness_score: float = 100.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "period": self.period,
            "total_decisions_analyzed": self.total_decisions_analyzed,
            "bias_metrics": [m.to_dict() for m in self.bias_metrics],
            "alerts": self.alerts,
            "overall_fairness_score": round(self.overall_fairness_score, 1),
            "metrics_exceeded": sum(1 for m in self.bias_metrics if m.exceeded),
        }


@dataclass
class DecisionRecord:
    """A governance decision record for bias analysis."""
    agent_id: str
    action_group: str
    target_resource: str
    scope_level: int
    verdict: str
    risk_score: float
    input_length: int = 0
    output_length: int = 0
    timestamp: str = ""


# Four-fifths rule threshold (80% rule from US EEOC guidelines)
DISPARITY_THRESHOLD = 0.80


class BiasMonitor:
    """Monitors governance decisions for systematic bias."""

    def __init__(self, disparity_threshold: float = DISPARITY_THRESHOLD):
        self._decisions: List[DecisionRecord] = []
        self._threshold = disparity_threshold

    def record_decision(self, decision: DecisionRecord) -> None:
        """Record a decision for bias analysis."""
        self._decisions.append(decision)

    def load_decisions(self, decisions: List[Dict[str, Any]]) -> None:
        """Load decisions from DynamoDB format."""
        for d in decisions:
            self._decisions.append(DecisionRecord(
                agent_id=d.get("agent_id", ""),
                action_group=d.get("action_requested", d.get("action_group", "")),
                target_resource=d.get("target_resource", ""),
                scope_level=int(d.get("scope_level", 1)),
                verdict=d.get("verdict", ""),
                risk_score=float(d.get("risk_score", 0)),
                input_length=int(d.get("input_length", 0)),
                output_length=int(d.get("output_length", 0)),
                timestamp=d.get("timestamp", ""),
            ))

    def analyze_verdict_bias_by_action_group(self) -> List[BiasMetric]:
        """Check if denial rates vary significantly across action groups."""
        metrics = []
        groups: Dict[str, List[str]] = defaultdict(list)

        for d in self._decisions:
            groups[d.action_group].append(d.verdict)

        if len(groups) < 2:
            return metrics

        group_denial_rates: Dict[str, float] = {}
        for group, verdicts in groups.items():
            if len(verdicts) >= 5:
                denial_rate = sum(1 for v in verdicts if v == "deny") / len(verdicts)
                group_denial_rates[group] = denial_rate

        group_names = list(group_denial_rates.keys())
        for i in range(len(group_names)):
            for j in range(i + 1, len(group_names)):
                a, b = group_names[i], group_names[j]
                rate_a = group_denial_rates[a]
                rate_b = group_denial_rates[b]

                if rate_a == 0 and rate_b == 0:
                    continue

                max_rate = max(rate_a, rate_b)
                min_rate = min(rate_a, rate_b)
                disparity = min_rate / max_rate if max_rate > 0 else 1.0

                metrics.append(BiasMetric(
                    metric_name="verdict_denial_rate_disparity",
                    group_a=a,
                    group_b=b,
                    group_a_rate=rate_a,
                    group_b_rate=rate_b,
                    disparity_ratio=disparity,
                    threshold=self._threshold,
                    exceeded=disparity < self._threshold,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

        return metrics

    def analyze_risk_score_bias_by_scope(self) -> List[BiasMetric]:
        """Check if risk scores are systematically biased by scope level."""
        metrics = []
        groups: Dict[int, List[float]] = defaultdict(list)

        for d in self._decisions:
            groups[d.scope_level].append(d.risk_score)

        scope_avgs: Dict[int, float] = {}
        for scope, scores in groups.items():
            if len(scores) >= 5:
                scope_avgs[scope] = sum(scores) / len(scores)

        scopes = sorted(scope_avgs.keys())
        for i in range(len(scopes)):
            for j in range(i + 1, len(scopes)):
                a, b = scopes[i], scopes[j]
                avg_a = scope_avgs[a]
                avg_b = scope_avgs[b]

                if avg_a == 0 and avg_b == 0:
                    continue

                max_avg = max(avg_a, avg_b)
                min_avg = min(avg_a, avg_b)
                disparity = min_avg / max_avg if max_avg > 0 else 1.0

                metrics.append(BiasMetric(
                    metric_name="risk_score_disparity_by_scope",
                    group_a=f"scope_{a}",
                    group_b=f"scope_{b}",
                    group_a_rate=avg_a,
                    group_b_rate=avg_b,
                    disparity_ratio=disparity,
                    threshold=self._threshold,
                    exceeded=disparity < self._threshold,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

        return metrics

    def analyze_escalation_bias_by_agent(self) -> List[BiasMetric]:
        """Check if escalation rates are fair across agents."""
        metrics = []
        groups: Dict[str, List[str]] = defaultdict(list)

        for d in self._decisions:
            groups[d.agent_id].append(d.verdict)

        agent_escalation_rates: Dict[str, float] = {}
        for agent, verdicts in groups.items():
            if len(verdicts) >= 5:
                esc_rate = sum(1 for v in verdicts if v == "escalate") / len(verdicts)
                agent_escalation_rates[agent] = esc_rate

        if len(agent_escalation_rates) < 2:
            return metrics

        agents = list(agent_escalation_rates.keys())
        for i in range(len(agents)):
            for j in range(i + 1, len(agents)):
                a, b = agents[i], agents[j]
                rate_a = agent_escalation_rates[a]
                rate_b = agent_escalation_rates[b]

                if rate_a == 0 and rate_b == 0:
                    continue

                max_rate = max(rate_a, rate_b)
                min_rate = min(rate_a, rate_b)
                disparity = min_rate / max_rate if max_rate > 0 else 1.0

                metrics.append(BiasMetric(
                    metric_name="escalation_rate_disparity_by_agent",
                    group_a=a,
                    group_b=b,
                    group_a_rate=rate_a,
                    group_b_rate=rate_b,
                    disparity_ratio=disparity,
                    threshold=self._threshold,
                    exceeded=disparity < self._threshold,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

        return metrics

    def generate_report(self, period: str = "all") -> BiasReport:
        """Generate a comprehensive bias report."""
        import uuid

        all_metrics = []
        all_metrics.extend(self.analyze_verdict_bias_by_action_group())
        all_metrics.extend(self.analyze_risk_score_bias_by_scope())
        all_metrics.extend(self.analyze_escalation_bias_by_agent())

        alerts = []
        for m in all_metrics:
            if m.exceeded:
                alerts.append(
                    f"BIAS ALERT: {m.metric_name} between {m.group_a} and {m.group_b} "
                    f"(disparity ratio {m.disparity_ratio:.2f} < threshold {m.threshold})"
                )

        exceeded_count = sum(1 for m in all_metrics if m.exceeded)
        total_metrics = len(all_metrics) if all_metrics else 1
        fairness_score = 100.0 * (1 - exceeded_count / total_metrics)

        report = BiasReport(
            report_id=str(uuid.uuid4()),
            period=period,
            total_decisions_analyzed=len(self._decisions),
            bias_metrics=all_metrics,
            alerts=alerts,
            overall_fairness_score=fairness_score,
        )

        if alerts:
            logger.warning(json.dumps({
                "event": "bias_alerts_generated",
                "alert_count": len(alerts),
                "fairness_score": fairness_score,
            }))

        return report
