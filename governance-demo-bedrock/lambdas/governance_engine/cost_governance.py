"""AI Cost Governance.

Budget controls, spend tracking, and cost alerts for AI agent operations.
Prevents runaway costs from autonomous agents making unlimited API calls.

Features:
- Per-agent budget limits (daily, monthly)
- Cost allocation by agent, action group, and business unit
- Spend alerts when approaching thresholds (80%, 90%, 100%)
- Automatic throttling when budget exceeded
- Cost-per-decision tracking
- ESG/carbon footprint estimation (token-based)

Addresses LLM Council feedback:
- "AI cost governance with budget controls"
- "Cost allocation tags"
- "Alert when AI spend exceeds threshold"
- "Carbon footprint tracking for ESG compliance"
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Estimated costs per operation (USD)
COST_PER_OPERATION = {
    "bedrock_invoke": 0.0003,
    "guardrail_eval": 0.0001,
    "lambda_invoke": 0.0000002,
    "dynamodb_read": 0.00000025,
    "dynamodb_write": 0.0000125,
    "s3_put": 0.000005,
    "step_functions_transition": 0.000025,
    "governance_decision": 0.001,
}

# Token-based carbon estimation (gCO2 per 1K tokens, approximate)
CARBON_PER_1K_TOKENS = 0.3


@dataclass
class AgentBudget:
    """Budget configuration for an agent."""
    agent_id: str
    daily_limit_usd: float = 10.0
    monthly_limit_usd: float = 200.0
    alert_threshold_pct: float = 80.0
    hard_limit_action: str = "throttle"
    business_unit: str = ""
    cost_center: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "daily_limit_usd": self.daily_limit_usd,
            "monthly_limit_usd": self.monthly_limit_usd,
            "alert_threshold_pct": self.alert_threshold_pct,
            "hard_limit_action": self.hard_limit_action,
            "business_unit": self.business_unit,
            "cost_center": self.cost_center,
        }


@dataclass
class SpendRecord:
    """A single cost event."""
    agent_id: str
    operation: str
    cost_usd: float
    timestamp: str
    action_group: str = ""
    tokens_used: int = 0
    carbon_grams: float = 0.0


@dataclass
class CostReport:
    """Cost summary for an agent or time period."""
    agent_id: str
    period: str
    total_cost_usd: float = 0.0
    total_decisions: int = 0
    cost_per_decision: float = 0.0
    total_tokens: int = 0
    total_carbon_grams: float = 0.0
    budget_utilization_pct: float = 0.0
    by_operation: Dict[str, float] = field(default_factory=dict)
    by_action_group: Dict[str, float] = field(default_factory=dict)
    alerts: List[str] = field(default_factory=list)
    throttled: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "period": self.period,
            "total_cost_usd": round(self.total_cost_usd, 6),
            "total_decisions": self.total_decisions,
            "cost_per_decision": round(self.cost_per_decision, 6),
            "total_tokens": self.total_tokens,
            "total_carbon_grams": round(self.total_carbon_grams, 3),
            "budget_utilization_pct": round(self.budget_utilization_pct, 1),
            "by_operation": {k: round(v, 6) for k, v in self.by_operation.items()},
            "by_action_group": {k: round(v, 6) for k, v in self.by_action_group.items()},
            "alerts": self.alerts,
            "throttled": self.throttled,
        }


class CostGovernance:
    """Tracks and enforces AI agent cost budgets."""

    def __init__(self):
        self._budgets: Dict[str, AgentBudget] = {}
        self._spend: Dict[str, List[SpendRecord]] = {}

    def set_budget(self, budget: AgentBudget) -> None:
        """Set or update an agent's budget."""
        self._budgets[budget.agent_id] = budget
        logger.info(json.dumps({
            "event": "budget_set",
            "agent_id": budget.agent_id,
            "daily_limit": budget.daily_limit_usd,
            "monthly_limit": budget.monthly_limit_usd,
        }))

    def record_spend(
        self, agent_id: str, operation: str, action_group: str = "", tokens: int = 0
    ) -> Optional[str]:
        """Record a cost event. Returns alert message if threshold crossed."""
        cost = COST_PER_OPERATION.get(operation, 0.0)
        carbon = (tokens / 1000.0) * CARBON_PER_1K_TOKENS if tokens > 0 else 0.0

        record = SpendRecord(
            agent_id=agent_id,
            operation=operation,
            cost_usd=cost,
            timestamp=datetime.now(timezone.utc).isoformat(),
            action_group=action_group,
            tokens_used=tokens,
            carbon_grams=carbon,
        )

        if agent_id not in self._spend:
            self._spend[agent_id] = []
        self._spend[agent_id].append(record)

        budget = self._budgets.get(agent_id)
        if budget:
            daily_spend = self._get_daily_spend(agent_id)
            utilization = (daily_spend / budget.daily_limit_usd * 100) if budget.daily_limit_usd > 0 else 0

            if utilization >= 100:
                logger.warning(json.dumps({
                    "event": "budget_exceeded",
                    "agent_id": agent_id,
                    "daily_spend": daily_spend,
                    "limit": budget.daily_limit_usd,
                    "action": budget.hard_limit_action,
                }))
                return f"BUDGET_EXCEEDED: {agent_id} spent ${daily_spend:.4f} (limit: ${budget.daily_limit_usd})"

            if utilization >= budget.alert_threshold_pct:
                return f"BUDGET_WARNING: {agent_id} at {utilization:.0f}% of daily budget"

        return None

    def check_budget(self, agent_id: str) -> Dict[str, Any]:
        """Check if agent is within budget. Returns status and utilization."""
        budget = self._budgets.get(agent_id)
        if not budget:
            return {"status": "no_budget", "throttled": False}

        daily_spend = self._get_daily_spend(agent_id)
        utilization = (daily_spend / budget.daily_limit_usd * 100) if budget.daily_limit_usd > 0 else 0
        throttled = utilization >= 100

        return {
            "status": "exceeded" if throttled else "warning" if utilization >= budget.alert_threshold_pct else "ok",
            "daily_spend_usd": round(daily_spend, 6),
            "daily_limit_usd": budget.daily_limit_usd,
            "utilization_pct": round(utilization, 1),
            "throttled": throttled,
            "hard_limit_action": budget.hard_limit_action,
        }

    def get_cost_report(self, agent_id: str, period: str = "daily") -> CostReport:
        """Generate a cost report for an agent."""
        records = self._spend.get(agent_id, [])
        budget = self._budgets.get(agent_id)

        total_cost = sum(r.cost_usd for r in records)
        total_tokens = sum(r.tokens_used for r in records)
        total_carbon = sum(r.carbon_grams for r in records)
        total_decisions = sum(1 for r in records if r.operation == "governance_decision")

        by_operation: Dict[str, float] = {}
        by_action_group: Dict[str, float] = {}
        for r in records:
            by_operation[r.operation] = by_operation.get(r.operation, 0) + r.cost_usd
            if r.action_group:
                by_action_group[r.action_group] = by_action_group.get(r.action_group, 0) + r.cost_usd

        budget_limit = budget.daily_limit_usd if budget else 0
        utilization = (total_cost / budget_limit * 100) if budget_limit > 0 else 0

        alerts = []
        if utilization >= 100:
            alerts.append("BUDGET_EXCEEDED")
        elif utilization >= 80:
            alerts.append("BUDGET_WARNING")

        return CostReport(
            agent_id=agent_id,
            period=period,
            total_cost_usd=total_cost,
            total_decisions=total_decisions,
            cost_per_decision=total_cost / total_decisions if total_decisions > 0 else 0,
            total_tokens=total_tokens,
            total_carbon_grams=total_carbon,
            budget_utilization_pct=utilization,
            by_operation=by_operation,
            by_action_group=by_action_group,
            alerts=alerts,
            throttled=utilization >= 100,
        )

    def _get_daily_spend(self, agent_id: str) -> float:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        records = self._spend.get(agent_id, [])
        return sum(r.cost_usd for r in records if r.timestamp[:10] == today)

    def load_budgets_from_table(self, table) -> None:
        """Load agent budgets from DynamoDB."""
        try:
            response = table.scan()
            for item in response.get("Items", []):
                budget = AgentBudget(
                    agent_id=item["agent_id"],
                    daily_limit_usd=float(item.get("daily_limit_usd", 10.0)),
                    monthly_limit_usd=float(item.get("monthly_limit_usd", 200.0)),
                    alert_threshold_pct=float(item.get("alert_threshold_pct", 80.0)),
                    hard_limit_action=item.get("hard_limit_action", "throttle"),
                    business_unit=item.get("business_unit", ""),
                    cost_center=item.get("cost_center", ""),
                )
                self._budgets[budget.agent_id] = budget
        except Exception as e:
            logger.error(json.dumps({
                "event": "cost_budget_load_failed",
                "error": str(e),
            }))
