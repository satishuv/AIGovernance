"""Environment Isolation module.

Provides pure-logic utilities for validating deployment environments,
detecting cross-environment violations, scoping policy evaluation by
environment, and generating environment-partitioned S3 evidence prefixes.

No DynamoDB dependency — this is a stateless logic module.

Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.6
"""

import json
import logging
from datetime import date, datetime, timezone
from typing import Dict

logger = logging.getLogger(__name__)

VALID_ENVIRONMENTS = {"dev", "staging", "prod"}


class EnvironmentIsolation:
    """Stateless utilities for environment-scoped governance."""

    def validate_environment(self, environment: str) -> bool:
        """Check whether an environment value is valid.

        Args:
            environment: The environment string to validate.

        Returns:
            True if environment is one of "dev", "staging", or "prod";
            False otherwise.
        """
        return environment in VALID_ENVIRONMENTS

    def check_cross_environment(
        self, requesting_agent_env: str, target_env: str
    ) -> bool:
        """Check whether a cross-environment access is allowed.

        Access is allowed only when both environments match. A mismatch
        is logged as a structured cross-environment violation record.

        Args:
            requesting_agent_env: The requesting agent's declared environment.
            target_env: The target resource's environment.

        Returns:
            True if environments match, False otherwise.
        """
        if requesting_agent_env == target_env:
            return True

        now = datetime.now(timezone.utc).isoformat()
        logger.warning(
            json.dumps(
                {
                    "audit_event": "cross_environment_violation",
                    "requesting_agent_env": requesting_agent_env,
                    "target_env": target_env,
                    "timestamp": now,
                }
            )
        )
        return False

    def get_environment_policy_filter(
        self, environment: str
    ) -> Dict[str, str]:
        """Return a filter dict that scopes policy evaluation to an environment.

        Args:
            environment: The environment to scope policies to.

        Returns:
            A dictionary suitable for filtering policies by environment.
        """
        return {"environment": environment}

    def get_environment_evidence_prefix(
        self, environment: str, agent_id: str, evidence_date: date
    ) -> str:
        """Return an S3 key prefix partitioned by environment, agent, and date.

        The prefix follows the pattern:
        ``evidence/{environment}/{agent_id}/YYYY/MM/DD/``

        Args:
            environment: Deployment environment.
            agent_id: The agent's unique identifier.
            evidence_date: The date for partitioning.

        Returns:
            S3 key prefix string.
        """
        return (
            f"evidence/{environment}/{agent_id}/"
            f"{evidence_date.strftime('%Y/%m/%d')}/"
        )
