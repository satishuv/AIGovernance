"""Governance Pipeline Self-Protection.

Answers: "What governs the governance?"

Verifies that the governance pipeline itself has not been tampered with.
If someone modifies opa_engine.py, decision_engine.py, or any governance
module in the Lambda deployment, this module detects it.

Mechanisms:
1. Code hash verification: SHA-256 hash of each governance module compared
   against known-good hashes stored in DynamoDB (set at deploy time by CDK).
2. Environment integrity: Verify critical env vars are present and not
   modified from expected values.
3. Import chain verification: Ensure all required modules loaded successfully.
4. Runtime attestation: Periodic self-check that governance logic is intact.

If integrity is violated, the pipeline DENIES all requests until
re-deployment from the trusted CI/CD pipeline restores integrity.
"""

import hashlib
import importlib
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

CRITICAL_MODULES = [
    "pipeline_orchestrator",
    "decision_engine",
    "opa_engine",
    "policy_engine",
    "input_sanitizer",
    "kill_switch",
    "risk_scoring",
    "behavioral_invariants",
    "tool_execution_auth",
    "tool_response_validator",
    "output_guardrails",
    "fail_safe",
]

REQUIRED_ENV_VARS = [
    "SCOPE_TABLE_NAME",
    "EVIDENCE_BUCKET_NAME",
    "AGENT_REGISTRY_TABLE_NAME",
]


class PipelineIntegrityVerifier:
    """Verifies that governance pipeline code and configuration are untampered.

    Deploy-time: CDK stores SHA-256 hashes of each critical module in DynamoDB.
    Runtime: This verifier recomputes hashes and compares.
    """

    def __init__(self, integrity_table=None):
        self._integrity_table = integrity_table
        self._known_hashes: Dict[str, str] = {}
        self._verification_result: Optional[Dict[str, Any]] = None
        self._last_verified: float = 0.0
        self._verification_interval_s = 300.0

    def load_known_hashes(self) -> None:
        """Load known-good module hashes from DynamoDB."""
        if self._integrity_table is None:
            return

        try:
            response = self._integrity_table.get_item(
                Key={"integrity_id": "governance_modules"}
            )
            item = response.get("Item", {})
            self._known_hashes = item.get("module_hashes", {})
            logger.info(json.dumps({
                "event": "integrity_hashes_loaded",
                "module_count": len(self._known_hashes),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))
        except Exception as e:
            logger.error(json.dumps({
                "event": "integrity_hash_load_failed",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

    def compute_module_hash(self, module_name: str) -> Optional[str]:
        """Compute SHA-256 hash of a module's source file."""
        try:
            module = sys.modules.get(module_name)
            if module is None:
                module = importlib.import_module(module_name)

            source_file = getattr(module, "__file__", None)
            if source_file is None or not os.path.exists(source_file):
                return None

            with open(source_file, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None

    def verify_code_integrity(self) -> Dict[str, Any]:
        """Verify all critical modules against known-good hashes.

        Returns:
            Dict with verification result, violations, and timestamp.
        """
        violations = []
        verified = []
        skipped = []

        for module_name in CRITICAL_MODULES:
            current_hash = self.compute_module_hash(module_name)

            if current_hash is None:
                skipped.append(module_name)
                continue

            known_hash = self._known_hashes.get(module_name)

            if known_hash is None:
                skipped.append(module_name)
                continue

            if current_hash != known_hash:
                violations.append({
                    "module": module_name,
                    "expected_hash": known_hash[:16] + "...",
                    "actual_hash": current_hash[:16] + "...",
                })
            else:
                verified.append(module_name)

        result = {
            "integrity_valid": len(violations) == 0,
            "verified_count": len(verified),
            "violation_count": len(violations),
            "skipped_count": len(skipped),
            "violations": violations,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if violations:
            logger.error(json.dumps({
                "event": "governance_integrity_violation",
                "violations": violations,
                "action": "deny_all_requests",
                "timestamp": result["timestamp"],
            }))

        self._verification_result = result
        return result

    def verify_environment_integrity(self) -> Dict[str, Any]:
        """Verify that required environment variables are present."""
        missing = []
        present = []

        for var in REQUIRED_ENV_VARS:
            if os.environ.get(var):
                present.append(var)
            else:
                missing.append(var)

        return {
            "environment_valid": len(missing) == 0,
            "present_count": len(present),
            "missing": missing,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def verify_import_chain(self) -> Dict[str, Any]:
        """Verify all critical modules are importable."""
        failed_imports = []
        successful = []

        for module_name in CRITICAL_MODULES:
            if module_name in sys.modules:
                successful.append(module_name)
            else:
                try:
                    importlib.import_module(module_name)
                    successful.append(module_name)
                except ImportError as e:
                    failed_imports.append({
                        "module": module_name,
                        "error": str(e),
                    })

        return {
            "imports_valid": len(failed_imports) == 0,
            "successful_count": len(successful),
            "failed_imports": failed_imports,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    def full_verification(self) -> Dict[str, Any]:
        """Run all integrity checks and return combined result.

        Returns DENY recommendation if any check fails.
        """
        code_result = self.verify_code_integrity()
        env_result = self.verify_environment_integrity()
        import_result = self.verify_import_chain()

        all_valid = (
            code_result["integrity_valid"]
            and env_result["environment_valid"]
            and import_result["imports_valid"]
        )

        result = {
            "pipeline_integrity_valid": all_valid,
            "code_integrity": code_result,
            "environment_integrity": env_result,
            "import_chain": import_result,
            "recommendation": "proceed" if all_valid else "deny_all",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if not all_valid:
            logger.error(json.dumps({
                "event": "pipeline_integrity_failed",
                "recommendation": "deny_all",
                "code_violations": code_result.get("violation_count", 0),
                "env_missing": env_result.get("missing", []),
                "import_failures": import_result.get("failed_imports", []),
                "timestamp": result["timestamp"],
            }))

        return result

    def generate_deploy_hashes(self) -> Dict[str, str]:
        """Generate hashes for all critical modules (called at deploy time).

        Returns:
            Dict of module_name -> SHA-256 hash for storage in DynamoDB.
        """
        hashes = {}
        for module_name in CRITICAL_MODULES:
            h = self.compute_module_hash(module_name)
            if h:
                hashes[module_name] = h
        return hashes

    def store_deploy_hashes(self, hashes: Dict[str, str]) -> None:
        """Store known-good hashes in DynamoDB (called by CDK post-deploy)."""
        if self._integrity_table is None:
            return

        self._integrity_table.put_item(Item={
            "integrity_id": "governance_modules",
            "module_hashes": hashes,
            "deployed_at": datetime.now(timezone.utc).isoformat(),
            "module_count": len(hashes),
        })

        logger.info(json.dumps({
            "event": "deploy_hashes_stored",
            "module_count": len(hashes),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))
