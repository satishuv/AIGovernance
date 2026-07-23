"""Evidence Pipeline module.

Writes structured evidence records to S3 with SHA-256 hashing, hash chain
continuity, date/agent-based partitioning, retry logic, and retention class
assignment. Generates Control_Trace objects for framework mapping.

Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 15.2, 15.3, 15.4
"""

import base64
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models import ControlTrace, EvidenceRecord, GovernanceDecision

logger = logging.getLogger(__name__)

MAX_RETRIES = 3
INITIAL_BACKOFF_SECONDS = 0.5

# Fields excluded from the SHA-256 record hash: the hash cannot cover itself,
# and the signature is computed over the hash so it cannot be an input to it.
_HASH_EXCLUDED_FIELDS = ("record_hash", "signature", "signing_key_id", "signing_algorithm")

# AARM R5/R6: KMS asymmetric signing of the record hash. Key id from env; when
# unset (e.g. local tests) signing is skipped and the hash chain still applies.
EVIDENCE_SIGNING_KEY_ID = os.environ.get("EVIDENCE_SIGNING_KEY_ID", "")
SIGNING_ALGORITHM = "ECDSA_SHA_256"


class EvidencePipeline:
    """Manages evidence record creation, hashing, and S3 storage."""

    def write_evidence(
        self,
        decision: GovernanceDecision,
        s3_client,
        bucket: str,
        environment: str,
        agent_id: str,
        kms_client=None,
        session_id: str = "",
        agent_role: str = "",
        scope_level: int = 0,
        policy_version_hash: str = "",
    ) -> Optional[EvidenceRecord]:
        """Create and store an evidence record from a governance decision.

        Args:
            decision: The GovernanceDecision to record as evidence.
            s3_client: boto3 S3 client.
            bucket: S3 bucket name for evidence storage.
            environment: Deployment environment (dev/staging/prod).
            agent_id: The agent's unique identifier.
            kms_client: Optional boto3 KMS client for AARM R5/R6 signing. When
                provided and a signing key is configured, the record hash is
                signed (offline-verifiable, non-repudiable). Signing failures
                are logged and do not block evidence writing.
            session_id: Session id (AARM R6 identity binding).
            agent_role: Agent role/privilege scope (AARM R6).
            scope_level: Scope level at decision time (AARM R6).
            policy_version_hash: Version/hash of the policy used (AARM R5).

        Returns:
            The created EvidenceRecord, or None if all retries fail.
        """
        now = datetime.now(timezone.utc)
        evidence_id = str(uuid.uuid4())

        risk_category = getattr(decision, "risk_category", "data_access")
        retention_class = self._assign_retention_class(risk_category)

        previous_hash = self._get_previous_hash(
            s3_client, bucket, environment, agent_id
        )

        record = EvidenceRecord(
            evidence_id=evidence_id,
            decision_id=decision.decision_id,
            agent_id=agent_id,
            action_requested=decision.action_requested,
            policy_result=(
                decision.policy_result.outcome
                if hasattr(decision.policy_result, "outcome")
                else str(decision.policy_result)
            ),
            risk_score=decision.risk_score,
            verdict=decision.verdict,
            timestamp=now.isoformat(),
            framework_mapping=list(decision.framework_mapping)
            if decision.framework_mapping
            else [],
            environment=environment,
            previous_hash=previous_hash,
            record_hash="",
            retention_class=retention_class,
            session_id=session_id,
            agent_role=agent_role,
            scope_level=scope_level,
            policy_version_hash=policy_version_hash,
        )

        # Compute hash over all content fields except the hash and signature
        # fields (the hash cannot cover itself; the signature is derived from it).
        record_dict = record.to_dict()
        for f in _HASH_EXCLUDED_FIELDS:
            record_dict.pop(f, None)
        record.record_hash = self._compute_hash(record_dict)

        # AARM R5/R6: sign the record hash with a KMS asymmetric key so the
        # receipt is offline-verifiable and cryptographically bound to origin.
        self._sign_record(record, kms_client)

        record_dict = record.to_dict()

        # Build S3 key
        s3_key = (
            f"evidence/{environment}/{agent_id}/"
            f"{now.strftime('%Y/%m/%d')}/{evidence_id}.json"
        )

        # Write with retry and exponential backoff
        body = json.dumps(record.to_dict(), default=str)
        last_error = None
        for attempt in range(MAX_RETRIES):
            try:
                s3_client.put_object(
                    Bucket=bucket,
                    Key=s3_key,
                    Body=body,
                    ContentType="application/json",
                    Metadata={"record_hash": record.record_hash},
                )
                logger.info(
                    json.dumps(
                        {
                            "audit_event": "evidence_written",
                            "evidence_id": evidence_id,
                            "decision_id": decision.decision_id,
                            "s3_key": s3_key,
                            "timestamp": now.isoformat(),
                        }
                    )
                )
                return record
            except Exception as exc:
                last_error = exc
                backoff = INITIAL_BACKOFF_SECONDS * (2 ** attempt)
                logger.warning(
                    json.dumps(
                        {
                            "audit_event": "evidence_write_retry",
                            "evidence_id": evidence_id,
                            "attempt": attempt + 1,
                            "backoff_seconds": backoff,
                            "error": str(exc),
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        }
                    )
                )
                time.sleep(backoff)

        logger.error(
            json.dumps(
                {
                    "audit_event": "evidence_write_failed",
                    "evidence_id": evidence_id,
                    "decision_id": decision.decision_id,
                    "retries_exhausted": MAX_RETRIES,
                    "error": str(last_error),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        )
        # Phase 3: publish evidence failure metric (Req 25.1)
        try:
            import boto3 as _boto3
            from cloudwatch_metrics import CloudWatchMetricsPublisher
            _cw = _boto3.client("cloudwatch")
            CloudWatchMetricsPublisher().publish_evidence_failure_metric(_cw)
        except Exception:
            pass
        return None

    @staticmethod
    def _compute_hash(record_dict: Dict[str, Any]) -> str:
        """Compute SHA-256 hash of a JSON-serialized evidence record.

        Args:
            record_dict: Dictionary representation of the evidence record.

        Returns:
            Hex-encoded SHA-256 hash string.
        """
        canonical = json.dumps(record_dict, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def _sign_record(record: EvidenceRecord, kms_client) -> None:
        """Sign the record hash with a KMS asymmetric key (AARM R5/R6).

        Signs the SHA-256 digest (MessageType=DIGEST) so the receipt carries an
        offline-verifiable, non-repudiable signature bound to the signing key.
        No-op when no KMS client or signing key is configured (e.g. local
        tests); the hash chain still provides tamper-evidence in that case.
        Signing failures are logged and never block evidence writing.
        """
        if kms_client is None or not EVIDENCE_SIGNING_KEY_ID:
            return
        try:
            digest = bytes.fromhex(record.record_hash)
            resp = kms_client.sign(
                KeyId=EVIDENCE_SIGNING_KEY_ID,
                Message=digest,
                MessageType="DIGEST",
                SigningAlgorithm=SIGNING_ALGORITHM,
            )
            record.signature = base64.b64encode(resp["Signature"]).decode("ascii")
            record.signing_key_id = EVIDENCE_SIGNING_KEY_ID
            record.signing_algorithm = SIGNING_ALGORITHM
        except Exception as exc:
            logger.error(json.dumps({
                "audit_event": "evidence_signing_failed",
                "evidence_id": record.evidence_id,
                "error": str(exc),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }))

    @staticmethod
    def _get_previous_hash(
        s3_client, bucket: str, environment: str, agent_id: str
    ) -> str:
        """Retrieve the hash of the most recent evidence record for hash chain.

        Args:
            s3_client: boto3 S3 client.
            bucket: S3 bucket name.
            environment: Deployment environment.
            agent_id: The agent's unique identifier.

        Returns:
            The previous record hash, or empty string if none exists.
        """
        prefix = f"evidence/{environment}/{agent_id}/"
        try:
            response = s3_client.list_objects_v2(
                Bucket=bucket, Prefix=prefix, MaxKeys=1000
            )
            contents = response.get("Contents", [])
            if not contents:
                return ""
            # Sort by LastModified descending to get most recent
            contents.sort(key=lambda x: x.get("LastModified", ""), reverse=True)
            latest_key = contents[0]["Key"]
            obj = s3_client.get_object(Bucket=bucket, Key=latest_key)
            body = json.loads(obj["Body"].read().decode("utf-8"))
            return body.get("record_hash", "")
        except Exception as exc:
            logger.warning(
                json.dumps(
                    {
                        "audit_event": "previous_hash_retrieval_failed",
                        "environment": environment,
                        "agent_id": agent_id,
                        "error": str(exc),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            )
            return ""

    @staticmethod
    def _assign_retention_class(risk_category: str) -> str:
        """Assign retention class based on risk category.

        Args:
            risk_category: The risk category of the action.

        Returns:
            "extended" for emergency_action and deployment categories,
            "standard" for all others.
        """
        if risk_category in ("emergency_action", "deployment"):
            return "extended"
        return "standard"

    @staticmethod
    def generate_control_traces(
        evidence_record: EvidenceRecord,
        framework_mapping: List[str],
    ) -> List[ControlTrace]:
        """Create one ControlTrace per control ID in the framework mapping.

        Args:
            evidence_record: The evidence record to link traces to.
            framework_mapping: List of control IDs (ISO 42001 / NIST AI RMF).

        Returns:
            List of ControlTrace objects.
        """
        now = datetime.now(timezone.utc).isoformat()
        traces = []
        for control_id in framework_mapping:
            trace = ControlTrace(
                control_id=control_id,
                implementation_component="GovernanceEngine",
                evidence_record_id=evidence_record.evidence_id,
                decision_id=evidence_record.decision_id,
                timestamp=now,
            )
            traces.append(trace)
        return traces
