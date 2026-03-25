"""Evidence Integrity and Immutability module.

Provides SHA-256 verification of individual evidence records, hash chain
verification across date ranges, and retention configuration. Integrity
violations are logged and optionally published to an operator SNS topic.

Requirements: 15.1, 15.2, 15.3, 15.5, 15.6
"""

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

RETENTION_DAYS = {"standard": 365, "extended": 2555}


class EvidenceIntegrity:
    """Verifies evidence record integrity and hash chain continuity."""

    def __init__(self, sns_client=None, sns_topic_arn: str = "") -> None:
        self._sns_client = sns_client
        self._sns_topic_arn = sns_topic_arn

    def verify_record_integrity(
        self,
        evidence_id: str,
        s3_client,
        bucket: str,
        s3_key: str,
    ) -> bool:
        """Verify a single evidence record's SHA-256 hash integrity.

        Retrieves the record from S3, recomputes its hash, and compares
        against the stored record_hash. Logs and alerts on mismatch.

        Args:
            evidence_id: The evidence record identifier.
            s3_client: boto3 S3 client.
            bucket: S3 bucket name.
            s3_key: S3 key of the evidence record.

        Returns:
            True if hashes match, False on mismatch.
        """
        obj = s3_client.get_object(Bucket=bucket, Key=s3_key)
        body = json.loads(obj["Body"].read().decode("utf-8"))

        stored_hash = body.get("record_hash", "")

        # Recompute hash excluding the record_hash field
        verify_dict = {k: v for k, v in body.items() if k != "record_hash"}
        canonical = json.dumps(verify_dict, sort_keys=True, default=str)
        computed_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

        if computed_hash == stored_hash:
            return True

        now = datetime.utcnow().isoformat()
        violation = {
            "audit_event": "evidence_integrity_violation",
            "evidence_id": evidence_id,
            "s3_key": s3_key,
            "stored_hash": stored_hash,
            "computed_hash": computed_hash,
            "timestamp": now,
        }
        logger.error(json.dumps(violation))

        self._publish_alert(
            f"Evidence integrity violation for {evidence_id}: "
            f"stored_hash={stored_hash}, computed_hash={computed_hash}"
        )
        return False

    def verify_hash_chain(
        self,
        s3_client,
        bucket: str,
        environment: str,
        agent_id: str,
        start_date: str,
        end_date: str,
    ) -> List[Dict[str, Any]]:
        """Verify hash chain continuity for an agent's evidence records.

        Retrieves all evidence records in the date range, orders them by
        timestamp, and verifies each record's previous_hash matches the
        hash of the preceding record.

        Args:
            s3_client: boto3 S3 client.
            bucket: S3 bucket name.
            environment: Deployment environment.
            agent_id: The agent's unique identifier.
            start_date: Start date (YYYY-MM-DD).
            end_date: End date (YYYY-MM-DD).

        Returns:
            List of verification result dicts, one per record.
        """
        prefix = f"evidence/{environment}/{agent_id}/"
        response = s3_client.list_objects_v2(
            Bucket=bucket, Prefix=prefix, MaxKeys=1000
        )
        all_keys = [obj["Key"] for obj in response.get("Contents", [])]
        while response.get("IsTruncated"):
            response = s3_client.list_objects_v2(
                Bucket=bucket,
                Prefix=prefix,
                MaxKeys=1000,
                ContinuationToken=response["NextContinuationToken"],
            )
            all_keys.extend(obj["Key"] for obj in response.get("Contents", []))

        # Filter keys by date range and load records
        records = []
        for key in all_keys:
            parts = key.split("/")
            if len(parts) >= 6:
                date_str = f"{parts[3]}-{parts[4]}-{parts[5]}"
                if start_date <= date_str <= end_date:
                    obj = s3_client.get_object(Bucket=bucket, Key=key)
                    body = json.loads(obj["Body"].read().decode("utf-8"))
                    body["_s3_key"] = key
                    records.append(body)

        # Sort by timestamp for chain verification
        records.sort(key=lambda r: r.get("timestamp", ""))

        results: List[Dict[str, Any]] = []
        previous_hash = ""

        for record in records:
            evidence_id = record.get("evidence_id", "")
            record_previous_hash = record.get("previous_hash", "")
            record_hash = record.get("record_hash", "")

            chain_valid = True
            if previous_hash and record_previous_hash != previous_hash:
                chain_valid = False
                now = datetime.utcnow().isoformat()
                violation = {
                    "audit_event": "hash_chain_violation",
                    "evidence_id": evidence_id,
                    "expected_previous_hash": previous_hash,
                    "actual_previous_hash": record_previous_hash,
                    "timestamp": now,
                }
                logger.error(json.dumps(violation))
                self._publish_alert(
                    f"Hash chain violation for {evidence_id}: "
                    f"expected={previous_hash}, actual={record_previous_hash}"
                )

            results.append({
                "evidence_id": evidence_id,
                "chain_valid": chain_valid,
                "record_hash": record_hash,
            })
            previous_hash = record_hash

        return results

    @staticmethod
    def get_retention_config(retention_class: str) -> int:
        """Return retention period in days for a retention class.

        Args:
            retention_class: "standard" or "extended".

        Returns:
            Retention period in days (365 or 2555).
        """
        return RETENTION_DAYS.get(retention_class, 365)

    def _publish_alert(self, message: str) -> None:
        """Publish an integrity alert to the operator SNS topic."""
        if self._sns_client and self._sns_topic_arn:
            try:
                self._sns_client.publish(
                    TopicArn=self._sns_topic_arn,
                    Subject="Evidence Integrity Alert",
                    Message=message,
                )
            except Exception as exc:
                logger.error(
                    json.dumps({
                        "audit_event": "sns_alert_failed",
                        "error": str(exc),
                        "timestamp": datetime.utcnow().isoformat(),
                    })
                )
