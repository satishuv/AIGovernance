"""Compliance Refresh Handler.

Invokes ComplianceMapper.refresh_mappings() to regenerate both ISO 42001
and NIST AI RMF mapping documents in JSON and Markdown formats. Writes
updated documents to the evidence S3 bucket.

Designed to be triggered by a CDK custom resource on stack deployment or
manually via Lambda invocation.

Requirements: 23.4
"""

import json
import logging
import os
from typing import Any, Dict

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point, refresh compliance mapping documents.

    Reads control mappings from the ControlMappingTable, generates
    ISO 42001 and NIST AI RMF compliance mapping documents in both
    JSON and Markdown formats, and writes them to the evidence S3 bucket.

    Environment variables:
        CONTROL_MAPPING_TABLE_NAME: DynamoDB table with control mappings.
        EVIDENCE_BUCKET_NAME: S3 bucket for evidence/compliance storage.
        IMMUTABLE_EVIDENCE_BUCKET_NAME: Optional override for evidence bucket.

    Returns:
        Dict with paths of generated mapping documents.
    """
    control_mapping_table_name = os.environ.get("CONTROL_MAPPING_TABLE_NAME", "")
    evidence_bucket = os.environ.get(
        "IMMUTABLE_EVIDENCE_BUCKET_NAME",
        os.environ.get("EVIDENCE_BUCKET_NAME", ""),
    )

    if not control_mapping_table_name or not evidence_bucket:
        msg = "Missing required environment variables"
        logger.error(json.dumps({
            "event": "compliance_refresh_skipped",
            "reason": msg,
        }))
        return {"status": "skipped", "reason": msg}

    try:
        from compliance_mapper import ComplianceMapper
        from control_mapping import ControlMappingManager
        from evidence_pipeline import EvidencePipeline

        dynamodb = boto3.resource("dynamodb")
        s3_client = boto3.client("s3")

        control_mapping_mgr = ControlMappingManager(
            dynamodb.Table(control_mapping_table_name)
        )
        evidence_pipeline = EvidencePipeline()
        mapper = ComplianceMapper()

        paths = mapper.refresh_mappings(
            control_mapping_table=control_mapping_mgr,
            evidence_pipeline=evidence_pipeline,
            s3_client=s3_client,
            bucket=evidence_bucket,
        )

        logger.info(json.dumps({
            "event": "compliance_refresh_completed",
            "paths": paths,
        }))

        return {"status": "success", "paths": paths}

    except Exception as exc:
        logger.error(json.dumps({
            "event": "compliance_refresh_failed",
            "error": str(exc),
            "error_type": type(exc).__name__,
        }))
        return {"status": "error", "error": str(exc)}
