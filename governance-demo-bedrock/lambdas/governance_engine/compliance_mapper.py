"""ISO 42001 and NIST AI RMF Compliance Mapper module.

Generates compliance mapping documents for ISO 42001 Annex A controls and
NIST AI RMF GOVERN/MAP/MEASURE functions. Supports export to JSON and
Markdown formats, and bulk refresh to S3.

Requirements: 23.1, 23.2, 23.3, 23.4
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models import ComplianceMappingEntry

logger = logging.getLogger(__name__)

# ISO 42001 Annex A controls relevant to AI governance
_ISO_42001_CONTROLS = [
    {"control_id": "A.2", "control_name": "AI Policy"},
    {"control_id": "A.3", "control_name": "Internal Organization"},
    {"control_id": "A.4", "control_name": "Resources for AI"},
    {"control_id": "A.5", "control_name": "Assessing AI Impacts"},
    {"control_id": "A.6", "control_name": "AI System Lifecycle"},
    {"control_id": "A.7", "control_name": "AI System Support"},
    {"control_id": "A.8", "control_name": "Data for AI"},
    {"control_id": "A.9", "control_name": "AI System Performance"},
    {"control_id": "A.10", "control_name": "Third-party and Customer Relationships"},
]

# NIST AI RMF functions, categories, and subcategories
_NIST_AI_RMF_ENTRIES = [
    {"function_name": "GOVERN", "category": "GOVERN 1", "subcategory": "Policies, Processes, Procedures, and Practices"},
    {"function_name": "GOVERN", "category": "GOVERN 2", "subcategory": "Accountability"},
    {"function_name": "GOVERN", "category": "GOVERN 3", "subcategory": "Workforce Diversity"},
    {"function_name": "GOVERN", "category": "GOVERN 4", "subcategory": "Organizational Practices"},
    {"function_name": "GOVERN", "category": "GOVERN 5", "subcategory": "Processes for Engagement"},
    {"function_name": "GOVERN", "category": "GOVERN 6", "subcategory": "Policies and Procedures for Trustworthy AI"},
    {"function_name": "MAP", "category": "MAP 1", "subcategory": "Context and Use Cases"},
    {"function_name": "MAP", "category": "MAP 2", "subcategory": "Categorization"},
    {"function_name": "MAP", "category": "MAP 3", "subcategory": "Benefits and Costs"},
    {"function_name": "MAP", "category": "MAP 4", "subcategory": "Risks and Impacts"},
    {"function_name": "MAP", "category": "MAP 5", "subcategory": "Likelihood and Severity"},
    {"function_name": "MEASURE", "category": "MEASURE 1", "subcategory": "Metrics and Methodologies"},
    {"function_name": "MEASURE", "category": "MEASURE 2", "subcategory": "Evaluation and Tracking"},
    {"function_name": "MEASURE", "category": "MEASURE 3", "subcategory": "Continuous Improvement"},
    {"function_name": "MEASURE", "category": "MEASURE 4", "subcategory": "Feedback and Communication"},
]


class ComplianceMapper:
    """Generates and exports compliance mapping documents."""

    def generate_iso42001_mapping(
        self,
        control_mapping_table,
        evidence_pipeline=None,
    ) -> List[ComplianceMappingEntry]:
        """Generate ISO 42001 Annex A compliance mapping.

        Args:
            control_mapping_table: ControlMappingManager instance with loaded mappings.
            evidence_pipeline: Optional EvidencePipeline for evidence lookup.

        Returns:
            List of ComplianceMappingEntry objects for ISO 42001 controls.
        """
        entries = []
        mapping_table = control_mapping_table.get_mapping_table()
        mapping_by_control = {}
        for m in mapping_table:
            cid = m.get("control_id", "")
            if cid not in mapping_by_control:
                mapping_by_control[cid] = []
            mapping_by_control[cid].append(m)

        for control in _ISO_42001_CONTROLS:
            cid = control["control_id"]
            cname = control["control_name"]
            matched = mapping_by_control.get(cid, [])

            if matched:
                for m in matched:
                    entry = ComplianceMappingEntry(
                        control_id=cid,
                        control_name=cname,
                        framework="iso_42001",
                        implementation_component=m.get("implementation_component", ""),
                        evidence_generated=m.get("evidence_generated", ""),
                        compliance_status="implemented",
                    )
                    entries.append(entry)
            else:
                entry = ComplianceMappingEntry(
                    control_id=cid,
                    control_name=cname,
                    framework="iso_42001",
                    implementation_component="",
                    evidence_generated="",
                    compliance_status="planned",
                )
                entries.append(entry)

        logger.info(
            json.dumps(
                {
                    "audit_event": "iso42001_mapping_generated",
                    "entry_count": len(entries),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        )

        return entries

    def generate_nist_ai_rmf_mapping(
        self,
        control_mapping_table,
        evidence_pipeline=None,
    ) -> List[ComplianceMappingEntry]:
        """Generate NIST AI RMF compliance mapping.

        Covers GOVERN, MAP, and MEASURE functions.

        Args:
            control_mapping_table: ControlMappingManager instance with loaded mappings.
            evidence_pipeline: Optional EvidencePipeline for evidence lookup.

        Returns:
            List of ComplianceMappingEntry objects for NIST AI RMF entries.
        """
        entries = []
        mapping_table = control_mapping_table.get_mapping_table()
        mapping_by_control = {}
        for m in mapping_table:
            cid = m.get("control_id", "")
            if cid not in mapping_by_control:
                mapping_by_control[cid] = []
            mapping_by_control[cid].append(m)

        for nist_entry in _NIST_AI_RMF_ENTRIES:
            category = nist_entry["category"]
            matched = mapping_by_control.get(category, [])

            if matched:
                for m in matched:
                    entry = ComplianceMappingEntry(
                        control_id=category,
                        control_name=nist_entry["subcategory"],
                        framework="nist_ai_rmf",
                        function_name=nist_entry["function_name"],
                        category=category,
                        subcategory=nist_entry["subcategory"],
                        implementation_component=m.get("implementation_component", ""),
                        evidence_generated=m.get("evidence_generated", ""),
                        compliance_status="implemented",
                    )
                    entries.append(entry)
            else:
                entry = ComplianceMappingEntry(
                    control_id=category,
                    control_name=nist_entry["subcategory"],
                    framework="nist_ai_rmf",
                    function_name=nist_entry["function_name"],
                    category=category,
                    subcategory=nist_entry["subcategory"],
                    implementation_component="",
                    evidence_generated="",
                    compliance_status="planned",
                )
                entries.append(entry)

        logger.info(
            json.dumps(
                {
                    "audit_event": "nist_ai_rmf_mapping_generated",
                    "entry_count": len(entries),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        )

        return entries

    @staticmethod
    def export_json(
        entries: List[ComplianceMappingEntry],
        output_path: str,
        s3_client=None,
        bucket: str = "",
    ) -> str:
        """Export mapping entries as a JSON array.

        If s3_client and bucket are provided, writes to S3. Otherwise writes
        to a local file path.

        Args:
            entries: List of ComplianceMappingEntry objects to export.
            output_path: S3 key or local file path.
            s3_client: Optional boto3 S3 client for S3 writes.
            bucket: S3 bucket name (required if s3_client is provided).

        Returns:
            The output path where the JSON was written.
        """
        data = [entry.to_dict() for entry in entries]
        body = json.dumps(data, indent=2, default=str)

        if s3_client and bucket:
            s3_client.put_object(
                Bucket=bucket,
                Key=output_path,
                Body=body,
                ContentType="application/json",
            )
        else:
            with open(output_path, "w") as f:
                f.write(body)

        logger.info(
            json.dumps(
                {
                    "audit_event": "compliance_mapping_exported_json",
                    "output_path": output_path,
                    "entry_count": len(entries),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        )

        return output_path

    @staticmethod
    def export_markdown(
        entries: List[ComplianceMappingEntry],
        output_path: str,
        s3_client=None,
        bucket: str = "",
    ) -> str:
        """Export mapping entries as a Markdown table.

        If s3_client and bucket are provided, writes to S3. Otherwise writes
        to a local file path.

        Args:
            entries: List of ComplianceMappingEntry objects to export.
            output_path: S3 key or local file path.
            s3_client: Optional boto3 S3 client for S3 writes.
            bucket: S3 bucket name (required if s3_client is provided).

        Returns:
            The output path where the Markdown was written.
        """
        if not entries:
            body = "No compliance mapping entries.\n"
        else:
            framework = entries[0].framework
            if framework == "iso_42001":
                header = "| Control ID | Control Name | Implementation Component | Evidence Generated | Compliance Status |"
                separator = "|---|---|---|---|---|"
                rows = []
                for e in entries:
                    rows.append(
                        f"| {e.control_id} | {e.control_name} | "
                        f"{e.implementation_component} | {e.evidence_generated} | "
                        f"{e.compliance_status} |"
                    )
                body = f"# ISO 42001 Compliance Mapping\n\n{header}\n{separator}\n" + "\n".join(rows) + "\n"
            else:
                header = "| Function | Category | Subcategory | Implementation Component | Evidence Generated | Compliance Status |"
                separator = "|---|---|---|---|---|---|"
                rows = []
                for e in entries:
                    rows.append(
                        f"| {e.function_name} | {e.category} | {e.subcategory} | "
                        f"{e.implementation_component} | {e.evidence_generated} | "
                        f"{e.compliance_status} |"
                    )
                body = f"# NIST AI RMF Compliance Mapping\n\n{header}\n{separator}\n" + "\n".join(rows) + "\n"

        if s3_client and bucket:
            s3_client.put_object(
                Bucket=bucket,
                Key=output_path,
                Body=body,
                ContentType="text/markdown",
            )
        else:
            with open(output_path, "w") as f:
                f.write(body)

        logger.info(
            json.dumps(
                {
                    "audit_event": "compliance_mapping_exported_markdown",
                    "output_path": output_path,
                    "entry_count": len(entries),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        )

        return output_path

    def refresh_mappings(
        self,
        control_mapping_table,
        evidence_pipeline,
        s3_client,
        bucket: str,
    ) -> Dict[str, str]:
        """Regenerate both frameworks in both formats and write to S3.

        Writes to:
          - compliance/iso_42001/mapping.json
          - compliance/iso_42001/mapping.md
          - compliance/nist_ai_rmf/mapping.json
          - compliance/nist_ai_rmf/mapping.md

        Args:
            control_mapping_table: ControlMappingManager instance.
            evidence_pipeline: EvidencePipeline instance.
            s3_client: boto3 S3 client.
            bucket: S3 bucket name for evidence/compliance storage.

        Returns:
            Dict mapping framework/format to S3 key paths.
        """
        iso_entries = self.generate_iso42001_mapping(
            control_mapping_table, evidence_pipeline
        )
        nist_entries = self.generate_nist_ai_rmf_mapping(
            control_mapping_table, evidence_pipeline
        )

        paths = {}

        paths["iso_42001_json"] = self.export_json(
            iso_entries, "compliance/iso_42001/mapping.json", s3_client, bucket
        )
        paths["iso_42001_md"] = self.export_markdown(
            iso_entries, "compliance/iso_42001/mapping.md", s3_client, bucket
        )
        paths["nist_ai_rmf_json"] = self.export_json(
            nist_entries, "compliance/nist_ai_rmf/mapping.json", s3_client, bucket
        )
        paths["nist_ai_rmf_md"] = self.export_markdown(
            nist_entries, "compliance/nist_ai_rmf/mapping.md", s3_client, bucket
        )

        logger.info(
            json.dumps(
                {
                    "audit_event": "compliance_mappings_refreshed",
                    "paths": paths,
                    "iso_entry_count": len(iso_entries),
                    "nist_entry_count": len(nist_entries),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        )

        return paths
