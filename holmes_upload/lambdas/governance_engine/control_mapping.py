"""Control Mapping module.

Provides a mapping table linking ISO 42001 and NIST AI RMF controls
to implementation components and evidence generated. Supports querying
by component and updating individual mappings.

Requirements: 14.1, 14.4
"""

import json
import logging
from typing import Dict, List

logger = logging.getLogger(__name__)


class ControlMappingManager:
    """Manages the Control_Mapping_Table linking controls to components."""

    def __init__(self) -> None:
        self._mappings: List[Dict[str, str]] = []

    def get_mapping_table(self) -> List[Dict[str, str]]:
        """Return the full Control_Mapping_Table.

        Returns:
            List of dicts with keys: control_id, control_name,
            implementation_component, evidence_generated.
        """
        return list(self._mappings)

    def get_mappings_for_component(
        self, component_name: str
    ) -> List[Dict[str, str]]:
        """Return all control mappings for a given implementation component.

        Args:
            component_name: Name of the implementation component.

        Returns:
            List of matching mapping dicts.
        """
        return [
            m for m in self._mappings
            if m.get("implementation_component") == component_name
        ]

    def update_mapping(
        self,
        control_id: str,
        implementation_component: str,
        evidence_generated: str,
    ) -> Dict[str, str]:
        """Add or update a mapping entry.

        If a mapping with the same control_id and implementation_component
        exists, it is updated. Otherwise a new entry is added.

        Args:
            control_id: The framework control identifier.
            implementation_component: Component implementing the control.
            evidence_generated: Description of evidence produced.

        Returns:
            The created or updated mapping dict.
        """
        for mapping in self._mappings:
            if (
                mapping.get("control_id") == control_id
                and mapping.get("implementation_component") == implementation_component
            ):
                mapping["evidence_generated"] = evidence_generated
                logger.info(
                    json.dumps({
                        "audit_event": "control_mapping_updated",
                        "control_id": control_id,
                        "implementation_component": implementation_component,
                    })
                )
                return mapping

        new_mapping = {
            "control_id": control_id,
            "control_name": control_id,
            "implementation_component": implementation_component,
            "evidence_generated": evidence_generated,
        }
        self._mappings.append(new_mapping)

        logger.info(
            json.dumps({
                "audit_event": "control_mapping_added",
                "control_id": control_id,
                "implementation_component": implementation_component,
            })
        )
        return new_mapping

    def load_from_file(self, filepath: str) -> int:
        """Load mappings from a JSON file and merge into the table.

        Args:
            filepath: Path to a JSON file containing a list of mappings.

        Returns:
            Number of mappings loaded.
        """
        with open(filepath, "r") as f:
            data = json.load(f)

        mappings = data if isinstance(data, list) else data.get("mappings", [])
        for entry in mappings:
            self.update_mapping(
                control_id=entry.get("control_id", ""),
                implementation_component=entry.get("implementation_component", ""),
                evidence_generated=entry.get("evidence_generated", ""),
            )
        return len(mappings)
