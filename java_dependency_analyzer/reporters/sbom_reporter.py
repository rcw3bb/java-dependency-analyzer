"""
sbom_reporter module.

Generates SBOM (Software Bill of Materials) documents from a JSON scan report
in SPDX 2.3, CycloneDX 1.6, or SWID (ISO/IEC 19770-2) format.

:author: Ron Webb
:since: 1.4.0
"""

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..util.logger import setup_logger

__author__ = "Ron Webb"
__since__ = "1.4.0"

_logger = setup_logger(__name__)

_SPDX_VERSION = "SPDX-2.3"
_CYCLONEDX_SPEC_VERSION = "1.6"
_CYCLONEDX_BOM_FORMAT = "CycloneDX"
_TOOL_NAME = "java-dependency-analyzer"


class SbomReporter:
    """
    Serialises a JSON scan report to an SBOM document.

    Supported standards: ``spdx``, ``cyclonedx``, ``swid``.

    :author: Ron Webb
    :since: 1.4.0
    """

    def report(self, scan_data: dict, standard: str, output_path: str) -> None:
        """
        Write an SBOM document in *standard* format to *output_path*.

        :author: Ron Webb
        :since: 1.4.0
        """
        standard_lower = standard.lower()
        generators = {
            "spdx": self._generate_spdx,
            "cyclonedx": self._generate_cyclonedx,
            "swid": self._generate_swid,
        }
        if standard_lower not in generators:
            raise ValueError(f"Unsupported SBOM standard: {standard}")

        sbom = generators[standard_lower](scan_data)

        _logger.info("Writing SBOM (%s) report to %s", standard, output_path)
        with open(output_path, "w", encoding="utf-8") as file_handle:
            json.dump(sbom, file_handle, indent=2)
        _logger.info("SBOM report written: %s", output_path)

    # ------------------------------------------------------------------
    # Dependency helpers
    # ------------------------------------------------------------------

    def _collect_all_dependencies(self, dependencies: list) -> list:
        """
        Flatten the dependency tree into a deduplicated list.

        :author: Ron Webb
        :since: 1.4.0
        """
        seen: set[tuple[str, str, str]] = set()
        result: list = []
        self._collect_deps_recursive(dependencies, seen, result)
        return result

    def _collect_deps_recursive(
        self,
        dependencies: list,
        seen: set,
        result: list,
    ) -> None:
        """
        Recursively collect all unique dependencies from the tree.

        :author: Ron Webb
        :since: 1.4.0
        """
        for dep in dependencies:
            key = (
                dep.get("group_id", ""),
                dep.get("artifact_id", ""),
                dep.get("version", ""),
            )
            if key not in seen:
                seen.add(key)
                result.append(dep)
            self._collect_deps_recursive(
                dep.get("transitive_dependencies", []), seen, result
            )

    # ------------------------------------------------------------------
    # SPDX 2.3
    # ------------------------------------------------------------------

    def _generate_spdx(self, scan_data: dict) -> dict:
        """
        Generate an SPDX 2.3 JSON SBOM document.

        :author: Ron Webb
        :since: 1.4.0
        """
        source_file = scan_data.get("source_file", "unknown")
        name = Path(source_file).stem
        namespace = f"https://spdx.org/spdxdocs/{name}-{uuid.uuid4()}"
        dependencies = self._collect_all_dependencies(
            scan_data.get("dependencies", [])
        )

        packages, relationships = self._build_spdx_packages(dependencies)

        return {
            "spdxVersion": _SPDX_VERSION,
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": name,
            "documentNamespace": namespace,
            "creationInfo": {
                "created": datetime.now(timezone.utc).isoformat(),
                "creators": [f"Tool: {_TOOL_NAME}"],
            },
            "packages": packages,
            "relationships": relationships,
        }

    def _build_spdx_packages(self, dependencies: list) -> tuple[list, list]:
        """
        Build the SPDX packages and relationships lists from *dependencies*.

        :author: Ron Webb
        :since: 1.4.0
        """
        packages: list = []
        relationships: list = []
        for dep in dependencies:
            spdx_id = self._spdx_id(dep)
            group_id = dep.get("group_id", "")
            artifact_id = dep.get("artifact_id", "")
            version = dep.get("version", "")
            packages.append(
                {
                    "SPDXID": spdx_id,
                    "name": artifact_id,
                    "versionInfo": version,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": False,
                    "supplier": f"Organization: {group_id}",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": (
                                f"pkg:maven/{group_id}/{artifact_id}@{version}"
                            ),
                        }
                    ],
                }
            )
            relationships.append(
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": spdx_id,
                }
            )
        return packages, relationships

    @staticmethod
    def _spdx_id(dep: dict) -> str:
        """
        Generate a valid SPDX element ID for a dependency.

        Replaces characters not allowed in an SPDX ``idstring`` with hyphens.

        :author: Ron Webb
        :since: 1.4.0
        """
        raw = (
            f"{dep.get('group_id', '')}-"
            f"{dep.get('artifact_id', '')}-"
            f"{dep.get('version', '')}"
        )
        sanitised = re.sub(r"[^A-Za-z0-9.\-]", "-", raw)
        return f"SPDXRef-{sanitised}"

    # ------------------------------------------------------------------
    # CycloneDX 1.6
    # ------------------------------------------------------------------

    def _generate_cyclonedx(self, scan_data: dict) -> dict:
        """
        Generate a CycloneDX 1.6 JSON SBOM document.

        :author: Ron Webb
        :since: 1.4.0
        """
        dependencies = self._collect_all_dependencies(
            scan_data.get("dependencies", [])
        )

        components = []
        for dep in dependencies:
            group_id = dep.get("group_id", "")
            artifact_id = dep.get("artifact_id", "")
            version = dep.get("version", "")
            components.append(
                {
                    "type": "library",
                    "group": group_id,
                    "name": artifact_id,
                    "version": version,
                    "purl": f"pkg:maven/{group_id}/{artifact_id}@{version}",
                    "scope": dep.get("scope", "required"),
                }
            )

        return {
            "bomFormat": _CYCLONEDX_BOM_FORMAT,
            "specVersion": _CYCLONEDX_SPEC_VERSION,
            "version": 1,
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"name": _TOOL_NAME}],
            },
            "components": components,
        }

    # ------------------------------------------------------------------
    # SWID (ISO/IEC 19770-2)
    # ------------------------------------------------------------------

    def _generate_swid(self, scan_data: dict) -> dict:
        """
        Generate a SWID (ISO/IEC 19770-2) JSON SBOM document.

        :author: Ron Webb
        :since: 1.4.0
        """
        source_file = scan_data.get("source_file", "unknown")
        name = Path(source_file).stem
        dependencies = self._collect_all_dependencies(
            scan_data.get("dependencies", [])
        )

        software_items = []
        for dep in dependencies:
            group_id = dep.get("group_id", "")
            artifact_id = dep.get("artifact_id", "")
            version = dep.get("version", "")
            software_items.append(
                {
                    "tagId": f"{group_id}:{artifact_id}:{version}",
                    "name": artifact_id,
                    "version": version,
                    "tagVersion": 1,
                    "entity": [{"name": group_id, "role": "softwareCreator"}],
                }
            )

        return {
            "tagId": f"{_TOOL_NAME}.{name}.{uuid.uuid4()}",
            "name": name,
            "version": scan_data.get("scanned_at", ""),
            "tagVersion": 1,
            "entity": [{"name": _TOOL_NAME, "role": "tagCreator"}],
            "payload": {
                "software": software_items,
            },
        }
