"""
sbom_parser module.

Parses SBOM (Software Bill of Materials) JSON files in SPDX 2.3 or CycloneDX 1.6
format and extracts the contained Java dependencies.

:author: Ron Webb
:since: 1.5.0
"""

import json
import re
from pathlib import Path

from ..models.dependency import Dependency
from ..util.logger import setup_logger
from .base import DependencyParser

__author__ = "Ron Webb"
__since__ = "1.5.0"

_logger = setup_logger(__name__)

# Matches a Maven package URL: pkg:maven/{groupId}/{artifactId}@{version}
_PURL_MAVEN_RE = re.compile(r"^pkg:maven/([^/]+)/([^@]+)@(.+?)(?:[?#].*)?$")

# Maps CycloneDX scope values to Java dependency scope names
_CYCLONEDX_SCOPE_MAP: dict[str, str] = {
    "required": "compile",
    "optional": "runtime",
    "excluded": "provided",
}


def _parse_maven_purl(purl: str) -> tuple[str, str, str] | None:
    """
    Extract (group_id, artifact_id, version) from a Maven package URL.

    Returns *None* when *purl* is not a valid Maven purl.

    :author: Ron Webb
    :since: 1.5.0
    """
    match = _PURL_MAVEN_RE.match(purl.strip())
    if not match:
        return None
    return match.group(1), match.group(2), match.group(3)


class SbomParser(DependencyParser):
    """
    Parses an SBOM JSON file in SPDX 2.3 or CycloneDX 1.6 format.

    All components found in the file are returned as a flat list of
    :class:`~java_dependency_analyzer.models.dependency.Dependency` objects.
    Components without enough Maven coordinate information are silently skipped.

    :author: Ron Webb
    :since: 1.5.0
    """

    def __init__(self, standard: str) -> None:
        """
        Initialise the parser for the given SBOM *standard*.

        :author: Ron Webb
        :since: 1.5.0
        """
        self._standard = standard.lower()

    def parse(self, file_path: str) -> list[Dependency]:
        """
        Parse *file_path* and return a flat list of dependencies.

        :author: Ron Webb
        :since: 1.5.0
        """
        _logger.info("Parsing %s SBOM from '%s'", self._standard, file_path)
        try:
            content = Path(file_path).read_text(encoding="utf-8")
            data = json.loads(content)
        except (OSError, json.JSONDecodeError) as exc:
            _logger.error("Failed to read SBOM file: %s", exc)
            return []

        parsers = {
            "spdx": self._parse_spdx,
            "cyclonedx": self._parse_cyclonedx,
        }
        parser_fn = parsers.get(self._standard)
        if parser_fn is None:
            _logger.error("Unsupported SBOM standard: %s", self._standard)
            return []

        return parser_fn(data)

    # ------------------------------------------------------------------
    # SPDX 2.3
    # ------------------------------------------------------------------

    def _parse_spdx(self, data: dict) -> list[Dependency]:
        """
        Extract dependencies from a SPDX 2.3 JSON document.

        Each package must have a Maven purl in its ``externalRefs`` list.
        Packages without a valid Maven purl are skipped.

        :author: Ron Webb
        :since: 1.5.0
        """
        deps: list[Dependency] = []
        for pkg in data.get("packages", []):
            dep = self._spdx_package_to_dep(pkg)
            if dep is not None:
                deps.append(dep)
        _logger.info("Parsed %d dependencies from SPDX SBOM", len(deps))
        return deps

    @staticmethod
    def _spdx_package_to_dep(pkg: dict) -> Dependency | None:
        """
        Convert a single SPDX package entry to a :class:`Dependency`.

        Returns *None* when no Maven purl can be found.

        :author: Ron Webb
        :since: 1.5.0
        """
        for ref in pkg.get("externalRefs", []):
            if ref.get("referenceType") != "purl":
                continue
            locator = ref.get("referenceLocator", "")
            if not locator.startswith("pkg:maven/"):
                continue
            parsed = _parse_maven_purl(locator)
            if parsed is None:
                continue
            group_id, artifact_id, version = parsed
            return Dependency(
                group_id=group_id,
                artifact_id=artifact_id,
                version=version,
                scope="compile",
            )
        return None

    # ------------------------------------------------------------------
    # CycloneDX 1.6
    # ------------------------------------------------------------------

    def _parse_cyclonedx(self, data: dict) -> list[Dependency]:
        """
        Extract dependencies from a CycloneDX 1.6 JSON document.

        :author: Ron Webb
        :since: 1.5.0
        """
        deps: list[Dependency] = []
        for component in data.get("components", []):
            dep = self._cyclonedx_component_to_dep(component)
            if dep is not None:
                deps.append(dep)
        _logger.info("Parsed %d dependencies from CycloneDX SBOM", len(deps))
        return deps

    @staticmethod
    def _cyclonedx_component_to_dep(component: dict) -> Dependency | None:
        """
        Convert a single CycloneDX component entry to a :class:`Dependency`.

        Returns *None* when required coordinate fields are missing.

        :author: Ron Webb
        :since: 1.5.0
        """
        group_id = component.get("group", "").strip()
        artifact_id = component.get("name", "").strip()
        version = component.get("version", "").strip()

        # Fall back to purl parsing when group is absent
        if not group_id:
            purl = component.get("purl", "")
            if purl.startswith("pkg:maven/"):
                parsed = _parse_maven_purl(purl)
                if parsed:
                    group_id, artifact_id, version = parsed

        if not (group_id and artifact_id and version):
            return None

        cdx_scope = component.get("scope", "required")
        scope = _CYCLONEDX_SCOPE_MAP.get(cdx_scope, "compile")
        return Dependency(
            group_id=group_id,
            artifact_id=artifact_id,
            version=version,
            scope=scope,
        )
