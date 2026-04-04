"""
maven_parser module.

Parses Maven pom.xml files to extract runtime dependencies.

:author: Ron Webb
:since: 1.0.0
"""

import re
from lxml import etree

from ..models.dependency import Dependency
from ..util.logger import setup_logger
from .base import DependencyParser, RUNTIME_SCOPES

__author__ = "Ron Webb"
__since__ = "1.0.0"

_logger = setup_logger(__name__)

# POM XML namespace
_POM_NS = "http://maven.apache.org/POM/4.0.0"


class MavenParser(DependencyParser):
    """
    Parses a Maven pom.xml file and extracts runtime dependencies.

    Handles property placeholder substitution (e.g., ${project.version})
    and filters to compile/runtime scopes only.

    :author: Ron Webb
    :since: 1.0.0
    """

    def parse(self, file_path: str) -> list[Dependency]:
        """
        Parse the given pom.xml file and return a list of direct dependencies.

        :author: Ron Webb
        :since: 1.0.0
        """
        _logger.info("Parsing Maven POM: %s", file_path)
        try:
            tree = etree.parse(
                file_path
            )  # nosec B320  # pylint: disable=c-extension-no-member
        except etree.XMLSyntaxError as exc:  # pylint: disable=c-extension-no-member
            _logger.error("Failed to parse POM XML: %s", exc)
            return []

        root = tree.getroot()
        namespace = self._detect_namespace(root)
        properties = self._extract_properties(root, namespace)
        return self._extract_dependencies(root, namespace, properties)

    def _detect_namespace(self, root: etree._Element) -> dict[str, str]:
        """
        Detect whether the POM uses the standard Maven namespace or none.

        :author: Ron Webb
        :since: 1.0.0
        """
        if root.tag.startswith("{"):
            return {"m": _POM_NS}
        return {}

    def _tag(self, name: str, namespace: dict[str, str]) -> str:
        """
        Return the namespaced or plain tag name for an element lookup.

        :author: Ron Webb
        :since: 1.0.0
        """
        if namespace:
            return f"{{{_POM_NS}}}{name}"
        return name

    def _extract_properties(
        self, root: etree._Element, namespace: dict[str, str]
    ) -> dict[str, str]:
        """
        Extract all <properties> entries from the POM for variable substitution.

        :author: Ron Webb
        :since: 1.0.0
        """
        props: dict[str, str] = {}
        props_el = root.find(self._tag("properties", namespace))
        if props_el is not None:
            for child in props_el:
                local = etree.QName(
                    child.tag
                ).localname  # pylint: disable=c-extension-no-member
                if child.text:
                    props[local] = child.text.strip()

        # Add standard project coordinates as substitutable properties
        for coord in ("groupId", "artifactId", "version"):
            coord_el = root.find(self._tag(coord, namespace))
            if coord_el is not None and coord_el.text:
                props[f"project.{coord}"] = coord_el.text.strip()
                props[coord] = coord_el.text.strip()

        return props

    def _resolve_value(self, value: str, properties: dict[str, str]) -> str:
        """
        Replace ${property} placeholders with values from the properties map.

        :author: Ron Webb
        :since: 1.0.0
        """
        pattern = re.compile(r"\$\{([^}]+)\}")
        for match in pattern.finditer(value):
            key = match.group(1)
            replacement = properties.get(key, "")
            value = value.replace(match.group(0), replacement)
        return value

    def _extract_dependencies(
        self,
        root: etree._Element,
        namespace: dict[str, str],
        properties: dict[str, str],
    ) -> list[Dependency]:
        """
        Extract <dependency> elements, filter by scope, and return Dependency objects.

        :author: Ron Webb
        :since: 1.0.0
        """
        deps: list[Dependency] = []
        deps_container = root.find(self._tag("dependencies", namespace))
        if deps_container is None:
            return deps

        for dep_el in deps_container.findall(self._tag("dependency", namespace)):
            dep = self._parse_dependency_element(dep_el, namespace, properties)
            if dep is not None:
                deps.append(dep)

        return deps

    def _parse_dependency_element(
        self,
        dep_el: etree._Element,
        namespace: dict[str, str],
        properties: dict[str, str],
    ) -> Dependency | None:
        """
        Parse a single <dependency> element into a Dependency object.

        Returns None if the dependency should be skipped (wrong scope, missing fields).

        :author: Ron Webb
        :since: 1.0.0
        """

        def text(tag: str) -> str:
            child_el = dep_el.find(self._tag(tag, namespace))
            raw = (
                child_el.text.strip() if child_el is not None and child_el.text else ""
            )
            return self._resolve_value(raw, properties)

        group_id = text("groupId")
        artifact_id = text("artifactId")
        version = text("version")
        scope = text("scope") or "compile"

        if not group_id or not artifact_id:
            return None

        if scope not in RUNTIME_SCOPES:
            _logger.debug(
                "Skipping dependency %s:%s (scope=%s)", group_id, artifact_id, scope
            )
            return None

        if not version:
            _logger.warning("No version for %s:%s — skipping", group_id, artifact_id)
            return None

        return Dependency(
            group_id=group_id,
            artifact_id=artifact_id,
            version=version,
            scope=scope,
        )
