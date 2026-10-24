"""
transitive module.

Resolves transitive dependencies by fetching POMs from Maven Central.

:author: Ron Webb
:since: 1.0.0
"""

import os
import re
from collections.abc import Callable

import httpx
from dotenv import load_dotenv
from lxml import etree  # pylint: disable=c-extension-no-member

from ..models.dependency import Dependency
from ..parsers.base import RUNTIME_SCOPES
from ..util.logger import setup_logger
from ..util.xml_helpers import POM_NS

__author__ = "Ron Webb"
__since__ = "1.0.0"

load_dotenv()

_logger = setup_logger(__name__)

_MAVEN_CENTRAL = os.getenv(
    "MAVEN_CENTRAL_URL",
    "https://maven-central.storage-download.googleapis.com/maven2",
)
# Maximum depth for transitive dependency resolution.
# Prevents infinite recursion and excessive network requests.
_MAX_DEPTH = 5

# Scopes that do NOT propagate transitively to the consumer
_NON_TRANSITIVE_SCOPES = frozenset({"test", "provided", "system", "import"})


class TransitiveResolver:
    """
    Resolves transitive dependencies by recursively fetching POM files from Maven Central.

    Uses an in-memory cache to avoid redundant network requests for the same artifact.

    :author: Ron Webb
    :since: 1.0.0
    """

    def __init__(self, client: httpx.Client | None = None) -> None:
        """
        Initialise the resolver with an optional shared httpx client.

        :author: Ron Webb
        :since: 1.0.0
        """
        self._client = client or httpx.Client(timeout=30)
        self._cache: dict[str, list[Dependency]] = {}

    def resolve(
        self,
        dependency: Dependency,
        depth: int = 0,
        _visited: set[str] | None = None,
    ) -> Dependency:
        """
        Recursively resolve transitive dependencies for the given dependency.

        Modifies the dependency in-place by populating
        ``dependency.transitive_dependencies`` and setting depth on children.

        Uses a *visited* set to skip any coordinate that has already been
        processed in the current resolution tree, preventing infinite loops
        caused by circular dependency declarations.

        :author: Ron Webb
        :since: 1.0.0
        """
        if _visited is None:
            _visited = set()

        if depth >= _MAX_DEPTH:
            _logger.debug(
                "Max depth %d reached at %s", _MAX_DEPTH, dependency.coordinates
            )
            return dependency

        key = dependency.coordinates
        if key in _visited:
            _logger.debug("Already visited, skipping: %s", key)
            return dependency
        _visited.add(key)

        if key in self._cache:
            dependency.transitive_dependencies = [
                Dependency(
                    group_id=d.group_id,
                    artifact_id=d.artifact_id,
                    version=d.version,
                    scope=d.scope,
                    depth=depth + 1,
                )
                for d in self._cache[key]
            ]
            return dependency

        pom_content = self._fetch_pom(self._pom_urls(dependency))
        if pom_content is None:
            return dependency

        direct_children = self._parse_pom_dependencies(pom_content, dependency)
        self._cache[key] = direct_children

        for child in direct_children:
            child.depth = depth + 1
            self.resolve(child, depth + 1, _visited)

        dependency.transitive_dependencies = direct_children
        return dependency

    def resolve_all(self, dependencies: list[Dependency]) -> list[Dependency]:
        """
        Resolve transitive dependencies for a list of direct dependencies.

        A single visited set is shared across all top-level dependencies so
        that any coordinate already resolved in a previous branch is not
        fetched or recursed into again.

        :author: Ron Webb
        :since: 1.0.0
        """
        visited: set[str] = set()
        for dep in dependencies:
            self.resolve(dep, depth=0, _visited=visited)
        return dependencies

    def _pom_urls(self, dep: Dependency) -> list[str]:
        """
        Build the POM URLs for the given dependency.

        :author: Ron Webb
        :since: 1.0.0
        """
        path = f"{dep.maven_path}/{dep.artifact_id}-{dep.version}.pom"
        return [f"{_MAVEN_CENTRAL}/{path}"]

    def _fetch_pom(self, urls: list[str]) -> bytes | None:
        """
        Fetch the POM from the first of *urls* that serves it; return raw bytes or None.

        A genuine 404 is final.  Network errors, HTTP 429/5xx and throttled
        responses (any response carrying ``Retry-After``) are logged as warnings
        and move on to the next URL, if any.

        :author: Ron Webb
        :since: 1.0.0
        """
        for url in urls:
            try:
                response = self._client.get(url)
            except httpx.RequestError as exc:
                _logger.warning("Network error fetching POM %s: %s", url, exc)
                continue
            if response.status_code == 200:
                return response.content
            if self._is_transient_failure(response):
                _logger.warning(
                    "POM fetch failed or was throttled (HTTP %d, Retry-After: %s): %s",
                    response.status_code,
                    response.headers.get("Retry-After", "n/a"),
                    url,
                )
                continue
            _logger.debug("POM not found (HTTP %d): %s", response.status_code, url)
            return None
        return None

    @staticmethod
    def _is_transient_failure(response: httpx.Response) -> bool:
        """
        Return True when *response* indicates a failure worth trying another URL for.

        :author: Ron Webb
        :since: 1.6.0
        """
        return (
            response.status_code == 429
            or response.status_code >= 500
            or "Retry-After" in response.headers
        )

    def _parse_pom_dependencies(
        self, pom_content: bytes, parent: Dependency
    ) -> list[Dependency]:
        """
        Parse a POM's <dependencies> section and return runtime-scoped children.

        :author: Ron Webb
        :since: 1.0.0
        """
        try:
            # Use a secure parser with external entity processing disabled to prevent XXE
            parser = etree.XMLParser(  # pylint: disable=c-extension-no-member
                resolve_entities=False, no_network=True
            )
            root = etree.fromstring(
                pom_content, parser
            )  # pylint: disable=c-extension-no-member
        except etree.XMLSyntaxError as exc:  # pylint: disable=c-extension-no-member
            _logger.warning("Could not parse POM for %s: %s", parent.coordinates, exc)
            return []

        ns_map = {"m": POM_NS}
        ns_prefix = "m:" if root.tag.startswith("{") else ""

        def find(node: etree._Element, tag: str) -> etree._Element | None:
            return (
                node.find(f"{ns_prefix}{tag}", ns_map) if ns_prefix else node.find(tag)
            )

        def text(node: etree._Element, tag: str) -> str:
            child = find(node, tag)
            return child.text.strip() if child is not None and child.text else ""

        # Extract properties for version variable substitution
        properties = self._extract_pom_properties(root, ns_prefix, ns_map)
        # Add parent version as fallback
        properties.setdefault("project.version", parent.version)
        properties.setdefault("version", parent.version)

        deps_container = find(root, "dependencies")
        if deps_container is None:
            return []

        children: list[Dependency] = []
        for dep_el in (
            deps_container.findall(f"{ns_prefix}dependency", ns_map)
            if ns_prefix
            else deps_container.findall("dependency")
        ):
            child = self._parse_dep_el(dep_el, properties, text)
            if child is not None:
                children.append(child)

        return children

    def _extract_pom_properties(
        self,
        root: etree._Element,
        ns_prefix: str,
        ns_map: dict[str, str],
    ) -> dict[str, str]:
        """
        Extract <properties> entries from a POM element.

        :author: Ron Webb
        :since: 1.0.0
        """
        props: dict[str, str] = {}
        props_el = (
            root.find("m:properties", ns_map) if ns_prefix else root.find("properties")
        )
        if props_el is not None:
            for child in props_el:
                if not isinstance(child.tag, str):  # skip comments and PIs
                    continue
                local = etree.QName(
                    child.tag
                ).localname  # pylint: disable=c-extension-no-member
                if child.text:
                    props[local] = child.text.strip()
        return props

    def _parse_dep_el(
        self,
        dep_el: etree._Element,
        properties: dict[str, str],
        text_fn: Callable[[etree._Element, str], str],
    ) -> Dependency | None:
        """
        Parse a single dependency XML element into a Dependency, or return None to skip it.

        :author: Ron Webb
        :since: 1.0.0
        """
        group_id = self._resolve_property(text_fn(dep_el, "groupId"), properties)
        artifact_id = self._resolve_property(text_fn(dep_el, "artifactId"), properties)
        version = self._resolve_property(text_fn(dep_el, "version"), properties)
        scope = text_fn(dep_el, "scope") or "compile"
        optional_raw = text_fn(dep_el, "optional")
        optional = optional_raw.lower() == "true"

        if not group_id or not artifact_id or not version:
            return None
        if scope in _NON_TRANSITIVE_SCOPES:
            return None
        if optional:
            return None
        if scope not in RUNTIME_SCOPES:
            return None

        return Dependency(
            group_id=group_id,
            artifact_id=artifact_id,
            version=version,
            scope=scope,
        )

    def _resolve_property(self, value: str, properties: dict[str, str]) -> str:
        """
        Replace ${key} placeholders using the provided properties dictionary.

        :author: Ron Webb
        :since: 1.0.0
        """
        if not value or "${" not in value:
            return value
        for match in re.finditer(r"\$\{([^}]+)\}", value):
            key = match.group(1)
            value = value.replace(match.group(0), properties.get(key, ""))
        return value
