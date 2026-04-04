"""
gradle_parser module.

Parses Gradle build files (build.gradle and build.gradle.kts) to extract
runtime dependencies using regex-based analysis.

:author: Ron Webb
:since: 1.0.0
"""

import re
from pathlib import Path

from ..models.dependency import Dependency
from ..util.logger import setup_logger
from .base import DependencyParser, RUNTIME_SCOPES

__author__ = "Ron Webb"
__since__ = "1.0.0"

_logger = setup_logger(__name__)

# Matches Groovy DSL shorthand: implementation 'group:artifact:version'
_GROOVY_SHORTHAND = re.compile(
    r"""(?:^|\s)(?P<config>implementation|api|compile|runtimeOnly|runtime)\s+['"]"""
    r"""(?P<group>[^:'"]+):(?P<artifact>[^:'"]+):(?P<version>[^:'"]+)['"]""",
    re.MULTILINE,
)

# Matches Kotlin DSL shorthand: implementation("group:artifact:version")
_KOTLIN_SHORTHAND = re.compile(
    r"""(?:^|\s)(?P<config>implementation|api|compile|runtimeOnly|runtime)\s*\("""
    r"""["'](?P<group>[^:'"]+):(?P<artifact>[^:'"]+):(?P<version>[^:'"]+)["']\)""",
    re.MULTILINE,
)

# Matches Groovy block syntax:
#   implementation group: 'g', name: 'a', version: 'v'
_GROOVY_BLOCK = re.compile(
    r"""(?:^|\s)(?P<config>implementation|api|compile|runtimeOnly|runtime)\s+"""
    r"""group:\s*['"](?P<group>[^'"]+)['"]\s*,\s*name:\s*"""
    r"""['"](?P<artifact>[^'"]+)['"]\s*,\s*version:\s*['"](?P<version>[^'"]+)['"]""",
    re.MULTILINE,
)

# Matches Groovy ext { } block content (no nested braces)
_EXT_BLOCK_PATTERN = re.compile(r"\bext\s*\{([^}]*)\}", re.DOTALL)

# Matches simple key = 'value' or key = "value" assignments inside ext blocks
_EXT_PROPERTY_PATTERN = re.compile(
    r"""^[ \t]*(\w+)\s*=\s*['"]([^'"]+)['"]""",
    re.MULTILINE,
)

# Matches Groovy `def varName = 'value'` or Kotlin `val varName = "value"`
_DEF_VAL_PATTERN = re.compile(
    r"""(?:^|\s)(?:def|val)\s+(\w+)\s*=\s*["']([^"']+)["']""",
    re.MULTILINE,
)

# Matches Kotlin block syntax:
#   implementation(group = "g", name = "a", version = "v")
_KOTLIN_BLOCK = re.compile(
    r"""(?:^|\s)(?P<config>implementation|api|compile|runtimeOnly|runtime)\s*\(\s*"""
    r"""group\s*=\s*["'](?P<group>[^'"]+)["']\s*,\s*name\s*=\s*"""
    r"""["'](?P<artifact>[^'"]+)["']\s*,\s*version\s*=\s*["'](?P<version>[^'"]+)["']\s*\)""",
    re.MULTILINE,
)


class GradleParser(DependencyParser):
    """
    Parses Gradle build files (Groovy DSL and Kotlin DSL) to extract runtime dependencies.

    Supports both shorthand notation and named-parameter block notation.
    Handles build.gradle (Groovy) and build.gradle.kts (Kotlin DSL).

    :author: Ron Webb
    :since: 1.0.0
    """

    def parse(self, file_path: str) -> list[Dependency]:
        """
        Parse the given Gradle build file and return a list of direct dependencies.

        :author: Ron Webb
        :since: 1.0.0
        """
        _logger.info("Parsing Gradle build file: %s", file_path)
        path = Path(file_path)
        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            _logger.error("Failed to read Gradle file: %s", exc)
            return []

        is_kotlin_dsl = path.suffix == ".kts"
        content = self._strip_comments(content, is_kotlin_dsl)
        ext_props = self._extract_ext_properties(content)
        if ext_props:
            content = self._resolve_variables(content, ext_props)

        seen: set[str] = set()
        deps: list[Dependency] = []

        for dep in self._extract_all(content):
            key = dep.coordinates
            if key not in seen:
                seen.add(key)
                deps.append(dep)

        _logger.info("Found %d unique dependencies in %s", len(deps), file_path)
        return deps

    def _extract_ext_properties(self, content: str) -> dict[str, str]:
        """
        Extract simple string variable assignments from ``ext {}`` blocks and
        top-level ``def``/``val`` declarations.

        Returns a mapping of variable name to its string value.

        :author: Ron Webb
        :since: 1.0.0
        """
        props: dict[str, str] = {}
        for block_match in _EXT_BLOCK_PATTERN.finditer(content):
            for prop_match in _EXT_PROPERTY_PATTERN.finditer(block_match.group(1)):
                props[prop_match.group(1)] = prop_match.group(2)
        for def_match in _DEF_VAL_PATTERN.finditer(content):
            props[def_match.group(1)] = def_match.group(2)
        return props

    def _resolve_variables(self, content: str, props: dict[str, str]) -> str:
        """
        Substitute ``${varName}`` placeholders in *content* using *props*.

        Unrecognised variable references are left unchanged.

        :author: Ron Webb
        :since: 1.0.0
        """

        def _replacer(match: re.Match) -> str:
            return props.get(match.group(1), match.group(0))

        return re.sub(r"\$\{(\w+)\}", _replacer, content)

    def _strip_comments(self, content: str, _is_kotlin_dsl: bool) -> str:
        """
        Remove single-line (//) and block (/* */) comments from the file content.

        :author: Ron Webb
        :since: 1.0.0
        """
        # Remove block comments
        content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
        # Remove single-line comments
        content = re.sub(r"//.*", "", content)
        return content

    def _extract_all(self, content: str) -> list[Dependency]:
        """
        Run all regex patterns against the content and collect matches.

        :author: Ron Webb
        :since: 1.0.0
        """
        deps: list[Dependency] = []
        for pattern in (
            _GROOVY_SHORTHAND,
            _KOTLIN_SHORTHAND,
            _GROOVY_BLOCK,
            _KOTLIN_BLOCK,
        ):
            for match in pattern.finditer(content):
                dep = self._match_to_dependency(match)
                if dep is not None:
                    deps.append(dep)
        return deps

    def _match_to_dependency(self, match: re.Match) -> Dependency | None:
        """
        Convert a regex match object to a Dependency instance.

        Returns None if the configuration scope is not runtime-relevant.

        :author: Ron Webb
        :since: 1.0.0
        """
        config = match.group("config")
        group = match.group("group").strip()
        artifact = match.group("artifact").strip()
        version = match.group("version").strip()

        # Normalise scope name: 'compile' -> 'compile', 'implementation' -> 'implementation'
        scope = config if config in RUNTIME_SCOPES else "compile"

        if not group or not artifact or not version:
            return None

        # Skip variable references that couldn't be resolved
        if "$" in version:
            _logger.debug(
                "Skipping %s:%s — unresolved version: %s", group, artifact, version
            )
            return None

        _logger.debug(
            "Found dependency: %s:%s:%s (scope=%s)", group, artifact, version, scope
        )
        return Dependency(
            group_id=group,
            artifact_id=artifact,
            version=version,
            scope=scope,
        )
