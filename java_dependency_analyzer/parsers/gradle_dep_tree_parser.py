"""
gradle_dep_tree_parser module.

Parses the text output of ``gradle dependencies`` to reconstruct
the full dependency tree including transitive dependencies.

:author: Ron Webb
:since: 1.0.0
"""

import re

from ..models.dependency import Dependency
from ..util.logger import setup_logger
from .base import DepTreeParser

__author__ = "Ron Webb"
__since__ = "1.0.0"

_logger = setup_logger(__name__)

# Matches the tree connector characters at the start of a dependency line.
# Each level of indentation is exactly 5 characters wide ("     " or "|    ").
_INDENT_UNIT = 5
_CONNECTOR_RE = re.compile(r"^((?:[|\\+]\s{3,4}|\s{5})*)([+\\])--- (.+)$")

# Matches a resolved version arrow, e.g. "1.0 -> 2.0", "RELEASE -> 4.16.0", or "artifact -> 4.16.0"
_VERSION_ARROW_RE = re.compile(r"\s*->\s*(\S+)$")

# Gradle coordinates without an explicit version: group:artifact (version comes from arrow)
_COORD_NO_VERSION_RE = re.compile(r"^([^:]+):([^:]+)$")

# Suffix appended to repeated subtree roots by Gradle
_REPEATED_SUFFIX = " (*)"

# Lines annotated as constraints (not actual dependencies)
_CONSTRAINT_SUFFIX = " (c)"

# Gradle coordinates: group:artifact:version
_COORD_RE = re.compile(r"^([^:]+):([^:]+):(.+)$")


class GradleDepTreeParser(DepTreeParser):
    """
    Parses the plain-text output of ``gradle dependencies`` and reconstructs
    the dependency tree as a list of :class:`~java_dependency_analyzer.models.dependency.Dependency`
    objects with nested ``transitive_dependencies``.

    The parser is format-agnostic regarding the configuration name; it processes
    the first dependency-tree block it encounters.  Users should redirect the
    output of the configuration they care about (e.g. ``runtimeClasspath``) into
    a text file and pass that file here.

    :author: Ron Webb
    :since: 1.0.0
    """

    def __init__(self) -> None:
        """
        Initialise the parser with an empty version-resolution cache.

        :author: Ron Webb
        :since: 1.1.1
        """
        # Maps (group_id, artifact_id) -> resolved version from a -> arrow
        self._resolutions: dict[tuple[str, str], str] = {}

    def parse(self, file_path: str) -> list[Dependency]:
        """
        Reset the resolution cache and delegate to the base parser.

        :author: Ron Webb
        :since: 1.1.1
        """
        self._resolutions = {}
        return super().parse(file_path)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _line_to_entry(self, line: str) -> tuple[int, bool, Dependency] | None:
        """
        Convert a single Gradle dep-tree line to a ``(depth, is_leaf, dep)``
        entry, or return *None* to skip the line.

        :author: Ron Webb
        :since: 1.0.0
        """
        if line.rstrip().endswith(_CONSTRAINT_SUFFIX):
            return None

        match = _CONNECTOR_RE.match(line)
        if match is None:
            return None

        indent_str, coord_str = match.group(1), match.group(3)
        depth = len(indent_str) // _INDENT_UNIT

        is_leaf = coord_str.endswith(_REPEATED_SUFFIX)
        if is_leaf:
            coord_str = coord_str[: -len(_REPEATED_SUFFIX)]

        dep = self._parse_coordinate(coord_str, depth)
        if dep is None:
            return None

        return depth, is_leaf, dep

    def _parse_coordinate(self, coord_str: str, depth: int) -> Dependency | None:
        """
        Convert a Gradle coordinate string (with optional ``->`` resolution)
        into a :class:`Dependency`.  Returns *None* if the string cannot be
        parsed.

        :author: Ron Webb
        :since: 1.0.0
        """
        # Resolve version arrows: "group:artifact:1.0 -> 2.0" or "group:artifact -> 2.0"
        arrow_match = _VERSION_ARROW_RE.search(coord_str)
        if arrow_match:
            resolved_version = arrow_match.group(1)
            # Strip the arrow portion from the coordinate
            coord_str = coord_str[: arrow_match.start()]
        else:
            resolved_version = None

        coord_str = coord_str.strip()
        coord_match = _COORD_RE.match(coord_str)
        if coord_match is not None:
            group_id = coord_match.group(1).strip()
            artifact_id = coord_match.group(2).strip()
            version = resolved_version or coord_match.group(3).strip()
        else:
            # Handle "group:artifact -> version" (no version before the arrow)
            no_ver_match = _COORD_NO_VERSION_RE.match(coord_str)
            if no_ver_match and resolved_version:
                group_id = no_ver_match.group(1).strip()
                artifact_id = no_ver_match.group(2).strip()
                version = resolved_version
            else:
                _logger.debug("Could not parse coordinate: %s", coord_str)
                return None

        if not group_id or not artifact_id or not version:
            return None

        # Store the resolved version the first time a -> arrow is seen for this artifact
        if resolved_version:
            self._resolutions[(group_id, artifact_id)] = resolved_version
        # Apply any cached resolution so (*) repeated entries use the resolved version
        version = self._resolutions.get((group_id, artifact_id), version)

        return Dependency(
            group_id=group_id,
            artifact_id=artifact_id,
            version=version,
            scope="runtime",
            depth=depth,
        )
