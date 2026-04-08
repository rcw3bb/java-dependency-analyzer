"""
maven_dep_tree_parser module.

Parses the text output of ``mvn dependency:tree`` to reconstruct
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

# Maven tree output prefix on every INFO line
_INFO_PREFIX = "[INFO] "
_INFO_PREFIX_LEN = len(_INFO_PREFIX)

# Each level of indentation is 3 characters wide ("|  " or "   ").
# _INDENT_UNIT and the literal \s{2} / \s{3} inside _CONNECTOR_RE must stay in sync.
_INDENT_UNIT = 3

# Matches the tree connector at the start of a dependency after stripping [INFO]
# Groups: (1) indent text, (2) connector "+- " or "\- ", (3) coordinate string
_CONNECTOR_RE = re.compile(r"^((?:[|\\+]\s{2}|\s{3})*)[+\\]- (.+)$")

# Matches Maven coordinates: group:artifact:type:version:scope
_COORD_RE = re.compile(r"^([^:]+):([^:]+):[^:]+:([^:]+):([^:]+)$")


class MavenDepTreeParser(DepTreeParser):
    """
    Parses the plain-text output of ``mvn dependency:tree`` and reconstructs
    the dependency tree as a list of :class:`~java_dependency_analyzer.models.dependency.Dependency`
    objects with nested ``transitive_dependencies``.

    Only lines with a ``+- `` or ``\\- `` connector are interpreted as
    dependency entries; all other lines (headers, the root artifact line,
    ``[INFO] BUILD SUCCESS``, etc.) are silently skipped.

    :author: Ron Webb
    :since: 1.0.0
    """

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _line_to_entry(self, line: str) -> tuple[int, bool, Dependency] | None:
        """
        Convert a single Maven dep-tree line to a ``(depth, is_leaf, dep)``
        entry, or return *None* to skip the line.

        :author: Ron Webb
        :since: 1.0.0
        """
        stripped = self._strip_info_prefix(line)
        if stripped is None:
            return None

        match = _CONNECTOR_RE.match(stripped)
        if match is None:
            return None

        indent_str = match.group(1)
        coord_str = match.group(2)
        depth = len(indent_str) // _INDENT_UNIT

        dep = self._parse_coordinate(coord_str, depth)
        if dep is None:
            return None

        return depth, False, dep

    def _strip_info_prefix(self, line: str) -> str | None:
        """
        Remove the ``[INFO] `` prefix from a Maven log line; return *None*
        if the prefix is absent (i.e. the line is not a Maven INFO line).

        :author: Ron Webb
        :since: 1.0.0
        """
        if line.startswith(_INFO_PREFIX):
            return line[_INFO_PREFIX_LEN:]
        return None

    def _parse_coordinate(self, coord_str: str, depth: int) -> Dependency | None:
        """
        Convert a Maven coordinate string (``group:artifact:type:version:scope``)
        into a :class:`Dependency`.  Returns *None* if the string cannot be
        parsed.

        :author: Ron Webb
        :since: 1.0.0
        """
        coord_match = _COORD_RE.match(coord_str.strip())
        if coord_match is None:
            _logger.debug("Could not parse Maven coordinate: %s", coord_str)
            return None

        group_id = coord_match.group(1).strip()
        artifact_id = coord_match.group(2).strip()
        version = coord_match.group(3).strip()
        scope = coord_match.group(4).strip()

        if not group_id or not artifact_id or not version:
            return None

        return Dependency(
            group_id=group_id,
            artifact_id=artifact_id,
            version=version,
            scope=scope,
            depth=depth,
        )
