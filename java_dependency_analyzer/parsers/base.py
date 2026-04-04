"""
base module.

Defines the abstract base class for dependency file parsers and shared
tree-building utilities.

:author: Ron Webb
:since: 1.0.0
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from pathlib import Path

from ..models.dependency import Dependency
from ..util.logger import setup_logger

__author__ = "Ron Webb"
__since__ = "1.0.0"

_logger = setup_logger(__name__)

# Runtime scopes that contribute to the executable classpath
RUNTIME_SCOPES = frozenset({"compile", "runtime", "implementation", "api", "runtimeOnly"})


def attach_node(
    dep: Dependency,
    depth: int,
    is_leaf: bool,
    roots: list[Dependency],
    stack: list[Dependency | None],
) -> None:
    """
    Attach *dep* to the correct position in the dependency tree represented
    by *roots* (top-level nodes) and *stack* (depth-indexed parent cursor).

    *stack[d]* holds the :class:`Dependency` that is the current parent at
    depth *d*.  After attaching *dep*, the stack is updated so that
    ``stack[depth]`` points to *dep* (or ``None`` if *dep* is a leaf).

    :author: Ron Webb
    :since: 1.0.0
    """
    if depth == 0:
        roots.append(dep)
    else:
        parent_depth = depth - 1
        if parent_depth < len(stack) and stack[parent_depth] is not None:
            stack[parent_depth].transitive_dependencies.append(dep)  # type: ignore[union-attr]

    new_entry: Dependency | None = None if is_leaf else dep
    if depth < len(stack):
        stack[depth] = new_entry
    else:
        while len(stack) < depth:
            stack.append(None)
        stack.append(new_entry)


def build_tree_from_lines(
    lines: list[str],
    line_to_entry: Callable[[str], tuple[int, bool, Dependency] | None],
) -> list[Dependency]:
    """
    Build a nested dependency tree from raw text *lines*.

    Each line is passed through *line_to_entry*, which should return a
    ``(depth, is_leaf, dep)`` tuple or *None* to skip the line.  The
    resulting entries are assembled into a tree using :func:`attach_node`.

    This function is the shared core of both :class:`GradleDepTreeParser`
    and :class:`MavenDepTreeParser`.

    :author: Ron Webb
    :since: 1.0.0
    """
    roots: list[Dependency] = []
    stack: list[Dependency | None] = []
    for line in lines:
        entry = line_to_entry(line)
        if entry is None:
            continue
        depth, is_leaf, dep = entry
        attach_node(dep, depth, is_leaf, roots, stack)
    return roots


class DependencyParser(ABC):
    """
    Abstract base class for all dependency file parsers.

    :author: Ron Webb
    :since: 1.0.0
    """

    @abstractmethod
    def parse(self, file_path: str) -> list[Dependency]:
        """
        Parse the given build file and return a list of direct dependencies.

        Only runtime-relevant scopes are returned (compile, runtime,
        implementation, api, runtimeOnly).

        :author: Ron Webb
        :since: 1.0.0
        """


class DepTreeParser(DependencyParser):
    """
    Intermediate base class for parsers that read pre-generated dependency
    tree text files (e.g. ``gradle dependencies`` or ``mvn dependency:tree``).

    Subclasses must implement :meth:`_line_to_entry` to convert a single
    text line into a ``(depth, is_leaf, dep)`` entry.

    :author: Ron Webb
    :since: 1.0.0
    """

    def parse(self, file_path: str) -> list[Dependency]:
        """
        Read *file_path* and build a dependency tree by passing each line
        through :meth:`_line_to_entry`.

        :author: Ron Webb
        :since: 1.0.0
        """
        _logger.info("Parsing dependency tree from '%s'", file_path)
        try:
            content = Path(file_path).read_text(encoding="utf-8")
        except OSError as exc:
            _logger.error("Failed to read file: %s", exc)
            return []

        lines = content.splitlines()
        return build_tree_from_lines(lines, self._line_to_entry)

    @abstractmethod
    def _line_to_entry(
        self, line: str
    ) -> tuple[int, bool, Dependency] | None:
        """
        Convert a single dependency-tree text line into a
        ``(depth, is_leaf, dep)`` tuple, or return *None* to skip the line.

        :author: Ron Webb
        :since: 1.0.0
        """
