"""
jar_parser module.

Builds a dependency list from jar files, either from a text file listing jars
or from a single jar, by resolving each jar's Maven coordinates.

:author: Ron Webb
:since: 1.6.0
"""

from pathlib import Path

from ..models.dependency import Dependency
from ..resolvers.jar_resolver import JarCoordinateResolver
from ..util.logger import setup_logger
from .base import DependencyParser

__author__ = "Ron Webb"
__since__ = "1.6.0"

_logger = setup_logger(__name__)


class JarParser(DependencyParser):
    """
    Parses a list of jar files (or a single jar) into dependencies.

    In list mode the input file holds one jar per line (absolute path or file
    name); blank lines and lines starting with ``#`` are ignored.  In single
    jar mode the input is the jar itself.  Jars that cannot be identified are
    skipped with a warning.

    :author: Ron Webb
    :since: 1.6.0
    """

    def __init__(
        self,
        single_jar: bool = False,
        resolver: JarCoordinateResolver | None = None,
    ) -> None:
        """
        Initialise the parser.

        When *single_jar* is True the parsed input is a jar rather than a list file.

        :author: Ron Webb
        :since: 1.6.0
        """
        self._single_jar = single_jar
        self._resolver = resolver or JarCoordinateResolver()

    def parse(self, file_path: str) -> list[Dependency]:
        """
        Return the de-duplicated dependencies for the jar(s) referenced by *file_path*.

        :author: Ron Webb
        :since: 1.6.0
        """
        if self._single_jar:
            jars, base_dir = [file_path], None
        else:
            jars = self._read_jar_list(file_path)
            base_dir = Path(file_path).resolve().parent

        deps: dict[str, Dependency] = {}
        for jar in jars:
            dep = self._resolve_jar(jar, base_dir)
            if dep is not None:
                deps.setdefault(dep.coordinates, dep)
        _logger.info("Resolved %d dependencies from %d jar(s)", len(deps), len(jars))
        return list(deps.values())

    @staticmethod
    def _read_jar_list(file_path: str) -> list[str]:
        """
        Read the jar entries of the list file, skipping blank and comment lines.

        :author: Ron Webb
        :since: 1.6.0
        """
        try:
            content = Path(file_path).read_text(encoding="utf-8-sig")
        except (OSError, UnicodeDecodeError) as exc:
            _logger.error("Failed to read jar list file: %s", exc)
            return []
        entries = (line.strip().strip("\"'") for line in content.splitlines())
        return [e for e in entries if e and not e.startswith("#")]

    def _resolve_jar(self, jar: str, base_dir: Path | None) -> Dependency | None:
        """
        Resolve a single *jar* entry, returning *None* when it is not a usable jar.

        :author: Ron Webb
        :since: 1.6.0
        """
        if not jar.lower().endswith(".jar"):
            _logger.warning("Skipping '%s': not a .jar file", jar)
            return None
        return self._resolver.resolve(jar, base_dir)
