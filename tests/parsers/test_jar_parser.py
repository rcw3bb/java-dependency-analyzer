"""
test_jar_parser module.

Tests for :class:`JarParser`.

:author: Ron Webb
:since: 1.6.0
"""

from pathlib import Path, PureWindowsPath
from java_dependency_analyzer.models.dependency import Dependency
from java_dependency_analyzer.parsers.jar_parser import JarParser

__author__ = "Ron Webb"
__since__ = "1.6.0"


class _FakeResolver:
    """Resolver stub mapping jar file names to dependencies."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Path | None]] = []

    def resolve(self, jar: str, base_dir: Path | None = None) -> Dependency | None:
        """Record the call and return a dependency named after the jar."""
        self.calls.append((jar, base_dir))
        name = PureWindowsPath(jar).stem
        if name.startswith("unknown"):
            return None
        artifact, _, version = name.rpartition("-")
        return Dependency(group_id="g", artifact_id=artifact, version=version)


class TestJarParser:
    """Tests for ``JarParser.parse``."""

    def test_list_mode_reads_entries(self, tmp_path):
        """List mode should resolve each non-blank, non-comment entry."""
        jar_list = tmp_path / "jars.txt"
        jar_list.write_text(
            "# comment\n\nfoo-1.0.jar\n  C:\\libs\\bar-2.0.JAR  \n'baz-3.0.jar'\n",
            encoding="utf-8",
        )
        resolver = _FakeResolver()

        deps = JarParser(resolver=resolver).parse(str(jar_list))

        assert [d.coordinates for d in deps] == ["g:foo:1.0", "g:bar:2.0", "g:baz:3.0"]
        assert resolver.calls[0][1] == tmp_path.resolve()

    def test_single_jar_mode(self):
        """Single jar mode should treat the input as the jar itself."""
        resolver = _FakeResolver()

        deps = JarParser(single_jar=True, resolver=resolver).parse("foo-1.0.jar")

        assert [d.coordinates for d in deps] == ["g:foo:1.0"]
        assert resolver.calls == [("foo-1.0.jar", None)]

    def test_duplicates_are_removed(self, tmp_path):
        """The same coordinates listed twice should appear once."""
        jar_list = tmp_path / "jars.txt"
        jar_list.write_text("foo-1.0.jar\nfoo-1.0.jar\n", encoding="utf-8")

        deps = JarParser(resolver=_FakeResolver()).parse(str(jar_list))

        assert len(deps) == 1

    def test_unresolved_jar_is_skipped(self, tmp_path):
        """A jar the resolver cannot identify should be skipped."""
        jar_list = tmp_path / "jars.txt"
        jar_list.write_text("unknown-1.0.jar\nfoo-1.0.jar\n", encoding="utf-8")

        deps = JarParser(resolver=_FakeResolver()).parse(str(jar_list))

        assert [d.artifact_id for d in deps] == ["foo"]

    def test_non_jar_entry_is_skipped(self, tmp_path):
        """Entries without a .jar extension should not reach the resolver."""
        jar_list = tmp_path / "jars.txt"
        jar_list.write_text("readme.txt\n", encoding="utf-8")
        resolver = _FakeResolver()

        assert JarParser(resolver=resolver).parse(str(jar_list)) == []
        assert not resolver.calls

    def test_missing_list_file_returns_empty(self, tmp_path):
        """An unreadable list file should yield no dependencies."""
        missing = tmp_path / "missing.txt"

        assert JarParser(resolver=_FakeResolver()).parse(str(missing)) == []

    def test_default_resolver_is_created(self):
        """A resolver should be created when none is injected."""
        assert JarParser()._resolver is not None  # pylint: disable=protected-access
