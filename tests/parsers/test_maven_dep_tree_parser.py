"""
test_maven_dep_tree_parser module.

Tests for the MavenDepTreeParser.

:author: Ron Webb
:since: 1.0.0
"""

from pathlib import Path

import pytest

from java_dependency_analyzer.parsers.maven_dep_tree_parser import MavenDepTreeParser

__author__ = "Ron Webb"
__since__ = "1.0.0"

_FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestMavenDepTreeParser:
    """Tests for MavenDepTreeParser."""

    def test_parse_fixture_returns_correct_root_count(self):
        """Fixture file should yield 4 top-level dependencies."""
        parser = MavenDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_maven_deps.txt"))
        assert len(deps) == 4

    def test_parse_nested_deps(self):
        """spring-core should have spring-jcl as a transitive child."""
        parser = MavenDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_maven_deps.txt"))
        spring_core = next(d for d in deps if d.artifact_id == "spring-core")
        child_artifacts = {d.artifact_id for d in spring_core.transitive_dependencies}
        assert "spring-jcl" in child_artifacts

    def test_extracts_version_correctly(self):
        """The parser should extract the version from position 3 of the coordinate."""
        parser = MavenDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_maven_deps.txt"))
        slf4j = next(d for d in deps if d.artifact_id == "slf4j-api")
        assert slf4j.version == "2.0.13"

    def test_extracts_scope_correctly(self):
        """The parser should extract the scope from position 4 of the coordinate."""
        parser = MavenDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_maven_deps.txt"))
        logback = next(d for d in deps if d.artifact_id == "logback-classic")
        assert logback.scope == "compile"

    def test_skip_non_tree_lines(self):
        """Header lines, root artifact line, and BUILD SUCCESS must not appear as deps."""
        parser = MavenDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_maven_deps.txt"))
        artifact_ids = [d.artifact_id for d in deps]
        # The root project itself and BUILD SUCCESS lines must not appear
        assert "sample-project" not in artifact_ids
        assert "BUILD" not in artifact_ids

    def test_parse_returns_empty_on_missing_file(self, tmp_path):
        """parse() should return an empty list for an unreadable path."""
        parser = MavenDepTreeParser()
        deps = parser.parse(str(tmp_path / "nonexistent.txt"))
        assert deps == []

    def test_depth_set_correctly(self):
        """Top-level deps have depth 0; their direct children have depth 1."""
        parser = MavenDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_maven_deps.txt"))
        spring_core = next(d for d in deps if d.artifact_id == "spring-core")
        assert spring_core.depth == 0
        for child in spring_core.transitive_dependencies:
            assert child.depth == 1

    def test_logback_has_two_transitive_children(self):
        """logback-classic should have logback-core and slf4j-api as children."""
        parser = MavenDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_maven_deps.txt"))
        logback = next(d for d in deps if d.artifact_id == "logback-classic")
        child_artifacts = {d.artifact_id for d in logback.transitive_dependencies}
        assert "logback-core" in child_artifacts
        assert "slf4j-api" in child_artifacts
