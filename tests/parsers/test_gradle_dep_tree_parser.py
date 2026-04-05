"""
test_gradle_dep_tree_parser module.

Tests for the GradleDepTreeParser.

:author: Ron Webb
:since: 1.0.0
"""

from pathlib import Path

import pytest

from java_dependency_analyzer.parsers.gradle_dep_tree_parser import GradleDepTreeParser

__author__ = "Ron Webb"
__since__ = "1.0.0"

_FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestGradleDepTreeParser:
    """Tests for GradleDepTreeParser."""

    def test_parse_fixture_returns_correct_root_count(self):
        """Fixture file should yield 4 top-level dependencies."""
        parser = GradleDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_gradle_deps.txt"))
        assert len(deps) == 4

    def test_parse_nested_deps(self):
        """spring-core should have spring-jcl and slf4j-api as transitive children."""
        parser = GradleDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_gradle_deps.txt"))
        spring_core = next(d for d in deps if d.artifact_id == "spring-core")
        child_artifacts = {d.artifact_id for d in spring_core.transitive_dependencies}
        assert "spring-jcl" in child_artifacts
        assert "slf4j-api" in child_artifacts

    def test_version_resolution_arrow(self):
        """Dependencies with '-> version' should use the resolved (right-hand) version."""
        parser = GradleDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_gradle_deps.txt"))
        slf4j = next(d for d in deps if d.artifact_id == "slf4j-api")
        assert slf4j.version == "2.0.13"

    def test_repeated_marker_creates_leaf(self):
        """A dependency marked with (*) should be a leaf with no transitive children."""
        parser = GradleDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_gradle_deps.txt"))
        logback = next(d for d in deps if d.artifact_id == "logback-classic")
        # logback-classic has logback-core and slf4j-api(*) as children
        slf4j_child = next(
            d for d in logback.transitive_dependencies if d.artifact_id == "slf4j-api"
        )
        assert slf4j_child.transitive_dependencies == []

    def test_skip_constraint_lines(self, tmp_path):
        """Lines ending with ' (c)' must not produce any Dependency."""
        content = (
            "runtimeClasspath\n"
            "+--- com.example:lib-a:1.0 (c)\n"
            "\\--- com.example:lib-b:2.0\n"
        )
        dep_file = tmp_path / "deps.txt"
        dep_file.write_text(content, encoding="utf-8")
        parser = GradleDepTreeParser()
        deps = parser.parse(str(dep_file))
        artifacts = [d.artifact_id for d in deps]
        assert "lib-a" not in artifacts
        assert "lib-b" in artifacts

    def test_parse_returns_empty_on_missing_file(self, tmp_path):
        """parse() should return an empty list for an unreadable path."""
        parser = GradleDepTreeParser()
        deps = parser.parse(str(tmp_path / "nonexistent.txt"))
        assert deps == []

    def test_depth_set_correctly(self):
        """Top-level deps have depth 0; their direct children have depth 1."""
        parser = GradleDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_gradle_deps.txt"))
        spring_core = next(d for d in deps if d.artifact_id == "spring-core")
        assert spring_core.depth == 0
        for child in spring_core.transitive_dependencies:
            assert child.depth == 1

    def test_version_without_arrow_is_used_as_is(self):
        """Dependencies without version arrows keep their declared version."""
        parser = GradleDepTreeParser()
        deps = parser.parse(str(_FIXTURES / "sample_gradle_deps.txt"))
        spring_core = next(d for d in deps if d.artifact_id == "spring-core")
        assert spring_core.version == "5.3.39"

    def test_no_version_before_arrow(self, tmp_path):
        """'group:artifact -> version' (no version before arrow) uses the resolved version."""
        content = (
            "runtimeClasspath\n"
            "+--- org.apache.camel:camel-core -> 4.16.0\n"
            "\\--- org.apache.camel:camel-main:4.16.0\n"
        )
        dep_file = tmp_path / "deps.txt"
        dep_file.write_text(content, encoding="utf-8")
        parser = GradleDepTreeParser()
        deps = parser.parse(str(dep_file))
        camel_core = next(d for d in deps if d.artifact_id == "camel-core")
        assert camel_core.version == "4.16.0"
        assert camel_core.group_id == "org.apache.camel"

    def test_repeated_entry_uses_resolved_version(self, tmp_path):
        """A (*) repeated entry should use the resolved version from the first occurrence."""
        content = (
            "runtimeClasspath\n"
            "+--- org.example:lib-a:1.0\n"
            "|    \\--- org.example:lib-b:2.0 -> 1.5\n"
            "\\--- org.example:lib-c:3.0\n"
            "     \\--- org.example:lib-b:2.0 (*)\n"
        )
        dep_file = tmp_path / "deps.txt"
        dep_file.write_text(content, encoding="utf-8")
        parser = GradleDepTreeParser()
        deps = parser.parse(str(dep_file))

        def _find(deps_list, artifact):
            for d in deps_list:
                if d.artifact_id == artifact:
                    return d
                found = _find(d.transitive_dependencies, artifact)
                if found:
                    return found
            return None

        lib_b_first = _find(deps, "lib-b")
        assert lib_b_first is not None
        assert lib_b_first.version == "1.5"

        lib_c = next(d for d in deps if d.artifact_id == "lib-c")
        lib_b_repeated = next(
            d for d in lib_c.transitive_dependencies if d.artifact_id == "lib-b"
        )
        assert lib_b_repeated.version == "1.5"
