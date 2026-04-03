"""
test_maven_parser module.

Tests for the Maven POM parser.

:author: Ron Webb
:since: 1.0.0
"""

import os
from pathlib import Path

import pytest

from java_dependency_analyzer.parsers.maven_parser import MavenParser

__author__ = "Ron Webb"
__since__ = "1.0.0"

_FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestMavenParser:
    """Tests for MavenParser."""

    def setup_method(self):
        """Create a fresh parser instance per test."""
        self.parser = MavenParser()

    def test_parse_returns_three_runtime_deps(self):
        """Should parse 3 runtime deps (compile + runtime scope) and skip test/provided/no-version."""
        deps = self.parser.parse(str(_FIXTURES / "sample_pom.xml"))
        assert len(deps) == 3

    def test_property_substitution(self):
        """Version ${log4j.version} should be resolved to 2.14.1."""
        deps = self.parser.parse(str(_FIXTURES / "sample_pom.xml"))
        log4j = next((d for d in deps if d.artifact_id == "log4j-core"), None)
        assert log4j is not None
        assert log4j.version == "2.14.1"

    def test_skips_test_scope(self):
        """junit (test scope) should not appear in results."""
        deps = self.parser.parse(str(_FIXTURES / "sample_pom.xml"))
        assert not any(d.artifact_id == "junit" for d in deps)

    def test_skips_provided_scope(self):
        """servlet-api (provided scope) should not appear in results."""
        deps = self.parser.parse(str(_FIXTURES / "sample_pom.xml"))
        assert not any(d.artifact_id == "servlet-api" for d in deps)

    def test_skips_dep_without_version(self):
        """Dependency with no version should be excluded."""
        deps = self.parser.parse(str(_FIXTURES / "sample_pom.xml"))
        assert not any(d.artifact_id == "no-version-dep" for d in deps)

    def test_no_namespace_pom(self):
        """POM without the standard namespace should still parse correctly."""
        deps = self.parser.parse(str(_FIXTURES / "no_namespace_pom.xml"))
        assert len(deps) == 1
        assert deps[0].artifact_id == "commons-lang3"

    def test_invalid_xml_returns_empty(self, tmp_path):
        """Malformed XML should return an empty list, not raise."""
        bad_pom = tmp_path / "pom.xml"
        bad_pom.write_text("<project><invalid>", encoding="utf-8")
        deps = self.parser.parse(str(bad_pom))
        assert deps == []

    def test_dep_coordinates(self):
        """Parsed dep should expose full coordinates."""
        deps = self.parser.parse(str(_FIXTURES / "sample_pom.xml"))
        log4j = next(d for d in deps if d.artifact_id == "log4j-core")
        assert log4j.coordinates == "org.apache.logging.log4j:log4j-core:2.14.1"

    def test_default_scope_is_compile(self):
        """Dependency without explicit scope defaults to compile."""
        deps = self.parser.parse(str(_FIXTURES / "sample_pom.xml"))
        log4j = next(d for d in deps if d.artifact_id == "log4j-core")
        assert log4j.scope == "compile"

    def test_runtime_scope_dep_included(self):
        """Dependency with runtime scope should be included."""
        deps = self.parser.parse(str(_FIXTURES / "sample_pom.xml"))
        pg = next((d for d in deps if d.artifact_id == "postgresql"), None)
        assert pg is not None
        assert pg.scope == "runtime"

    def test_empty_dependencies_section(self, tmp_path):
        """POM with no <dependencies> block returns empty list."""
        pom = tmp_path / "pom.xml"
        pom.write_text(
            '<?xml version="1.0"?><project><groupId>g</groupId>'
            '<artifactId>a</artifactId><version>1.0</version></project>',
            encoding="utf-8",
        )
        deps = self.parser.parse(str(pom))
        assert deps == []
