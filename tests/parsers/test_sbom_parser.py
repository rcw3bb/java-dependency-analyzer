"""
test_sbom_parser module.

Tests for the SbomParser class.

:author: Ron Webb
:since: 1.5.0
"""

import json
from pathlib import Path

import pytest

from java_dependency_analyzer.parsers.sbom_parser import SbomParser

__author__ = "Ron Webb"
__since__ = "1.5.0"

_FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestSbomParserSpdx:
    """Tests for SPDX 2.3 parsing via SbomParser."""

    def setup_method(self):
        """Create a fresh SPDX parser instance per test."""
        self.parser = SbomParser("spdx")

    def test_returns_list(self):
        """parse() should return a list."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_spdx.json"))
        assert isinstance(result, list)

    def test_parses_two_valid_packages(self):
        """Fixture has 2 packages with valid Maven purls; third has no purl and is skipped."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_spdx.json"))
        assert len(result) == 2

    def test_group_id(self):
        """Group ID should be extracted from the Maven purl."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_spdx.json"))
        groups = {d.group_id for d in result}
        assert "org.springframework" in groups

    def test_artifact_id(self):
        """Artifact ID should be extracted from the Maven purl."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_spdx.json"))
        artifacts = {d.artifact_id for d in result}
        assert "spring-core" in artifacts

    def test_version(self):
        """Version should be extracted from the Maven purl."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_spdx.json"))
        spring = next((d for d in result if d.artifact_id == "spring-core"), None)
        assert spring is not None
        assert spring.version == "5.3.20"

    def test_scope_defaults_to_compile(self):
        """Scope should default to 'compile' for SPDX packages."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_spdx.json"))
        assert all(d.scope == "compile" for d in result)

    def test_skips_packages_without_maven_purl(self):
        """Packages without a Maven purl in externalRefs should be skipped."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_spdx.json"))
        names = {d.artifact_id for d in result}
        assert "no-purl-package" not in names

    def test_empty_packages(self, tmp_path):
        """SPDX document with no packages should return an empty list."""
        sbom = {"spdxVersion": "SPDX-2.3", "packages": []}
        path = tmp_path / "empty.json"
        path.write_text(json.dumps(sbom), encoding="utf-8")
        result = self.parser.parse(str(path))
        assert result == []

    def test_case_insensitive_standard(self):
        """SbomParser should accept 'SPDX' in any case."""
        parser = SbomParser("SPDX")
        result = parser.parse(str(_FIXTURES / "sample_sbom_spdx.json"))
        assert len(result) == 2

    def test_missing_file_returns_empty(self):
        """Parsing a non-existent file should return an empty list."""
        result = self.parser.parse("/nonexistent/path/to/file.json")
        assert result == []

    def test_invalid_json_returns_empty(self, tmp_path):
        """Parsing a file with invalid JSON should return an empty list."""
        bad = tmp_path / "bad.json"
        bad.write_text("not json content", encoding="utf-8")
        result = self.parser.parse(str(bad))
        assert result == []

    def test_no_transitive_dependencies(self):
        """All parsed dependencies should be at depth 0 with no transitive deps."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_spdx.json"))
        assert all(d.depth == 0 for d in result)
        assert all(d.transitive_dependencies == [] for d in result)


class TestSbomParserCycloneDx:
    """Tests for CycloneDX 1.6 parsing via SbomParser."""

    def setup_method(self):
        """Create a fresh CycloneDX parser instance per test."""
        self.parser = SbomParser("cyclonedx")

    def test_returns_list(self):
        """parse() should return a list."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_cyclonedx.json"))
        assert isinstance(result, list)

    def test_parses_three_components(self):
        """Fixture has 3 components (2 with group + 1 purl-only) — all valid."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_cyclonedx.json"))
        assert len(result) == 3

    def test_group_id(self):
        """Group ID should be read from the 'group' field."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_cyclonedx.json"))
        groups = {d.group_id for d in result}
        assert "org.springframework" in groups

    def test_artifact_id(self):
        """Artifact ID should be read from the 'name' field."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_cyclonedx.json"))
        artifacts = {d.artifact_id for d in result}
        assert "spring-core" in artifacts

    def test_version(self):
        """Version should be read from the 'version' field."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_cyclonedx.json"))
        spring = next((d for d in result if d.artifact_id == "spring-core"), None)
        assert spring is not None
        assert spring.version == "5.3.20"

    def test_required_scope_maps_to_compile(self):
        """CycloneDX 'required' scope should map to 'compile'."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_cyclonedx.json"))
        spring = next((d for d in result if d.artifact_id == "spring-core"), None)
        assert spring is not None
        assert spring.scope == "compile"

    def test_optional_scope_maps_to_runtime(self):
        """CycloneDX 'optional' scope should map to 'runtime'."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_cyclonedx.json"))
        optional = next((d for d in result if d.artifact_id == "optional-lib"), None)
        assert optional is not None
        assert optional.scope == "runtime"

    def test_purl_fallback_when_group_absent(self):
        """Component without 'group' but with a Maven purl should still be parsed."""
        result = self.parser.parse(str(_FIXTURES / "sample_sbom_cyclonedx.json"))
        optional = next((d for d in result if d.artifact_id == "optional-lib"), None)
        assert optional is not None
        assert optional.group_id == "org.example"

    def test_empty_components(self, tmp_path):
        """CycloneDX document with no components should return an empty list."""
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}
        path = tmp_path / "empty.json"
        path.write_text(json.dumps(sbom), encoding="utf-8")
        result = self.parser.parse(str(path))
        assert result == []

    def test_case_insensitive_standard(self):
        """SbomParser should accept 'CycloneDX' in any case."""
        parser = SbomParser("CycloneDX")
        result = parser.parse(str(_FIXTURES / "sample_sbom_cyclonedx.json"))
        assert len(result) == 3

    def test_component_missing_required_fields_skipped(self, tmp_path):
        """A component missing group, name, or version should be skipped."""
        sbom = {
            "components": [
                {"type": "library", "name": "noversion", "group": "org.example"}
            ]
        }
        path = tmp_path / "incomplete.json"
        path.write_text(json.dumps(sbom), encoding="utf-8")
        result = self.parser.parse(str(path))
        assert result == []


class TestSbomParserUnsupportedStandard:
    """Tests for unsupported SBOM standard handling."""

    def test_unsupported_standard_returns_empty(self, tmp_path):
        """An unsupported standard should return an empty list."""
        sbom = {"some": "data"}
        path = tmp_path / "data.json"
        path.write_text(json.dumps(sbom), encoding="utf-8")
        parser = SbomParser("unknown")
        result = parser.parse(str(path))
        assert result == []
