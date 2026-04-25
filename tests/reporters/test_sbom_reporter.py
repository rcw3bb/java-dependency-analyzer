"""
test_sbom_reporter module.

Tests for the SbomReporter class.

:author: Ron Webb
:since: 1.4.0
"""

import json
import re

import pytest

from java_dependency_analyzer.reporters.sbom_reporter import SbomReporter

__author__ = "Ron Webb"
__since__ = "1.4.0"

_SCAN_DATA = {
    "source_file": "sample_pom.xml",
    "scanned_at": "2024-01-01T00:00:00",
    "project_dir": None,
    "dependencies": [
        {
            "group_id": "org.springframework",
            "artifact_id": "spring-core",
            "version": "5.3.20",
            "scope": "compile",
            "depth": 0,
            "transitive_dependencies": [
                {
                    "group_id": "commons-logging",
                    "artifact_id": "commons-logging",
                    "version": "1.2",
                    "scope": "compile",
                    "depth": 1,
                    "transitive_dependencies": [],
                    "vulnerabilities": [],
                }
            ],
            "vulnerabilities": [],
        }
    ],
}

_SCAN_DATA_EMPTY = {
    "source_file": "empty_pom.xml",
    "scanned_at": "2024-01-01T00:00:00",
    "project_dir": None,
    "dependencies": [],
}


class TestSbomReporterSpdx:
    """Tests for SPDX output from SbomReporter."""

    def test_spdx_creates_file(self, tmp_path):
        """report() with spdx should create a JSON file."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "spdx", str(out))
        assert out.exists()

    def test_spdx_valid_json(self, tmp_path):
        """SPDX output must be valid JSON."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "spdx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_spdx_version(self, tmp_path):
        """SPDX output must have spdxVersion SPDX-2.3."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "spdx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["spdxVersion"] == "SPDX-2.3"

    def test_spdx_packages_count(self, tmp_path):
        """SPDX packages list should include direct and transitive dependencies."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "spdx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        # 1 direct + 1 transitive = 2
        assert len(data["packages"]) == 2

    def test_spdx_package_fields(self, tmp_path):
        """Each SPDX package must have required fields."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "spdx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        pkg = data["packages"][0]
        assert "SPDXID" in pkg
        assert "name" in pkg
        assert "versionInfo" in pkg
        assert "externalRefs" in pkg

    def test_spdx_purl_in_external_refs(self, tmp_path):
        """SPDX packages must contain a Maven purl in externalRefs."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "spdx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        locator = data["packages"][0]["externalRefs"][0]["referenceLocator"]
        assert locator.startswith("pkg:maven/")

    def test_spdx_relationships_count(self, tmp_path):
        """SPDX relationships should have one entry per dependency."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "spdx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data["relationships"]) == 2

    def test_spdx_case_insensitive_standard(self, tmp_path):
        """SbomReporter should accept 'SPDX' in any case."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "SPDX", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["spdxVersion"] == "SPDX-2.3"

    def test_spdx_empty_dependencies(self, tmp_path):
        """SPDX output with no dependencies should have empty packages list."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA_EMPTY, "spdx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["packages"] == []
        assert data["relationships"] == []

    def test_spdx_id_no_illegal_chars(self, tmp_path):
        """SPDX element IDs must only contain allowed characters."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "spdx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        for pkg in data["packages"]:
            spdx_id = pkg["SPDXID"]
            assert re.match(r"^SPDXRef-[A-Za-z0-9.\-]+$", spdx_id), spdx_id

    def test_spdx_no_duplicate_packages(self, tmp_path):
        """Duplicate dependencies in the tree should appear only once in packages."""
        scan = {
            "source_file": "pom.xml",
            "dependencies": [
                {
                    "group_id": "org.example",
                    "artifact_id": "lib",
                    "version": "1.0",
                    "scope": "compile",
                    "transitive_dependencies": [
                        {
                            "group_id": "org.example",
                            "artifact_id": "lib",
                            "version": "1.0",
                            "scope": "compile",
                            "transitive_dependencies": [],
                            "vulnerabilities": [],
                        }
                    ],
                    "vulnerabilities": [],
                }
            ],
        }
        out = tmp_path / "out.json"
        SbomReporter().report(scan, "spdx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data["packages"]) == 1


class TestSbomReporterCycloneDx:
    """Tests for CycloneDX output from SbomReporter."""

    def test_cyclonedx_creates_file(self, tmp_path):
        """report() with cyclonedx should create a JSON file."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "cyclonedx", str(out))
        assert out.exists()

    def test_cyclonedx_bom_format(self, tmp_path):
        """CycloneDX output must have bomFormat set to 'CycloneDX'."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "cyclonedx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["bomFormat"] == "CycloneDX"

    def test_cyclonedx_spec_version(self, tmp_path):
        """CycloneDX output must have specVersion 1.6."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "cyclonedx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["specVersion"] == "1.6"

    def test_cyclonedx_components_count(self, tmp_path):
        """CycloneDX components list should include direct and transitive dependencies."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "cyclonedx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data["components"]) == 2

    def test_cyclonedx_component_fields(self, tmp_path):
        """Each CycloneDX component must have type, name, version, and purl."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "cyclonedx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        comp = data["components"][0]
        assert comp["type"] == "library"
        assert "name" in comp
        assert "version" in comp
        assert comp["purl"].startswith("pkg:maven/")

    def test_cyclonedx_serial_number_format(self, tmp_path):
        """CycloneDX serialNumber must be a valid urn:uuid."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "cyclonedx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["serialNumber"].startswith("urn:uuid:")

    def test_cyclonedx_case_insensitive_standard(self, tmp_path):
        """SbomReporter should accept 'CycloneDX' in any case."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "CycloneDX", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["bomFormat"] == "CycloneDX"

    def test_cyclonedx_empty_dependencies(self, tmp_path):
        """CycloneDX output with no dependencies should have empty components list."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA_EMPTY, "cyclonedx", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["components"] == []


class TestSbomReporterSwid:
    """Tests for SWID output from SbomReporter."""

    def test_swid_creates_file(self, tmp_path):
        """report() with swid should create a JSON file."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "swid", str(out))
        assert out.exists()

    def test_swid_valid_json(self, tmp_path):
        """SWID output must be valid JSON."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "swid", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_swid_has_tag_id(self, tmp_path):
        """SWID output must have a tagId field."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "swid", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "tagId" in data
        assert "java-dependency-analyzer" in data["tagId"]

    def test_swid_payload_software_count(self, tmp_path):
        """SWID payload.software list should include direct and transitive dependencies."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "swid", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert len(data["payload"]["software"]) == 2

    def test_swid_software_item_fields(self, tmp_path):
        """Each SWID software item must have tagId, name, version, and entity."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "swid", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        item = data["payload"]["software"][0]
        assert "tagId" in item
        assert "name" in item
        assert "version" in item
        assert "entity" in item

    def test_swid_case_insensitive_standard(self, tmp_path):
        """SbomReporter should accept 'SWID' in any case."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA, "SWID", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "tagId" in data

    def test_swid_empty_dependencies(self, tmp_path):
        """SWID output with no dependencies should have empty software list."""
        out = tmp_path / "out.json"
        SbomReporter().report(_SCAN_DATA_EMPTY, "swid", str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["payload"]["software"] == []


class TestSbomReporterInvalidStandard:
    """Tests for unsupported SBOM standard handling."""

    def test_invalid_standard_raises_value_error(self, tmp_path):
        """An unsupported standard should raise ValueError."""
        out = tmp_path / "out.json"
        with pytest.raises(ValueError, match="Unsupported SBOM standard"):
            SbomReporter().report(_SCAN_DATA, "unknown", str(out))
