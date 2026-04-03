"""
test_json_reporter module.

Tests for the JsonReporter.

:author: Ron Webb
:since: 1.0.0
"""

import json
from pathlib import Path

from java_dependency_analyzer.models.dependency import Dependency, Vulnerability
from java_dependency_analyzer.models.report import ScanResult
from java_dependency_analyzer.reporters.json_reporter import JsonReporter

__author__ = "Ron Webb"
__since__ = "1.0.0"


def _make_result(with_vuln: bool = False) -> ScanResult:
    """Build a minimal ScanResult for testing."""
    dep = Dependency(group_id="org.example", artifact_id="lib", version="1.0")
    if with_vuln:
        dep.vulnerabilities = [
            Vulnerability(cve_id="CVE-TEST", summary="Test vuln", severity="HIGH")
        ]
    return ScanResult(source_file="pom.xml", dependencies=[dep])


class TestJsonReporter:
    """Tests for JsonReporter."""

    def test_report_creates_file(self, tmp_path):
        """report() should create a JSON file at the given path."""
        out = tmp_path / "report.json"
        JsonReporter().report(_make_result(), str(out))
        assert out.exists()

    def test_report_valid_json(self, tmp_path):
        """The generated file must be valid JSON."""
        out = tmp_path / "report.json"
        JsonReporter().report(_make_result(), str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert isinstance(data, dict)

    def test_report_contains_summary(self, tmp_path):
        """JSON must contain a summary section with required keys."""
        out = tmp_path / "report.json"
        JsonReporter().report(_make_result(), str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "summary" in data
        assert "total_dependencies" in data["summary"]
        assert "total_vulnerabilities" in data["summary"]

    def test_report_source_file(self, tmp_path):
        """JSON must record the source_file."""
        out = tmp_path / "report.json"
        JsonReporter().report(_make_result(), str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["source_file"] == "pom.xml"

    def test_report_vuln_in_output(self, tmp_path):
        """Vulnerabilities should appear in the JSON output."""
        out = tmp_path / "report.json"
        JsonReporter().report(_make_result(with_vuln=True), str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        dep_data = data["dependencies"][0]
        assert dep_data["vulnerabilities"][0]["cve_id"] == "CVE-TEST"

    def test_report_total_vulnerabilities_count(self, tmp_path):
        """Summary total_vulnerabilities should reflect actual count."""
        out = tmp_path / "report.json"
        JsonReporter().report(_make_result(with_vuln=True), str(out))
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["summary"]["total_vulnerabilities"] == 1
