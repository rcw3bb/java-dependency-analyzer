"""
test_html_reporter module.

Tests for the HtmlReporter.

:author: Ron Webb
:since: 1.0.0
"""

from java_dependency_analyzer.models.dependency import Dependency, Vulnerability
from java_dependency_analyzer.models.report import ScanResult
from java_dependency_analyzer.reporters.html_reporter import HtmlReporter

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


class TestHtmlReporter:
    """Tests for HtmlReporter."""

    def test_report_creates_file(self, tmp_path):
        """report() should create an HTML file at the given path."""
        out = tmp_path / "report.html"
        HtmlReporter().report(_make_result(), str(out))
        assert out.exists()

    def test_report_is_html(self, tmp_path):
        """Generated file should start with <!DOCTYPE html>."""
        out = tmp_path / "report.html"
        HtmlReporter().report(_make_result(), str(out))
        content = out.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_report_contains_source_file(self, tmp_path):
        """HTML should reference the source file name."""
        out = tmp_path / "report.html"
        HtmlReporter().report(_make_result(), str(out))
        content = out.read_text(encoding="utf-8")
        assert "pom.xml" in content

    def test_report_contains_dependency(self, tmp_path):
        """HTML should contain the dependency artifact id."""
        out = tmp_path / "report.html"
        HtmlReporter().report(_make_result(), str(out))
        content = out.read_text(encoding="utf-8")
        assert "lib" in content

    def test_report_contains_vulnerability(self, tmp_path):
        """HTML should contain the CVE ID when a vulnerability is present."""
        out = tmp_path / "report.html"
        HtmlReporter().report(_make_result(with_vuln=True), str(out))
        content = out.read_text(encoding="utf-8")
        assert "CVE-TEST" in content

    def test_report_no_vuln_shows_none_found(self, tmp_path):
        """HTML should show 'None found' when no vulnerabilities exist."""
        out = tmp_path / "report.html"
        HtmlReporter().report(_make_result(), str(out))
        content = out.read_text(encoding="utf-8")
        assert "None found" in content

    def test_report_transitive_dep_included(self, tmp_path):
        """Transitive dependencies should appear in the HTML table."""
        child = Dependency(group_id="org.child", artifact_id="child-lib", version="2.0", depth=1)
        parent = Dependency(group_id="org.parent", artifact_id="parent-lib", version="1.0")
        parent.transitive_dependencies = [child]
        result = ScanResult(source_file="pom.xml", dependencies=[parent])
        out = tmp_path / "report.html"
        HtmlReporter().report(result, str(out))
        content = out.read_text(encoding="utf-8")
        assert "child-lib" in content
