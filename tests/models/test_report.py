"""
test_report module.

Tests for the ScanResult report model.

:author: Ron Webb
:since: 1.0.0
"""

from java_dependency_analyzer.models.dependency import Dependency, Vulnerability
from java_dependency_analyzer.models.report import ScanResult

__author__ = "Ron Webb"
__since__ = "1.0.0"


def _make_dep(group: str, artifact: str, version: str = "1.0") -> Dependency:
    """Create a Dependency quickly."""
    return Dependency(group_id=group, artifact_id=artifact, version=version)


def _make_vuln(cve_id: str = "CVE-TEST") -> Vulnerability:
    """Create a Vulnerability quickly."""
    return Vulnerability(cve_id=cve_id, summary="test", severity="HIGH")


class TestScanResult:
    """Tests for ScanResult."""

    def test_total_dependencies_empty(self):
        """Zero dependencies gives zero total."""
        result = ScanResult(source_file="pom.xml")
        assert result.total_dependencies == 0

    def test_total_dependencies_flat(self):
        """Flat list of 3 deps gives total of 3."""
        result = ScanResult(
            source_file="pom.xml",
            dependencies=[_make_dep("g", "a"), _make_dep("g", "b"), _make_dep("g", "c")],
        )
        assert result.total_dependencies == 3

    def test_total_dependencies_nested(self):
        """Transitive deps are counted recursively."""
        child = _make_dep("g", "child")
        parent = _make_dep("g", "parent")
        parent.transitive_dependencies = [child]
        result = ScanResult(source_file="pom.xml", dependencies=[parent])
        assert result.total_dependencies == 2

    def test_total_vulnerabilities_zero(self):
        """No vulnerabilities gives zero total."""
        result = ScanResult(source_file="pom.xml", dependencies=[_make_dep("g", "a")])
        assert result.total_vulnerabilities == 0

    def test_total_vulnerabilities_counted(self):
        """Vulnerabilities across multiple deps are summed."""
        dep1 = _make_dep("g", "a")
        dep1.vulnerabilities = [_make_vuln("CVE-1"), _make_vuln("CVE-2")]
        dep2 = _make_dep("g", "b")
        dep2.vulnerabilities = [_make_vuln("CVE-3")]
        result = ScanResult(source_file="pom.xml", dependencies=[dep1, dep2])
        assert result.total_vulnerabilities == 3

    def test_vulnerable_dependencies_includes_transitive(self):
        """Transitive deps with vulns appear in vulnerable_dependencies."""
        child = _make_dep("g", "child")
        child.vulnerabilities = [_make_vuln()]
        parent = _make_dep("g", "parent")
        parent.transitive_dependencies = [child]
        result = ScanResult(source_file="pom.xml", dependencies=[parent])
        assert len(result.vulnerable_dependencies) == 1
        assert result.vulnerable_dependencies[0].artifact_id == "child"

    def test_scanned_at_is_set(self):
        """scanned_at should be populated by default."""
        result = ScanResult(source_file="pom.xml")
        assert result.scanned_at != ""

    def test_vulnerable_dependencies_empty_when_clean(self):
        """vulnerable_dependencies is empty when no vulns found."""
        dep = _make_dep("g", "a")
        result = ScanResult(source_file="pom.xml", dependencies=[dep])
        assert result.vulnerable_dependencies == []

    def test_vulnerable_dependencies_deduped(self):
        """Same dep (same coordinates) appearing twice in tree is counted once."""
        vuln_dep_a = _make_dep("g", "a", "1.0")
        vuln_dep_a.vulnerabilities = [_make_vuln("CVE-1")]
        # Second node with identical coordinates (transitive of itself for test purposes)
        vuln_dep_a_dup = _make_dep("g", "a", "1.0")
        vuln_dep_a_dup.vulnerabilities = [_make_vuln("CVE-1")]
        root = _make_dep("g", "root")
        root.transitive_dependencies = [vuln_dep_a, vuln_dep_a_dup]
        result = ScanResult(source_file="pom.xml", dependencies=[root])
        assert len(result.vulnerable_dependencies) == 1

    def test_total_vulnerabilities_deduped_same_dep(self):
        """Same dep with a vulnerability appearing in tree twice counts vulns once."""
        vuln_dep = _make_dep("g", "a", "1.0")
        vuln_dep.vulnerabilities = [_make_vuln("CVE-1"), _make_vuln("CVE-2")]
        vuln_dep_dup = _make_dep("g", "a", "1.0")
        vuln_dep_dup.vulnerabilities = [_make_vuln("CVE-1"), _make_vuln("CVE-2")]
        root = _make_dep("g", "root")
        root.transitive_dependencies = [vuln_dep, vuln_dep_dup]
        result = ScanResult(source_file="pom.xml", dependencies=[root])
        # Should be 2 (from the single unique dep), not 4 (both duplicates)
        assert result.total_vulnerabilities == 2

    def test_vulnerable_dependencies_different_versions_both_counted(self):
        """Same group+artifact at different versions are separate entries."""
        dep_v1 = _make_dep("g", "a", "1.0")
        dep_v1.vulnerabilities = [_make_vuln("CVE-1")]
        dep_v2 = _make_dep("g", "a", "2.0")
        dep_v2.vulnerabilities = [_make_vuln("CVE-2")]
        result = ScanResult(source_file="pom.xml", dependencies=[dep_v1, dep_v2])
        assert len(result.vulnerable_dependencies) == 2
