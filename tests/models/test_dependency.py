"""
test_dependency module.

Tests for the Dependency and Vulnerability models.

:author: Ron Webb
:since: 1.0.0
"""

import pytest

from java_dependency_analyzer.models.dependency import Dependency, Vulnerability

__author__ = "Ron Webb"
__since__ = "1.0.0"


class TestVulnerability:
    """Tests for the Vulnerability dataclass."""

    def test_default_values(self):
        """Vulnerability should set sensible defaults."""
        vuln = Vulnerability(cve_id="CVE-2021-44228", summary="Log4Shell", severity="CRITICAL")
        assert vuln.affected_versions == []
        assert vuln.source == "osv"
        assert vuln.reference_url == ""

    def test_custom_values(self):
        """Vulnerability should store all provided values."""
        vuln = Vulnerability(
            cve_id="CVE-2021-44228",
            summary="RCE in Log4j",
            severity="CRITICAL",
            affected_versions=[">=2.0", "<2.15.0"],
            source="osv",
            reference_url="https://osv.dev/vulnerability/CVE-2021-44228",
        )
        assert vuln.cve_id == "CVE-2021-44228"
        assert vuln.severity == "CRITICAL"
        assert len(vuln.affected_versions) == 2


class TestDependency:
    """Tests for the Dependency dataclass."""

    def test_coordinates_property(self):
        """coordinates should return group:artifact:version."""
        dep = Dependency(group_id="org.apache.logging.log4j", artifact_id="log4j-core", version="2.14.1")
        assert dep.coordinates == "org.apache.logging.log4j:log4j-core:2.14.1"

    def test_maven_path_property(self):
        """maven_path should convert dots to slashes in groupId."""
        dep = Dependency(group_id="org.apache.logging.log4j", artifact_id="log4j-core", version="2.14.1")
        assert dep.maven_path == "org/apache/logging/log4j/log4j-core/2.14.1"

    def test_has_vulnerabilities_direct(self):
        """has_vulnerabilities should return True when self has vulns."""
        dep = Dependency(group_id="g", artifact_id="a", version="1.0")
        dep.vulnerabilities = [Vulnerability(cve_id="CVE-1", summary="x", severity="HIGH")]
        assert dep.has_vulnerabilities() is True

    def test_has_vulnerabilities_transitive(self):
        """has_vulnerabilities should return True when a transitive dep has vulns."""
        child = Dependency(group_id="g", artifact_id="b", version="1.0")
        child.vulnerabilities = [Vulnerability(cve_id="CVE-2", summary="y", severity="LOW")]
        parent = Dependency(group_id="g", artifact_id="a", version="1.0")
        parent.transitive_dependencies = [child]
        assert parent.has_vulnerabilities() is True

    def test_has_vulnerabilities_none(self):
        """has_vulnerabilities should return False when no vulns exist."""
        dep = Dependency(group_id="g", artifact_id="a", version="1.0")
        assert dep.has_vulnerabilities() is False

    def test_default_scope(self):
        """Default scope should be compile."""
        dep = Dependency(group_id="g", artifact_id="a", version="1.0")
        assert dep.scope == "compile"

    def test_default_depth(self):
        """Default depth should be 0."""
        dep = Dependency(group_id="g", artifact_id="a", version="1.0")
        assert dep.depth == 0
