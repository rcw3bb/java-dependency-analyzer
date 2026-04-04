"""
test_osv_scanner module.

Tests for the OsvScanner vulnerability scanner.

:author: Ron Webb
:since: 1.0.0
"""

import sqlite3

import httpx
import pytest
from pytest_httpx import HTTPXMock

from java_dependency_analyzer.cache.db import _initialise_schema
from java_dependency_analyzer.cache.vulnerability_cache import VulnerabilityCache
from java_dependency_analyzer.models.dependency import Dependency
from java_dependency_analyzer.scanners.osv_scanner import OsvScanner

__author__ = "Ron Webb"
__since__ = "1.0.0"

_LOG4J = Dependency(
    group_id="org.apache.logging.log4j",
    artifact_id="log4j-core",
    version="2.14.1",
)

_OSV_RESPONSE = {
    "vulns": [
        {
            "id": "CVE-2021-44228",
            "summary": "Remote code execution in Apache Log4j2",
            "severity": [{"type": "CVSS_V3", "score": "CRITICAL"}],
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "2.0-beta9"},
                                {"fixed": "2.15.0"},
                            ],
                        }
                    ],
                    "versions": ["2.14.1", "2.14.0"],
                }
            ],
            "references": [
                {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}
            ],
        }
    ]
}

_EMPTY_RESPONSE = {"vulns": []}


class TestOsvScanner:
    """Tests for OsvScanner."""

    def test_scan_returns_vulnerabilities(self, httpx_mock: HTTPXMock):
        """scan() should return parsed Vulnerability objects from OSV response."""
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/query",
            json=_OSV_RESPONSE,
        )
        with httpx.Client() as client:
            scanner = OsvScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2021-44228"
        assert vulns[0].severity == "CRITICAL"
        assert vulns[0].source == "osv"

    def test_scan_returns_empty_when_no_vulns(self, httpx_mock: HTTPXMock):
        """scan() should return an empty list when OSV finds nothing."""
        httpx_mock.add_response(url="https://api.osv.dev/v1/query", json=_EMPTY_RESPONSE)
        with httpx.Client() as client:
            scanner = OsvScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns == []

    def test_scan_affected_versions_extracted(self, httpx_mock: HTTPXMock):
        """Affected versions (range events + explicit) should be populated."""
        httpx_mock.add_response(url="https://api.osv.dev/v1/query", json=_OSV_RESPONSE)
        with httpx.Client() as client:
            scanner = OsvScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert ">=2.0-beta9" in vulns[0].affected_versions
        assert "<2.15.0" in vulns[0].affected_versions

    def test_scan_reference_url_extracted(self, httpx_mock: HTTPXMock):
        """Reference URL should be the first WEB reference."""
        httpx_mock.add_response(url="https://api.osv.dev/v1/query", json=_OSV_RESPONSE)
        with httpx.Client() as client:
            scanner = OsvScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert "nvd.nist.gov" in vulns[0].reference_url

    def test_scan_network_error_returns_empty(self, httpx_mock: HTTPXMock):
        """Network error should return an empty list, not raise."""
        httpx_mock.add_exception(httpx.ConnectError("timeout"), url="https://api.osv.dev/v1/query")
        with httpx.Client() as client:
            scanner = OsvScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns == []

    def test_scan_http_error_returns_empty(self, httpx_mock: HTTPXMock):
        """HTTP 500 from OSV should return an empty list, not raise."""
        httpx_mock.add_response(url="https://api.osv.dev/v1/query", status_code=500)
        with httpx.Client() as client:
            scanner = OsvScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns == []

    def test_scan_severity_fallback_to_database_specific(self, httpx_mock: HTTPXMock):
        """When severity list is empty, fall back to database_specific.severity."""
        response = {
            "vulns": [
                {
                    "id": "GHSA-1234",
                    "summary": "Some issue",
                    "severity": [],
                    "database_specific": {"severity": "HIGH"},
                    "affected": [],
                    "references": [],
                }
            ]
        }
        httpx_mock.add_response(url="https://api.osv.dev/v1/query", json=response)
        with httpx.Client() as client:
            scanner = OsvScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns[0].severity == "HIGH"

    def test_scan_fallback_reference_url(self, httpx_mock: HTTPXMock):
        """When no WEB reference exists, URL falls back to osv.dev URL."""
        response = {
            "vulns": [
                {
                    "id": "GHSA-XXXX",
                    "summary": "test",
                    "severity": [],
                    "affected": [],
                    "references": [{"type": "ADVISORY", "url": "https://example.com"}],
                }
            ]
        }
        httpx_mock.add_response(url="https://api.osv.dev/v1/query", json=response)
        with httpx.Client() as client:
            scanner = OsvScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert "osv.dev" in vulns[0].reference_url


@pytest.fixture()
def in_memory_cache():
    """Yield a VulnerabilityCache backed by an in-memory SQLite database."""
    conn = sqlite3.connect(":memory:")
    _initialise_schema(conn)
    cache = VulnerabilityCache(connection=conn)
    yield cache
    conn.close()


class TestOsvScannerCache:
    """Tests for OsvScanner cache behaviour."""

    def test_cache_miss_calls_api(self, httpx_mock: HTTPXMock, in_memory_cache):
        """On a cache miss the scanner should call the API."""
        httpx_mock.add_response(url="https://api.osv.dev/v1/query", json=_OSV_RESPONSE)
        with httpx.Client() as client:
            scanner = OsvScanner(client=client, cache=in_memory_cache)
            vulns = scanner.scan(_LOG4J)

        assert len(vulns) == 1
        assert vulns[0].source == "osv"

    def test_cache_miss_stores_response(self, httpx_mock: HTTPXMock, in_memory_cache):
        """After a cache miss the response should be persisted in the cache."""
        httpx_mock.add_response(url="https://api.osv.dev/v1/query", json=_OSV_RESPONSE)
        with httpx.Client() as client:
            scanner = OsvScanner(client=client, cache=in_memory_cache)
            scanner.scan(_LOG4J)

        stored = in_memory_cache.get("osv", _LOG4J.group_id, _LOG4J.artifact_id, _LOG4J.version)
        assert stored is not None

    def test_cache_hit_returns_osv_cache_source(self, httpx_mock: HTTPXMock, in_memory_cache):
        """On a cache hit the source field should be 'osv-cache'."""
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/query",
            json=_OSV_RESPONSE,
            is_reusable=True,
            is_optional=True,
        )
        with httpx.Client() as client:
            scanner = OsvScanner(client=client, cache=in_memory_cache)
            # First call populates the cache
            scanner.scan(_LOG4J)
            # Second call should serve from cache
            vulns = scanner.scan(_LOG4J)

        assert len(vulns) == 1
        assert vulns[0].source == "osv-cache"

    def test_api_failure_does_not_cache(self, httpx_mock: HTTPXMock, in_memory_cache):
        """A failed API call should not write anything to the cache."""
        httpx_mock.add_response(url="https://api.osv.dev/v1/query", status_code=500)
        with httpx.Client() as client:
            scanner = OsvScanner(client=client, cache=in_memory_cache)
            scanner.scan(_LOG4J)

        stored = in_memory_cache.get("osv", _LOG4J.group_id, _LOG4J.artifact_id, _LOG4J.version)
        assert stored is None

    def test_no_cache_still_calls_api(self, httpx_mock: HTTPXMock):
        """When cache=None the scanner calls the API directly every time."""
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/query",
            json=_OSV_RESPONSE,
            is_reusable=True,
        )
        with httpx.Client() as client:
            scanner = OsvScanner(client=client, cache=None)
            vulns = scanner.scan(_LOG4J)

        assert vulns[0].source == "osv"
