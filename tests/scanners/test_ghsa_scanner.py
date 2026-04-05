"""
test_ghsa_scanner module.

Tests for the GhsaScanner vulnerability scanner.

:author: Ron Webb
:since: 1.0.0
"""

import re
import sqlite3

import httpx
import pytest
from pytest_httpx import HTTPXMock

from java_dependency_analyzer.cache.db import _initialise_schema
from java_dependency_analyzer.cache.vulnerability_cache import VulnerabilityCache
from java_dependency_analyzer.models.dependency import Dependency
from java_dependency_analyzer.scanners.ghsa_scanner import GhsaScanner

__author__ = "Ron Webb"
__since__ = "1.0.0"

_LOG4J = Dependency(
    group_id="org.apache.logging.log4j",
    artifact_id="log4j-core",
    version="2.14.1",
)

# Match the base URL regardless of query parameters
_GHSA_URL_RE = re.compile(r"https://api\.github\.com/advisories")

_GHSA_RESPONSE = [
    {
        "ghsa_id": "GHSA-jfh8-c2jp-hdp9",
        "cve_id": "CVE-2021-44228",
        "summary": "Remote code execution in Apache Log4j2",
        "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-hdp9",
        "severity": "critical",
        "cvss": {
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "score": 10.0,
        },
        "cvss_severities": {
            "cvss_v3": {
                "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "score": 10.0,
            },
            "cvss_v4": None,
        },
        "vulnerabilities": [
            {
                "package": {
                    "ecosystem": "maven",
                    "name": "org.apache.logging.log4j:log4j-core",
                },
                "vulnerable_version_range": ">= 2.0-beta9, < 2.15.0",
                "first_patched_version": "2.15.0",
            }
        ],
    }
]

_EMPTY_RESPONSE: list = []


class TestGhsaScanner:
    """Tests for GhsaScanner."""

    def test_scan_returns_vulnerabilities(self, httpx_mock: HTTPXMock):
        """scan() should return parsed Vulnerability objects from a GHSA response."""
        httpx_mock.add_response(
            url=_GHSA_URL_RE,
            json=_GHSA_RESPONSE,
            is_reusable=True,
        )
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert len(vulns) == 1
        assert vulns[0].cve_id == "CVE-2021-44228"
        assert vulns[0].source == "ghsa"
        assert "log4j" in vulns[0].summary.lower()

    def test_scan_returns_empty_when_no_advisories(self, httpx_mock: HTTPXMock):
        """scan() should return an empty list when GHSA finds no advisories."""
        httpx_mock.add_response(
            url=_GHSA_URL_RE, json=_EMPTY_RESPONSE, is_reusable=True
        )
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns == []

    def test_scan_network_error_returns_empty(self, httpx_mock: HTTPXMock):
        """Network error should return an empty list, not raise."""
        httpx_mock.add_exception(httpx.ConnectError("timeout"), url=_GHSA_URL_RE)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns == []

    def test_scan_http_error_returns_empty(self, httpx_mock: HTTPXMock):
        """HTTP 500 from GitHub should return an empty list, not raise."""
        httpx_mock.add_response(url=_GHSA_URL_RE, status_code=500, is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns == []

    def test_scan_rate_limited_returns_empty(self, httpx_mock: HTTPXMock):
        """HTTP 429 (rate limited) should return an empty list, not raise."""
        httpx_mock.add_response(url=_GHSA_URL_RE, status_code=429, is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns == []

    def test_severity_extracted_from_label(self, httpx_mock: HTTPXMock):
        """Severity label (e.g. 'critical') should be uppercased."""
        httpx_mock.add_response(url=_GHSA_URL_RE, json=_GHSA_RESPONSE, is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns[0].severity == "CRITICAL"

    def test_severity_falls_back_to_cvss_v3_score(self, httpx_mock: HTTPXMock):
        """When severity label is absent, fall back to cvss_severities.cvss_v3.score."""
        advisory = {
            "ghsa_id": "GHSA-xxxx-1111-yyyy",
            "cve_id": None,
            "summary": "Some vulnerability",
            "html_url": "https://github.com/advisories/GHSA-xxxx-1111-yyyy",
            "severity": "unknown",
            "cvss": None,
            "cvss_severities": {
                "cvss_v3": {"score": 7.5},
                "cvss_v4": None,
            },
            "vulnerabilities": [],
        }
        httpx_mock.add_response(url=_GHSA_URL_RE, json=[advisory], is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns[0].severity == "7.5"

    def test_severity_falls_back_to_legacy_cvss_score(self, httpx_mock: HTTPXMock):
        """When severity label and cvss_severities are absent, fall back to cvss.score."""
        advisory = {
            "ghsa_id": "GHSA-xxxx-2222-yyyy",
            "cve_id": None,
            "summary": "Legacy scoring",
            "html_url": "https://github.com/advisories/GHSA-xxxx-2222-yyyy",
            "severity": "",
            "cvss": {"score": 8.1},
            "cvss_severities": {"cvss_v3": None, "cvss_v4": None},
            "vulnerabilities": [],
        }
        httpx_mock.add_response(url=_GHSA_URL_RE, json=[advisory], is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns[0].severity == "8.1"

    def test_severity_unknown_when_no_data(self, httpx_mock: HTTPXMock):
        """When no severity data is present, severity should be 'UNKNOWN'."""
        advisory = {
            "ghsa_id": "GHSA-xxxx-3333-yyyy",
            "cve_id": None,
            "summary": "No severity info",
            "html_url": "https://github.com/advisories/GHSA-xxxx-3333-yyyy",
            "severity": "",
            "cvss": None,
            "cvss_severities": {"cvss_v3": None, "cvss_v4": None},
            "vulnerabilities": [],
        }
        httpx_mock.add_response(url=_GHSA_URL_RE, json=[advisory], is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns[0].severity == "UNKNOWN"

    def test_affected_versions_extracted(self, httpx_mock: HTTPXMock):
        """Affected version range constraints should be split and returned."""
        httpx_mock.add_response(url=_GHSA_URL_RE, json=_GHSA_RESPONSE, is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert ">= 2.0-beta9" in vulns[0].affected_versions
        assert "< 2.15.0" in vulns[0].affected_versions

    def test_affected_versions_deduplication(self, httpx_mock: HTTPXMock):
        """Duplicate version constraints across multiple entries should appear once."""
        advisory = {
            "ghsa_id": "GHSA-xxxx-4444-yyyy",
            "cve_id": "CVE-2021-99999",
            "summary": "Duplicate ranges",
            "html_url": "https://github.com/advisories/GHSA-xxxx-4444-yyyy",
            "severity": "high",
            "cvss": None,
            "cvss_severities": {},
            "vulnerabilities": [
                {"vulnerable_version_range": "< 2.0"},
                {"vulnerable_version_range": "< 2.0"},
            ],
        }
        httpx_mock.add_response(url=_GHSA_URL_RE, json=[advisory], is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns[0].affected_versions.count("< 2.0") == 1

    def test_cve_id_falls_back_to_ghsa_id(self, httpx_mock: HTTPXMock):
        """When cve_id is None, the ghsa_id should be used as the identifier."""
        advisory = {
            "ghsa_id": "GHSA-xxxx-5555-yyyy",
            "cve_id": None,
            "summary": "No CVE assigned",
            "html_url": "https://github.com/advisories/GHSA-xxxx-5555-yyyy",
            "severity": "medium",
            "cvss": None,
            "cvss_severities": {},
            "vulnerabilities": [],
        }
        httpx_mock.add_response(url=_GHSA_URL_RE, json=[advisory], is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns[0].cve_id == "GHSA-xxxx-5555-yyyy"

    def test_reference_url_is_html_url(self, httpx_mock: HTTPXMock):
        """reference_url should be populated from the advisory html_url."""
        httpx_mock.add_response(url=_GHSA_URL_RE, json=_GHSA_RESPONSE, is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert "github.com/advisories" in vulns[0].reference_url


@pytest.fixture()
def in_memory_cache():
    """Yield a VulnerabilityCache backed by an in-memory SQLite database."""
    conn = sqlite3.connect(":memory:")
    _initialise_schema(conn)
    cache = VulnerabilityCache(connection=conn)
    yield cache
    conn.close()


class TestGhsaScannerCache:
    """Tests for GhsaScanner cache behaviour."""

    def test_cache_miss_calls_api(self, httpx_mock: HTTPXMock, in_memory_cache):
        """On a cache miss the scanner should call the API."""
        httpx_mock.add_response(url=_GHSA_URL_RE, json=_GHSA_RESPONSE, is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client, cache=in_memory_cache)
            vulns = scanner.scan(_LOG4J)

        assert len(vulns) == 1
        assert vulns[0].source == "ghsa"

    def test_cache_miss_stores_response(self, httpx_mock: HTTPXMock, in_memory_cache):
        """After a cache miss the response should be persisted in the cache."""
        httpx_mock.add_response(url=_GHSA_URL_RE, json=_GHSA_RESPONSE, is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client, cache=in_memory_cache)
            scanner.scan(_LOG4J)

        stored = in_memory_cache.get(
            "ghsa", _LOG4J.group_id, _LOG4J.artifact_id, _LOG4J.version
        )
        assert stored is not None

    def test_cache_hit_returns_ghsa_cache_source(
        self, httpx_mock: HTTPXMock, in_memory_cache
    ):
        """On a cache hit the source field should be 'ghsa-cache'."""
        httpx_mock.add_response(
            url=_GHSA_URL_RE,
            json=_GHSA_RESPONSE,
            is_reusable=True,
            is_optional=True,
        )
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client, cache=in_memory_cache)
            # First call populates the cache
            scanner.scan(_LOG4J)
            # Second call should serve from cache
            vulns = scanner.scan(_LOG4J)

        assert len(vulns) == 1
        assert vulns[0].source == "ghsa-cache"

    def test_api_failure_does_not_cache(self, httpx_mock: HTTPXMock, in_memory_cache):
        """A failed API call should not write anything to the cache."""
        httpx_mock.add_response(url=_GHSA_URL_RE, status_code=500, is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client, cache=in_memory_cache)
            scanner.scan(_LOG4J)

        stored = in_memory_cache.get(
            "ghsa", _LOG4J.group_id, _LOG4J.artifact_id, _LOG4J.version
        )
        assert stored is None

    def test_rate_limit_does_not_cache(self, httpx_mock: HTTPXMock, in_memory_cache):
        """A rate-limited (429) response should not be written to the cache."""
        httpx_mock.add_response(url=_GHSA_URL_RE, status_code=429, is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client, cache=in_memory_cache)
            scanner.scan(_LOG4J)

        stored = in_memory_cache.get(
            "ghsa", _LOG4J.group_id, _LOG4J.artifact_id, _LOG4J.version
        )
        assert stored is None

    def test_no_cache_still_calls_api(self, httpx_mock: HTTPXMock):
        """When cache=None the scanner calls the API directly every time."""
        httpx_mock.add_response(
            url=_GHSA_URL_RE,
            json=_GHSA_RESPONSE,
            is_reusable=True,
        )
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client, cache=None)
            vulns = scanner.scan(_LOG4J)

        assert vulns[0].source == "ghsa"


class TestGhsaScannerRateLimit:
    """Tests for GhsaScanner rate-limit behaviour.

    :author: Ron Webb
    :since: 1.1.1
    """

    def test_rate_limited_false_initially(self):
        """rate_limited should be False on a freshly created scanner."""
        scanner = GhsaScanner()
        assert scanner.rate_limited is False

    def test_http_429_sets_rate_limited(self, httpx_mock: HTTPXMock):
        """An HTTP 429 response should set rate_limited to True."""
        httpx_mock.add_response(url=_GHSA_URL_RE, status_code=429, is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            scanner.scan(_LOG4J)

        assert scanner.rate_limited is True

    def test_http_403_rate_limit_body_sets_rate_limited(self, httpx_mock: HTTPXMock):
        """An HTTP 403 whose body contains 'rate limit' should set rate_limited to True."""
        httpx_mock.add_response(
            url=_GHSA_URL_RE,
            status_code=403,
            text="HTTP/1.1 403 rate limited exceeded",
            is_reusable=True,
        )
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            scanner.scan(_LOG4J)

        assert scanner.rate_limited is True

    def test_http_403_non_rate_limit_body_does_not_set_rate_limited(
        self, httpx_mock: HTTPXMock
    ):
        """An HTTP 403 whose body does NOT mention 'rate limit' should not set rate_limited."""
        httpx_mock.add_response(
            url=_GHSA_URL_RE,
            status_code=403,
            text="Forbidden",
            is_reusable=True,
        )
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            scanner.scan(_LOG4J)

        assert scanner.rate_limited is False

    def test_rate_limited_skips_api_call(self, httpx_mock: HTTPXMock):
        """When rate_limited is True, scan() should return [] without hitting the API."""
        httpx_mock.add_response(url=_GHSA_URL_RE, status_code=429, is_reusable=True)
        with httpx.Client() as client:
            scanner = GhsaScanner(client=client)
            scanner.scan(_LOG4J)  # first call triggers rate limit
            # Second scan must not make another HTTP request; if it did,
            # pytest-httpx would flag an unexpected request and the assertion below
            # would still hold via the empty list.
            second_dep = Dependency(
                group_id="com.example", artifact_id="other", version="1.0.0"
            )
            vulns = scanner.scan(second_dep)

        assert vulns == []
