"""
test_mvn_repository module.

Tests for the MvnRepositoryScanner.

:author: Ron Webb
:since: 1.0.0
"""

import httpx
from pytest_httpx import HTTPXMock

from java_dependency_analyzer.models.dependency import Dependency
from java_dependency_analyzer.scanners.mvn_repository import MvnRepositoryScanner

__author__ = "Ron Webb"
__since__ = "1.0.0"

_LOG4J = Dependency(
    group_id="org.apache.logging.log4j",
    artifact_id="log4j-core",
    version="2.14.1",
)

_ARTIFACT_URL = (
    "https://repo1.maven.org/maven2/"
    "org/apache/logging/log4j/log4j-core/2.14.1/"
)

_DIR_HTML = """
<html><body>
<pre>
<a href="../">../</a>
<a href="log4j-core-2.14.1.jar">log4j-core-2.14.1.jar</a>
<a href="log4j-core-2.14.1.pom">log4j-core-2.14.1.pom</a>
</pre>
</body></html>
"""


class TestMvnRepositoryScanner:
    """Tests for MvnRepositoryScanner."""

    def test_scan_always_returns_empty_on_200(self, httpx_mock: HTTPXMock):
        """Successful artifact fetch should return empty list (no vuln data at repo1)."""
        httpx_mock.add_response(url=_ARTIFACT_URL, text=_DIR_HTML)
        with httpx.Client(follow_redirects=True) as client:
            scanner = MvnRepositoryScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns == []

    def test_scan_returns_empty_on_404(self, httpx_mock: HTTPXMock):
        """HTTP 404 should return empty list, not raise."""
        httpx_mock.add_response(url=_ARTIFACT_URL, status_code=404)
        with httpx.Client(follow_redirects=True) as client:
            scanner = MvnRepositoryScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns == []

    def test_scan_returns_empty_on_network_error(self, httpx_mock: HTTPXMock):
        """Network error should return empty list, not raise."""
        httpx_mock.add_exception(
            httpx.ConnectError("timeout"),
            url=_ARTIFACT_URL,
        )
        with httpx.Client(follow_redirects=True) as client:
            scanner = MvnRepositoryScanner(client=client)
            vulns = scanner.scan(_LOG4J)

        assert vulns == []

    def test_version_url_format(self):
        """_version_url should return correct repo1.maven.org directory URL."""
        scanner = MvnRepositoryScanner()
        url = scanner._version_url(_LOG4J)  # pylint: disable=protected-access
        assert url == _ARTIFACT_URL
