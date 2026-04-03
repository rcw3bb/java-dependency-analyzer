"""
mvn_repository module.

Verifies artifact existence on Maven Central (repo1.maven.org) for Maven dependencies.

:author: Ron Webb
:since: 1.0.0
"""

import time

import httpx

from ..models.dependency import Dependency, Vulnerability
from ..util.logger import setup_logger
from .base import VulnerabilityScanner

__author__ = "Ron Webb"
__since__ = "1.0.0"

_logger = setup_logger(__name__)

_BASE_URL = "https://repo1.maven.org/maven2"
_RATE_LIMIT_SECONDS = 1.0
_REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; java-dependency-analyzer/1.0; "
        "+https://github.com/rcw3bb/java-dependency-analyzer)"
    )
}


class MvnRepositoryScanner(VulnerabilityScanner):
    """
    Verifies artifact existence on Maven Central (repo1.maven.org).

    repo1.maven.org serves artifact files only and does not expose vulnerability
    information, so this scanner always returns an empty vulnerability list.
    It confirms the artifact is reachable and logs any issues.
    Rate-limited to one request per second to be a respectful client.

    :author: Ron Webb
    :since: 1.0.0
    """

    def __init__(self, client: httpx.Client | None = None) -> None:
        """
        Initialise the scanner with an optional shared httpx client.

        :author: Ron Webb
        :since: 1.0.0
        """
        self._client = client or httpx.Client(
            timeout=30, headers=_REQUEST_HEADERS, follow_redirects=True
        )
        self._last_request_time: float = 0.0

    def scan(self, dependency: Dependency) -> list[Vulnerability]:
        """
        Verify the artifact exists on Maven Central and return an empty vulnerability list.

        repo1.maven.org does not expose vulnerability data, so this scanner acts
        solely as an existence check. Vulnerability scanning is handled by OsvScanner.

        :author: Ron Webb
        :since: 1.0.0
        """
        self._rate_limit()
        url = self._version_url(dependency)
        _logger.debug("Checking Maven Central: %s", url)

        try:
            response = self._client.get(url)
            if response.status_code == 200:
                _logger.debug("Artifact confirmed on Maven Central: %s", dependency.coordinates)
            else:
                _logger.debug(
                    "Maven Central returned HTTP %d for %s",
                    response.status_code,
                    dependency.coordinates,
                )
        except httpx.RequestError as exc:
            _logger.warning(
                "Maven Central request failed for %s: %s", dependency.coordinates, exc
            )

        # repo1.maven.org provides no vulnerability data; OSV covers that
        return []

    def _version_url(self, dep: Dependency) -> str:
        """
        Return the repo1.maven.org directory URL for the specific artifact version.

        :author: Ron Webb
        :since: 1.0.0
        """
        group_path = dep.group_id.replace(".", "/")
        return f"{_BASE_URL}/{group_path}/{dep.artifact_id}/{dep.version}/"

    def _rate_limit(self) -> None:
        """
        Sleep if needed to maintain at most one request per second.

        :author: Ron Webb
        :since: 1.0.0
        """
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < _RATE_LIMIT_SECONDS:
            time.sleep(_RATE_LIMIT_SECONDS - elapsed)
        self._last_request_time = time.monotonic()
