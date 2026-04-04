"""
ghsa_scanner module.

Queries the GitHub Advisory Database REST API to get vulnerability information
for Maven packages.

:author: Ron Webb
:since: 1.0.0
"""

import json
import os

import httpx
from dotenv import load_dotenv

from ..cache.vulnerability_cache import VulnerabilityCache
from ..models.dependency import Dependency, Vulnerability
from ..util.logger import setup_logger
from .base import VulnerabilityScanner

__author__ = "Ron Webb"
__since__ = "1.0.0"

load_dotenv()

_logger = setup_logger(__name__)

_GHSA_API_URL = "https://api.github.com/advisories"
_ACCEPT_HEADER = "application/vnd.github+json"
_API_VERSION_HEADER = "2022-11-28"


class GhsaScanner(VulnerabilityScanner):
    """
    Queries the GitHub Advisory Database REST API (https://api.github.com/advisories)
    to find reviewed security advisories for a given Maven dependency version.

    Supports optional authentication via the ``GITHUB_TOKEN`` environment variable to
    increase the API rate limit from 60 to 5000 requests per hour.

    :author: Ron Webb
    :since: 1.0.0
    """

    def __init__(
        self,
        client: httpx.Client | None = None,
        cache: VulnerabilityCache | None = None,
    ) -> None:
        """
        Initialise the scanner with an optional shared httpx client and cache.

        If ``GITHUB_TOKEN`` is set in the environment, it is forwarded as a
        ``Bearer`` token to raise the GitHub API rate limit.
        When *cache* is provided, scan results are read from and written to it.

        :author: Ron Webb
        :since: 1.0.0
        """
        headers = {
            "Accept": _ACCEPT_HEADER,
            "X-GitHub-Api-Version": _API_VERSION_HEADER,
        }
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"Bearer {token}"

        self._client = client or httpx.Client(timeout=30, headers=headers)
        self._cache = cache

    def scan(self, dependency: Dependency) -> list[Vulnerability]:
        """
        Query the GitHub Advisory Database for advisories affecting this dependency.

        Checks the cache first when one is configured; only calls the API on a
        cache miss and stores the raw response on success.

        Uses the ``affects`` query parameter with ``group:artifact@version`` notation
        and filters by ``ecosystem=maven`` and ``type=reviewed``.

        :author: Ron Webb
        :since: 1.0.0
        """
        _logger.debug("Querying GHSA for %s", dependency.coordinates)
        cached = self._get_cached("ghsa", dependency)
        if cached is not None:
            return self._apply_cache_source(cached, "ghsa")

        affects = f"{dependency.group_id}:{dependency.artifact_id}@{dependency.version}"
        params = {
            "ecosystem": "maven",
            "affects": affects,
            "type": "reviewed",
        }
        try:
            response = self._client.get(_GHSA_API_URL, params=params)
            if response.status_code == 429:
                _logger.warning(
                    "GitHub Advisory API rate limit exceeded for %s",
                    dependency.coordinates,
                )
                return []
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as exc:
            _logger.warning("GHSA query failed for %s: %s", dependency.coordinates, exc)
            return []

        self._put_cached("ghsa", dependency, json.dumps(data))
        return self._parse_response(data)

    def _parse_response(self, data: list) -> list[Vulnerability]:
        """
        Parse the GitHub Advisory API response (a JSON array) into Vulnerability objects.

        :author: Ron Webb
        :since: 1.0.0
        """
        vulns: list[Vulnerability] = []
        for advisory in data:
            vuln_obj = self._parse_advisory(advisory)
            if vuln_obj is not None:
                vulns.append(vuln_obj)
        return vulns

    def _parse_advisory(self, advisory: dict) -> Vulnerability | None:
        """
        Convert a single GitHub Advisory dict into a Vulnerability object.

        The ``cve_id`` field prefers the CVE identifier when available and falls
        back to the GHSA identifier so every returned advisory has a unique ID.

        :author: Ron Webb
        :since: 1.0.0
        """
        ghsa_id = advisory.get("ghsa_id", "UNKNOWN")
        cve_id = advisory.get("cve_id") or ghsa_id
        summary = advisory.get("summary", "No summary available")
        severity = self._extract_severity(advisory)
        affected_versions = self._extract_affected_versions(advisory)
        reference_url = advisory.get("html_url", "")

        return Vulnerability(
            cve_id=cve_id,
            summary=summary,
            severity=severity,
            affected_versions=affected_versions,
            source="ghsa",
            reference_url=reference_url,
        )

    def _extract_severity(self, advisory: dict) -> str:
        """
        Extract a human-readable severity string from a GitHub Advisory entry.

        Tries, in order:
        1. The top-level ``severity`` label (e.g. ``"high"``, ``"critical"``).
        2. The CVSS v4 score from ``cvss_severities.cvss_v4.score``.
        3. The CVSS v3 score from ``cvss_severities.cvss_v3.score``.
        4. The legacy ``cvss.score`` field.

        :author: Ron Webb
        :since: 1.0.0
        """
        label = advisory.get("severity")
        if label and label not in ("", "unknown"):
            return label.upper()

        cvss_severities = advisory.get("cvss_severities", {})
        for key in ("cvss_v4", "cvss_v3"):
            score = (cvss_severities.get(key) or {}).get("score")
            if score is not None:
                return str(score)

        legacy_score = (advisory.get("cvss") or {}).get("score")
        if legacy_score is not None:
            return str(legacy_score)

        return "UNKNOWN"

    def _extract_affected_versions(self, advisory: dict) -> list[str]:
        """
        Extract affected version range strings from a GitHub Advisory entry.

        Each entry in ``vulnerabilities`` may carry a ``vulnerable_version_range``
        string (e.g. ``"< 2.17.0"`` or ``">= 2.0.0, < 2.15.0"``).  The method
        splits compound ranges on commas so the returned list contains individual
        constraint tokens.

        :author: Ron Webb
        :since: 1.0.0
        """
        affected_versions: list[str] = []
        seen: set[str] = set()
        for vuln_entry in advisory.get("vulnerabilities", []):
            version_range = vuln_entry.get("vulnerable_version_range")
            if not version_range:
                continue
            for part in version_range.split(","):
                constraint = part.strip()
                if constraint and constraint not in seen:
                    affected_versions.append(constraint)
                    seen.add(constraint)
        return affected_versions
