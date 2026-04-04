"""
osv_scanner module.

Queries the OSV.dev API to get vulnerability information for Maven packages.

:author: Ron Webb
:since: 1.0.0
"""

import json

import httpx

from ..cache.vulnerability_cache import VulnerabilityCache
from ..models.dependency import Dependency, Vulnerability
from ..util.logger import setup_logger
from .base import VulnerabilityScanner

__author__ = "Ron Webb"
__since__ = "1.0.0"

_logger = setup_logger(__name__)

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_OSV_VULN_URL = "https://osv.dev/vulnerability/"


class OsvScanner(VulnerabilityScanner):
    """
    Queries the OSV.dev API (https://api.osv.dev) to find vulnerabilities
    for a given Maven dependency version.

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

        When *cache* is provided, scan results are read from and written to it.

        :author: Ron Webb
        :since: 1.0.0
        """
        self._client = client or httpx.Client(timeout=30)
        self._cache = cache

    def scan(self, dependency: Dependency) -> list[Vulnerability]:
        """
        Query OSV.dev for vulnerabilities affecting this dependency version.

        :author: Ron Webb
        :since: 1.0.0
        """
        _logger.debug("Querying OSV for %s", dependency.coordinates)
        cached = self._get_cached("osv", dependency)
        if cached is not None:
            return self._apply_cache_source(cached, "osv")

        payload = {
            "version": dependency.version,
            "package": {
                "name": f"{dependency.group_id}:{dependency.artifact_id}",
                "ecosystem": "Maven",
            },
        }
        try:
            response = self._client.post(_OSV_QUERY_URL, json=payload)
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as exc:
            _logger.warning("OSV query failed for %s: %s", dependency.coordinates, exc)
            return []

        self._put_cached("osv", dependency, json.dumps(data))
        return self._parse_response(data)

    def _parse_response(self, data: dict) -> list[Vulnerability]:
        """
        Parse the OSV API response JSON into Vulnerability objects.

        :author: Ron Webb
        :since: 1.0.0
        """
        vulns: list[Vulnerability] = []
        for vuln in data.get("vulns", []):
            vuln_obj = self._parse_vuln(vuln)
            if vuln_obj is not None:
                vulns.append(vuln_obj)
        return vulns

    def _parse_vuln(self, vuln: dict) -> Vulnerability | None:
        """
        Convert a single OSV vulnerability dict into a Vulnerability object.

        :author: Ron Webb
        :since: 1.0.0
        """
        vuln_id = vuln.get("id", "UNKNOWN")
        summary = vuln.get("summary", "No summary available")
        severity = self._extract_severity(vuln)
        affected_versions = self._extract_affected_versions(vuln)
        reference_url = self._extract_reference_url(vuln, vuln_id)

        return Vulnerability(
            cve_id=vuln_id,
            summary=summary,
            severity=severity,
            affected_versions=affected_versions,
            source="osv",
            reference_url=reference_url,
        )

    def _extract_severity(self, vuln: dict) -> str:
        """
        Extract a human-readable severity from the vulnerability entry.

        :author: Ron Webb
        :since: 1.0.0
        """
        severity_list = vuln.get("severity", [])
        if severity_list:
            return severity_list[0].get("score", "UNKNOWN")
        # Try database_specific CVSS score
        db_specific = vuln.get("database_specific", {})
        return db_specific.get("severity", "UNKNOWN")

    def _extract_affected_versions(self, vuln: dict) -> list[str]:
        """
        Extract a flat list of affected version strings from the vulnerability entry.

        :author: Ron Webb
        :since: 1.0.0
        """
        affected_versions: list[str] = []
        for affected in vuln.get("affected", []):
            for version_range in affected.get("ranges", []):
                for event in version_range.get("events", []):
                    introduced = event.get("introduced")
                    fixed = event.get("fixed")
                    if introduced:
                        affected_versions.append(f">={introduced}")
                    if fixed:
                        affected_versions.append(f"<{fixed}")
            # Collect explicit version strings
            for ver in affected.get("versions", []):
                if ver not in affected_versions:
                    affected_versions.append(ver)
        return affected_versions

    def _extract_reference_url(self, vuln: dict, vuln_id: str) -> str:
        """
        Return the most relevant reference URL for the vulnerability.

        :author: Ron Webb
        :since: 1.0.0
        """
        for ref in vuln.get("references", []):
            if ref.get("type") == "WEB":
                return ref.get("url", "")
        return f"{_OSV_VULN_URL}{vuln_id}"
