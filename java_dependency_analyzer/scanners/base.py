"""
base module.

Defines the abstract base class for vulnerability scanners.

:author: Ron Webb
:since: 1.0.0
"""

import json
from abc import ABC, abstractmethod

from ..cache.vulnerability_cache import VulnerabilityCache
from ..models.dependency import Dependency, Vulnerability

__author__ = "Ron Webb"
__since__ = "1.0.0"


class VulnerabilityScanner(ABC):
    """
    Abstract base class for all vulnerability scanners.

    Provides shared cache helpers so concrete scanners can check and store
    raw API payloads without duplicating the logic.

    :author: Ron Webb
    :since: 1.0.0
    """

    # Subclasses set this in __init__; None disables caching.
    _cache: VulnerabilityCache | None = None

    @abstractmethod
    def scan(self, dependency: Dependency) -> list[Vulnerability]:
        """
        Scan the given dependency for known vulnerabilities.

        Returns a list of Vulnerability objects found for this exact version.

        :author: Ron Webb
        :since: 1.0.0
        """

    @abstractmethod
    def _parse_response(self, data: dict | list) -> list[Vulnerability]:
        """
        Parse the raw API response payload into Vulnerability objects.

        Concrete scanners receive either a ``dict`` (OSV) or a ``list`` (GHSA),
        so the parameter accepts either type.

        :author: Ron Webb
        :since: 1.0.0
        """

    def _get_cached(self, source: str, dependency: Dependency) -> str | None:
        """
        Return the cached JSON payload for *dependency* under *source*, or ``None``.

        :author: Ron Webb
        :since: 1.0.0
        """
        if self._cache is None:
            return None
        return self._cache.get(
            source, dependency.group_id, dependency.artifact_id, dependency.version
        )

    def _put_cached(self, source: str, dependency: Dependency, payload: str) -> None:
        """
        Persist *payload* in the cache under *source* for *dependency*.

        :author: Ron Webb
        :since: 1.0.0
        """
        if self._cache is not None:
            self._cache.put(
                source,
                dependency.group_id,
                dependency.artifact_id,
                dependency.version,
                payload,
            )

    def _apply_cache_source(self, data: str, source: str) -> list[Vulnerability]:
        """
        Deserialise *data* (a cached JSON string), parse into ``Vulnerability``
        objects, and mark each with ``source = "<source>-cache"``.

        Concrete scanners implement :meth:`_parse_response`; this helper
        delegates to it after decoding the cached payload.

        :author: Ron Webb
        :since: 1.0.0
        """
        parsed = self._parse_response(json.loads(data))
        for vuln in parsed:
            vuln.source = f"{source}-cache"
        return parsed
