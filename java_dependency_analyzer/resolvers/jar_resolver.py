"""
jar_resolver module.

Maps jar files to Maven coordinates by querying the Maven Central search API,
either through an optional artifact-to-group mapping, by the SHA-1 checksum of
the file, or by the artifact and version parsed from the jar file name.

:author: Ron Webb
:since: 1.6.0
"""

import hashlib
import os
import re
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

import httpx
from dotenv import load_dotenv

from ..models.dependency import Dependency
from ..util.logger import setup_logger

__author__ = "Ron Webb"
__since__ = "1.6.0"

load_dotenv()

_logger = setup_logger(__name__)

_MAVEN_SEARCH_URL = os.getenv(
    "MAVEN_SEARCH_URL", "https://central.sonatype.com/solrsearch/select"
)

# Splits "artifact-version" at the first hyphen that is followed by a digit
_JAR_NAME_RE = re.compile(r"^(?P<artifact>.+?)-(?P<version>\d.*)$")

_MAX_ROWS = 20

_MAX_ATTEMPTS = 4
_RETRY_BACKOFF_SECONDS = 1.0
_RETRY_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


class JarCoordinateResolver:
    """
    Resolves the Maven coordinates of a jar using the Maven Central search API.

    When the artifact parsed from the file name (``<artifact>-<version>.jar``) is
    in the optional group mapping, it is searched under each mapped group first.
    Otherwise, or when the mapping yields no match, the SHA-1 checksum is
    searched when the jar exists on disk, then the artifact id and version
    parsed from the file name.

    :author: Ron Webb
    :since: 1.6.0
    """

    def __init__(
        self,
        client: httpx.Client | None = None,
        group_mapping: Mapping[str, Sequence[str]] | None = None,
    ) -> None:
        """
        Initialise the resolver with an optional shared httpx client and group mapping.

        *group_mapping* maps an artifact id to the groups to try for it.

        :author: Ron Webb
        :since: 1.6.0
        """
        self._client = client or httpx.Client(timeout=30)
        self._group_mapping = group_mapping or {}

    def resolve(self, jar: str, base_dir: Path | None = None) -> Dependency | None:
        """
        Return the :class:`Dependency` for *jar*, or *None* when it cannot be identified.

        *jar* may be an absolute path or a file name.  A relative *jar* is looked
        up in *base_dir* (when given) and then in the current working directory
        to find the file on disk.

        :author: Ron Webb
        :since: 1.6.0
        """
        mapped = self._resolve_by_mapping(Path(jar).name)
        if mapped is not None:
            return mapped

        file_path = self._locate(jar, base_dir)
        if file_path is not None:
            docs = self._search(f'1:"{self._sha1(file_path)}"')
            if docs:
                return self._to_dependency(self._best_match(docs, Path(jar).name))
            _logger.debug("No checksum match for %s; trying file name", file_path)

        return self._resolve_by_name(Path(jar).name)

    @staticmethod
    def _parse_file_name(file_name: str) -> tuple[str, str] | None:
        """
        Return the ``(artifact, version)`` parsed from *file_name*, or *None*.

        :author: Ron Webb
        :since: 1.6.0
        """
        match = _JAR_NAME_RE.match(Path(file_name).stem)
        if not match:
            return None
        return match.group("artifact"), match.group("version")

    def _resolve_by_mapping(self, file_name: str) -> Dependency | None:
        """
        Resolve *file_name* through the group mapping, or return *None* when unmapped.

        Each group mapped to the artifact is searched in order; the first group
        that has the artifact at the file name's version wins.

        :author: Ron Webb
        :since: 1.6.0
        """
        parsed = self._parse_file_name(file_name)
        if parsed is None:
            return None
        artifact, version = parsed
        for group in self._group_mapping.get(artifact, ()):
            docs = self._search(f'g:"{group}" AND a:"{artifact}" AND v:"{version}"')
            doc = next(
                (
                    d
                    for d in docs
                    if (d["g"], d["a"], d["v"]) == (group, artifact, version)
                ),
                None,
            )
            if doc is not None:
                return self._to_dependency(doc)
        if artifact in self._group_mapping:
            _logger.warning(
                "No Maven Central match for mapped artifact '%s' (%s); "
                "falling back to best match",
                artifact,
                file_name,
            )
        return None

    @staticmethod
    def _best_match(docs: list[dict], file_name: str) -> dict:
        """
        Return the doc that agrees with the ``<artifact>-<version>.jar`` *file_name*.

        A checksum can match several indexed coordinates (for example
        ``log4j-api`` 2.2 and 2.20.0 for the same file), so the file name is used
        to choose among them.  The first doc is returned when none agrees.

        :author: Ron Webb
        :since: 1.6.0
        """
        parsed = JarCoordinateResolver._parse_file_name(file_name)
        if parsed:
            artifact, version = parsed
            for doc in docs:
                if doc["a"] == artifact and doc["v"] == version:
                    return doc
        return docs[0]

    @staticmethod
    def _locate(jar: str, base_dir: Path | None) -> Path | None:
        """
        Return the existing file for *jar*, or *None* when it is not on disk.

        :author: Ron Webb
        :since: 1.6.0
        """
        path = Path(jar)
        if path.is_absolute():
            return path if path.is_file() else None
        candidates = [Path.cwd() / path]
        if base_dir is not None:
            candidates.insert(0, base_dir / path)
        return next((c for c in candidates if c.is_file()), None)

    @staticmethod
    def _sha1(file_path: Path) -> str:
        """
        Return the hexadecimal SHA-1 checksum of *file_path*.

        :author: Ron Webb
        :since: 1.6.0
        """
        digest = hashlib.sha1()  # nosec B324 - Maven Central indexes SHA-1 only
        with open(file_path, "rb") as stream:
            for chunk in iter(lambda: stream.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _resolve_by_name(self, file_name: str) -> Dependency | None:
        """
        Resolve coordinates from the ``<artifact>-<version>.jar`` *file_name*.

        :author: Ron Webb
        :since: 1.6.0
        """
        parsed = self._parse_file_name(file_name)
        if parsed is None:
            _logger.warning("Cannot derive artifact and version from '%s'", file_name)
            return None
        artifact, version = parsed
        docs = self._search(f'a:"{artifact}" AND v:"{version}"')
        if not docs:
            _logger.warning("No Maven Central match found for '%s'", file_name)
            return None
        if len(docs) > 1:
            _logger.warning(
                "%d matches found for '%s'; using %s:%s:%s",
                len(docs),
                file_name,
                docs[0].get("g"),
                docs[0].get("a"),
                docs[0].get("v"),
            )
        return self._to_dependency(docs[0])

    def _search(self, query: str) -> list[dict]:
        """
        Run *query* against the Maven Central search API and return the matching docs.

        Returns an empty list on network or response errors.

        :author: Ron Webb
        :since: 1.6.0
        """
        response = self._get_with_retry(query)
        if response is None:
            return []
        if response.status_code != 200:
            _logger.warning(
                "Maven Central search failed (HTTP %d) for %s",
                response.status_code,
                query,
            )
            return []
        try:
            docs = response.json().get("response", {}).get("docs", [])
        except ValueError as exc:
            _logger.warning("Maven Central search error for %s: %s", query, exc)
            return []
        return [d for d in docs if d.get("g") and d.get("a") and d.get("v")]

    def _get_with_retry(self, query: str) -> httpx.Response | None:
        """
        Send the search request, retrying transient failures with a growing delay.

        Connection errors (e.g. a connection reset by the remote host), timeouts,
        HTTP 429 and HTTP 5xx responses are retried up to ``_MAX_ATTEMPTS`` times.
        Returns the last response, or *None* when every attempt raised an error.

        :author: Ron Webb
        :since: 1.6.0
        """
        params = {"q": query, "rows": str(_MAX_ROWS), "wt": "json"}
        response: httpx.Response | None = None
        for attempt in range(1, _MAX_ATTEMPTS + 1):
            error: httpx.RequestError | None = None
            try:
                response = self._client.get(_MAVEN_SEARCH_URL, params=params)
            except httpx.RequestError as exc:
                response, error = None, exc
            if error is None and response.status_code not in _RETRY_STATUS_CODES:
                return response
            if attempt == _MAX_ATTEMPTS:
                if error is not None:
                    _logger.warning(
                        "Maven Central search error for %s: %s", query, error
                    )
                return response
            _logger.debug(
                "Transient Maven Central failure for %s (attempt %d/%d): %s",
                query,
                attempt,
                _MAX_ATTEMPTS,
                error or response.status_code,
            )
            time.sleep(_RETRY_BACKOFF_SECONDS * attempt)
        return response

    @staticmethod
    def _to_dependency(doc: dict) -> Dependency:
        """
        Convert a search *doc* into a :class:`Dependency`.

        :author: Ron Webb
        :since: 1.6.0
        """
        return Dependency(
            group_id=doc["g"],
            artifact_id=doc["a"],
            version=doc["v"],
            scope="compile",
        )
