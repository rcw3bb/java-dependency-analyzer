"""
test_jar_resolver module.

Tests for :class:`JarCoordinateResolver`.

:author: Ron Webb
:since: 1.6.0
"""

import hashlib
import re

import httpx
import pytest
from pytest_httpx import HTTPXMock

from java_dependency_analyzer.resolvers import jar_resolver
from java_dependency_analyzer.resolvers.jar_resolver import JarCoordinateResolver

__author__ = "Ron Webb"
__since__ = "1.6.0"

_SEARCH = r"https://central\.sonatype\.com/solrsearch/select\?"
_SHA1_QUERY = re.compile(_SEARCH + r".*q=1%3A")
_NAME_QUERY = re.compile(_SEARCH + r".*q=a%3A")
_GROUP_QUERY = re.compile(_SEARCH + r".*q=g%3A")

_GUAVA = {"g": "com.google.guava", "a": "guava", "v": "31.1-jre"}
_OTHER = {"g": "io.github.tanyaofei", "a": "guava", "v": "31.1-jre"}


def _docs(*docs: dict) -> dict:
    """Build a search API response body."""
    return {"response": {"numFound": len(docs), "docs": list(docs)}}


class TestJarCoordinateResolver:
    """Tests for ``JarCoordinateResolver.resolve``."""

    @pytest.fixture(autouse=True)
    def _no_sleep(self, monkeypatch):
        """Skip the retry back-off delay."""
        monkeypatch.setattr(jar_resolver.time, "sleep", lambda _seconds: None)

    def test_retries_after_connection_reset(self, httpx_mock: HTTPXMock):
        """A dropped connection should be retried and then succeed."""
        httpx_mock.add_exception(httpx.ReadError("connection forcibly closed"))
        httpx_mock.add_response(url=_NAME_QUERY, json=_docs(_GUAVA))

        dep = JarCoordinateResolver().resolve("guava-31.1-jre.jar")

        assert dep is not None
        assert len(httpx_mock.get_requests()) == 2

    def test_retries_after_server_error(self, httpx_mock: HTTPXMock):
        """A transient 503 should be retried and then succeed."""
        httpx_mock.add_response(url=_NAME_QUERY, status_code=503)
        httpx_mock.add_response(url=_NAME_QUERY, json=_docs(_GUAVA))

        assert JarCoordinateResolver().resolve("guava-31.1-jre.jar") is not None

    def test_gives_up_after_max_attempts(self, httpx_mock: HTTPXMock):
        """Persistent failures should stop after the maximum number of attempts."""
        for _ in range(jar_resolver._MAX_ATTEMPTS):  # pylint: disable=protected-access
            httpx_mock.add_exception(httpx.ReadError("reset"))

        assert JarCoordinateResolver().resolve("guava-31.1-jre.jar") is None
        assert (
            len(httpx_mock.get_requests()) == jar_resolver._MAX_ATTEMPTS
        )  # pylint: disable=protected-access

    def test_resolves_existing_file_by_sha1(self, httpx_mock: HTTPXMock, tmp_path):
        """An existing jar should be identified through its SHA-1 checksum."""
        jar = tmp_path / "guava-31.1-jre.jar"
        jar.write_bytes(b"content")
        httpx_mock.add_response(url=_SHA1_QUERY, json=_docs(_GUAVA))

        dep = JarCoordinateResolver().resolve(str(jar))

        assert dep is not None
        assert dep.coordinates == "com.google.guava:guava:31.1-jre"
        request = httpx_mock.get_requests()[0]
        assert hashlib.sha1(b"content").hexdigest() in request.url.params["q"]

    def test_checksum_with_several_matches_prefers_file_name(
        self, httpx_mock: HTTPXMock, tmp_path
    ):
        """When a checksum matches several coordinates the file name picks one."""
        jar = tmp_path / "log4j-api-2.20.0.jar"
        jar.write_bytes(b"content")
        wrong = {"g": "org.apache.logging.log4j", "a": "log4j-api", "v": "2.2"}
        right = {"g": "org.apache.logging.log4j", "a": "log4j-api", "v": "2.20.0"}
        httpx_mock.add_response(url=_SHA1_QUERY, json=_docs(wrong, right))

        dep = JarCoordinateResolver().resolve(str(jar))

        assert dep is not None
        assert dep.version == "2.20.0"

    def test_falls_back_to_file_name_when_sha1_unknown(
        self, httpx_mock: HTTPXMock, tmp_path
    ):
        """An unknown checksum should fall back to the file name search."""
        jar = tmp_path / "guava-31.1-jre.jar"
        jar.write_bytes(b"content")
        httpx_mock.add_response(url=_SHA1_QUERY, json=_docs())
        httpx_mock.add_response(url=_NAME_QUERY, json=_docs(_GUAVA))

        dep = JarCoordinateResolver().resolve(str(jar))

        assert dep is not None
        assert dep.artifact_id == "guava"

    def test_resolves_missing_file_by_name(self, httpx_mock: HTTPXMock):
        """A jar that is not on disk should be searched by artifact and version."""
        httpx_mock.add_response(url=_NAME_QUERY, json=_docs(_GUAVA))

        dep = JarCoordinateResolver().resolve("commons-lang3-3.12.0.jar")

        assert dep is not None
        query = httpx_mock.get_requests()[0].url.params["q"]
        assert query == 'a:"commons-lang3" AND v:"3.12.0"'

    def test_relative_jar_found_in_base_dir(self, httpx_mock: HTTPXMock, tmp_path):
        """A relative jar should be located beside the list file."""
        (tmp_path / "guava-31.1-jre.jar").write_bytes(b"x")
        httpx_mock.add_response(url=_SHA1_QUERY, json=_docs(_GUAVA))

        dep = JarCoordinateResolver().resolve("guava-31.1-jre.jar", tmp_path)

        assert dep is not None

    def test_multiple_matches_use_first(self, httpx_mock: HTTPXMock):
        """Several name matches should resolve to the first one."""
        httpx_mock.add_response(url=_NAME_QUERY, json=_docs(_OTHER, _GUAVA))

        dep = JarCoordinateResolver().resolve("guava-31.1-jre.jar")

        assert dep is not None
        assert dep.group_id == "io.github.tanyaofei"

    def test_no_match_returns_none(self, httpx_mock: HTTPXMock):
        """No search result should return None."""
        httpx_mock.add_response(url=_NAME_QUERY, json=_docs())

        assert JarCoordinateResolver().resolve("unknown-1.0.jar") is None

    def test_unparseable_name_returns_none(self):
        """A file name without a version should return None without any request."""
        assert JarCoordinateResolver().resolve("noversion.jar") is None

    def test_http_error_returns_none(self, httpx_mock: HTTPXMock):
        """A non-200 search response should return None."""
        for _ in range(jar_resolver._MAX_ATTEMPTS):  # pylint: disable=protected-access
            httpx_mock.add_response(url=_NAME_QUERY, status_code=500)

        assert JarCoordinateResolver().resolve("guava-31.1-jre.jar") is None

    def test_network_error_returns_none(self, httpx_mock: HTTPXMock):
        """A network failure should return None."""
        for _ in range(jar_resolver._MAX_ATTEMPTS):  # pylint: disable=protected-access
            httpx_mock.add_exception(httpx.ConnectError("boom"))

        assert JarCoordinateResolver().resolve("guava-31.1-jre.jar") is None

    def test_invalid_json_returns_none(self, httpx_mock: HTTPXMock):
        """A malformed response body should return None."""
        httpx_mock.add_response(url=_NAME_QUERY, text="not json")

        assert JarCoordinateResolver().resolve("guava-31.1-jre.jar") is None

    def test_docs_missing_coordinates_are_ignored(self, httpx_mock: HTTPXMock):
        """Docs without group, artifact, or version should be filtered out."""
        httpx_mock.add_response(url=_NAME_QUERY, json=_docs({"g": "x"}))

        assert JarCoordinateResolver().resolve("guava-31.1-jre.jar") is None


class TestJarCoordinateResolverGroupMapping:
    """Tests for ``JarCoordinateResolver`` with a group mapping."""

    def test_mapped_artifact_searched_with_group(self, httpx_mock: HTTPXMock):
        """A mapped artifact should be searched under its mapped group."""
        httpx_mock.add_response(url=_GROUP_QUERY, json=_docs(_GUAVA))
        resolver = JarCoordinateResolver(group_mapping={"guava": ["com.google.guava"]})

        dep = resolver.resolve("guava-31.1-jre.jar")

        assert dep is not None
        assert dep.coordinates == "com.google.guava:guava:31.1-jre"
        query = httpx_mock.get_requests()[0].url.params["q"]
        assert query == 'g:"com.google.guava" AND a:"guava" AND v:"31.1-jre"'

    def test_mapping_skips_checksum_lookup(self, httpx_mock: HTTPXMock, tmp_path):
        """A mapped hit should not search the checksum even when the file exists."""
        jar = tmp_path / "guava-31.1-jre.jar"
        jar.write_bytes(b"content")
        httpx_mock.add_response(url=_GROUP_QUERY, json=_docs(_GUAVA))
        resolver = JarCoordinateResolver(group_mapping={"guava": ["com.google.guava"]})

        assert resolver.resolve(str(jar)) is not None
        assert len(httpx_mock.get_requests()) == 1

    def test_mapped_groups_tried_in_order(self, httpx_mock: HTTPXMock):
        """The next group is tried when the previous one has no match."""
        httpx_mock.add_response(url=_GROUP_QUERY, json=_docs())
        httpx_mock.add_response(url=_GROUP_QUERY, json=_docs(_GUAVA))
        resolver = JarCoordinateResolver(
            group_mapping={"guava": ["io.unknown", "com.google.guava"]}
        )

        dep = resolver.resolve("guava-31.1-jre.jar")

        assert dep is not None
        assert dep.group_id == "com.google.guava"
        assert len(httpx_mock.get_requests()) == 2

    def test_docs_of_other_groups_are_ignored(self, httpx_mock: HTTPXMock):
        """Only docs that match the mapped group, artifact and version count."""
        httpx_mock.add_response(url=_GROUP_QUERY, json=_docs(_OTHER))
        httpx_mock.add_response(url=_NAME_QUERY, json=_docs(_GUAVA))
        resolver = JarCoordinateResolver(group_mapping={"guava": ["com.google.guava"]})

        dep = resolver.resolve("guava-31.1-jre.jar")

        assert dep is not None
        assert dep.group_id == "com.google.guava"

    def test_mapped_miss_falls_back_to_best_match(self, httpx_mock: HTTPXMock):
        """No mapped match should fall back to the file name search."""
        httpx_mock.add_response(url=_GROUP_QUERY, json=_docs())
        httpx_mock.add_response(url=_NAME_QUERY, json=_docs(_OTHER))
        resolver = JarCoordinateResolver(group_mapping={"guava": ["com.google.guava"]})

        dep = resolver.resolve("guava-31.1-jre.jar")

        assert dep is not None
        assert dep.group_id == "io.github.tanyaofei"

    def test_unmapped_artifact_uses_best_match(self, httpx_mock: HTTPXMock):
        """An artifact absent from the mapping should use the existing search."""
        httpx_mock.add_response(url=_NAME_QUERY, json=_docs(_GUAVA))
        resolver = JarCoordinateResolver(group_mapping={"other": ["org.other"]})

        dep = resolver.resolve("guava-31.1-jre.jar")

        assert dep is not None
        assert len(httpx_mock.get_requests()) == 1
        query = httpx_mock.get_requests()[0].url.params["q"]
        assert query == 'a:"guava" AND v:"31.1-jre"'
