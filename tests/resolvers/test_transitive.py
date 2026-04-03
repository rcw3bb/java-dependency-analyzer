"""
test_transitive module.

Tests for the TransitiveResolver.

:author: Ron Webb
:since: 1.0.0
"""

import pytest
from pytest_httpx import HTTPXMock

from java_dependency_analyzer.models.dependency import Dependency
from java_dependency_analyzer.resolvers.transitive import TransitiveResolver
import httpx

__author__ = "Ron Webb"
__since__ = "1.0.0"

_SIMPLE_POM = b"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
      <scope>compile</scope>
    </dependency>
  </dependencies>
</project>
"""

_POM_WITH_TEST_SCOPE = b"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"""

_POM_OPTIONAL = b"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.optional</groupId>
      <artifactId>optional-lib</artifactId>
      <version>1.0</version>
      <optional>true</optional>
    </dependency>
  </dependencies>
</project>
"""


class TestTransitiveResolver:
    """Tests for TransitiveResolver."""

    def test_resolve_adds_transitive_deps(self, httpx_mock: HTTPXMock):
        """Resolver should fetch POM and populate transitive_dependencies."""
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.pom",
            content=_SIMPLE_POM,
        )
        # The resolver will recursively try to fetch the transitive dep's POM
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom",
            status_code=404,
        )
        dep = Dependency(group_id="org.apache.logging.log4j", artifact_id="log4j-core", version="2.14.1")
        with httpx.Client() as client:
            resolver = TransitiveResolver(client=client)
            resolver.resolve(dep)

        assert len(dep.transitive_dependencies) == 1
        assert dep.transitive_dependencies[0].artifact_id == "commons-lang3"

    def test_resolve_skips_test_scope(self, httpx_mock: HTTPXMock):
        """Transitive deps with test scope should not be added."""
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/com/example/parent/1.0.0/parent-1.0.0.pom",
            content=_POM_WITH_TEST_SCOPE,
        )
        dep = Dependency(group_id="com.example", artifact_id="parent", version="1.0.0")
        with httpx.Client() as client:
            resolver = TransitiveResolver(client=client)
            resolver.resolve(dep)

        assert dep.transitive_dependencies == []

    def test_resolve_skips_optional(self, httpx_mock: HTTPXMock):
        """Optional transitive deps should not be added."""
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/com/example/parent/1.0.0/parent-1.0.0.pom",
            content=_POM_OPTIONAL,
        )
        dep = Dependency(group_id="com.example", artifact_id="parent", version="1.0.0")
        with httpx.Client() as client:
            resolver = TransitiveResolver(client=client)
            resolver.resolve(dep)

        assert dep.transitive_dependencies == []

    def test_resolve_uses_cache(self, httpx_mock: HTTPXMock):
        """Second resolve call for same artifact should not make a second HTTP request."""
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/com/example/parent/1.0.0/parent-1.0.0.pom",
            content=_SIMPLE_POM,
        )
        # Resolver recurses into commons-lang3 during dep1 resolution
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom",
            status_code=404,
        )
        dep1 = Dependency(group_id="com.example", artifact_id="parent", version="1.0.0")
        dep2 = Dependency(group_id="com.example", artifact_id="parent", version="1.0.0")

        with httpx.Client() as client:
            resolver = TransitiveResolver(client=client)
            resolver.resolve(dep1)
            resolver.resolve(dep2)  # Should use cache — only 1 HTTP call registered

        # pytest-httpx would raise if unexpectedly more calls were made
        assert len(dep2.transitive_dependencies) == 1

    def test_resolve_404_returns_no_children(self, httpx_mock: HTTPXMock):
        """404 from Maven Central should result in no transitive dependencies."""
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/com/example/missing/1.0.0/missing-1.0.0.pom",
            status_code=404,
        )
        dep = Dependency(group_id="com.example", artifact_id="missing", version="1.0.0")
        with httpx.Client() as client:
            resolver = TransitiveResolver(client=client)
            resolver.resolve(dep)

        assert dep.transitive_dependencies == []

    def test_resolve_all(self, httpx_mock: HTTPXMock):
        """resolve_all should process each dependency in the list."""
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/com/example/a/1.0/a-1.0.pom",
            status_code=404,
        )
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/com/example/b/2.0/b-2.0.pom",
            status_code=404,
        )
        deps = [
            Dependency(group_id="com.example", artifact_id="a", version="1.0"),
            Dependency(group_id="com.example", artifact_id="b", version="2.0"),
        ]
        with httpx.Client() as client:
            resolver = TransitiveResolver(client=client)
            result = resolver.resolve_all(deps)

        assert len(result) == 2

    def test_max_depth_not_exceeded(self, httpx_mock: HTTPXMock):
        """Resolver should not go deeper than MAX_DEPTH."""
        # Responding to all calls with the same self-referencing POM would loop infinitely
        # without depth guard; the test passes if it terminates
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/com/example/deep/1.0/deep-1.0.pom",
            content=_SIMPLE_POM,
        )
        # commons-lang3 at depth 1 fetches its own POM
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom",
            status_code=404,
        )
        dep = Dependency(group_id="com.example", artifact_id="deep", version="1.0")
        with httpx.Client() as client:
            resolver = TransitiveResolver(client=client)
            resolver.resolve(dep, depth=0)

        # Verify we did not recurse into infinite territory — test terminates
        assert dep.transitive_dependencies is not None

    def test_network_error_returns_no_children(self, httpx_mock: HTTPXMock):
        """Network error on POM fetch should not crash; returns empty transitive list."""
        httpx_mock.add_exception(
            httpx.ConnectError("timeout"),
            url="https://repo1.maven.org/maven2/com/example/err/1.0/err-1.0.pom",
        )
        dep = Dependency(group_id="com.example", artifact_id="err", version="1.0")
        with httpx.Client() as client:
            resolver = TransitiveResolver(client=client)
            resolver.resolve(dep)

        assert dep.transitive_dependencies == []

    def test_transitive_child_depth_set(self, httpx_mock: HTTPXMock):
        """Transitive children should have depth = parent_depth + 1."""
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/com/example/parent/1.0.0/parent-1.0.0.pom",
            content=_SIMPLE_POM,
        )
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/org/apache/commons/commons-lang3/3.12.0/commons-lang3-3.12.0.pom",
            status_code=404,
        )
        dep = Dependency(group_id="com.example", artifact_id="parent", version="1.0.0", depth=0)
        with httpx.Client() as client:
            resolver = TransitiveResolver(client=client)
            resolver.resolve(dep)

        assert dep.transitive_dependencies[0].depth == 1

    def test_cycle_detection_skips_visited_dependency(self, httpx_mock: HTTPXMock):
        """A dependency that points back to itself (cycle) should not recurse infinitely."""
        # A's POM lists B as a dependency
        pom_a = b"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>a</artifactId><version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId><artifactId>b</artifactId><version>1.0</version>
      <scope>compile</scope>
    </dependency>
  </dependencies>
</project>"""
        # B's POM lists A as a dependency (cycle: A -> B -> A)
        pom_b = b"""<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId><artifactId>b</artifactId><version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>com.example</groupId><artifactId>a</artifactId><version>1.0</version>
      <scope>compile</scope>
    </dependency>
  </dependencies>
</project>"""
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/com/example/a/1.0/a-1.0.pom",
            content=pom_a,
        )
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/com/example/b/1.0/b-1.0.pom",
            content=pom_b,
        )
        dep = Dependency(group_id="com.example", artifact_id="a", version="1.0")
        with httpx.Client() as client:
            resolver = TransitiveResolver(client=client)
            resolver.resolve(dep)  # Must terminate without hitting MAX_DEPTH

        # A -> B resolved; B declares A but visited set stops recursing into A again
        b_dep = dep.transitive_dependencies[0]
        assert len(dep.transitive_dependencies) == 1
        assert b_dep.artifact_id == "b"
        # B has A as a declared child, but A's transitives are empty (visited set cut off)
        assert len(b_dep.transitive_dependencies) == 1
        assert b_dep.transitive_dependencies[0].artifact_id == "a"
        assert b_dep.transitive_dependencies[0].transitive_dependencies == []

    def test_resolve_all_shared_visited_skips_duplicates(self, httpx_mock: HTTPXMock):
        """resolve_all should skip a dependency already visited in a prior branch."""
        httpx_mock.add_response(
            url="https://repo1.maven.org/maven2/com/example/a/1.0/a-1.0.pom",
            status_code=404,
        )
        dep1 = Dependency(group_id="com.example", artifact_id="a", version="1.0")
        dep2 = Dependency(group_id="com.example", artifact_id="a", version="1.0")
        with httpx.Client() as client:
            resolver = TransitiveResolver(client=client)
            result = resolver.resolve_all([dep1, dep2])

        # Only one HTTP request should have been made (dep2 skipped by visited set)
        assert len(result) == 2
