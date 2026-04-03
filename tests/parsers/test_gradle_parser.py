"""
test_gradle_parser module.

Tests for the Gradle build file parser (Groovy and Kotlin DSL).

:author: Ron Webb
:since: 1.0.0
"""

from pathlib import Path

import pytest

from java_dependency_analyzer.parsers.gradle_parser import GradleParser

__author__ = "Ron Webb"
__since__ = "1.0.0"

_FIXTURES = Path(__file__).parent.parent / "fixtures"


class TestGradleParser:
    """Tests for GradleParser."""

    def setup_method(self):
        """Create a fresh parser instance per test."""
        self.parser = GradleParser()

    def test_groovy_shorthand_deps(self):
        """Groovy shorthand notation should parse 4 unique runtime deps."""
        deps = self.parser.parse(str(_FIXTURES / "sample_build.gradle"))
        artifacts = {d.artifact_id for d in deps}
        assert "log4j-core" in artifacts
        assert "guava" in artifacts
        assert "postgresql" in artifacts
        assert "spring-core" in artifacts

    def test_groovy_excludes_test_dep(self):
        """testImplementation scope should be excluded."""
        deps = self.parser.parse(str(_FIXTURES / "sample_build.gradle"))
        assert not any(d.artifact_id == "junit" for d in deps)

    def test_groovy_deduplication(self):
        """Duplicate declarations should result in a single dependency entry."""
        deps = self.parser.parse(str(_FIXTURES / "sample_build.gradle"))
        log4j_count = sum(1 for d in deps if d.artifact_id == "log4j-core")
        assert log4j_count == 1

    def test_groovy_skips_unresolved_vars(self):
        """Dependencies with unresolved ${variable} versions should be skipped."""
        deps = self.parser.parse(str(_FIXTURES / "sample_build.gradle"))
        assert not any(d.artifact_id == "some-lib" for d in deps)

    def test_kotlin_shorthand_deps(self):
        """Kotlin DSL shorthand should parse the same runtime deps."""
        deps = self.parser.parse(str(_FIXTURES / "sample_build.gradle.kts"))
        artifacts = {d.artifact_id for d in deps}
        assert "log4j-core" in artifacts
        assert "guava" in artifacts
        assert "postgresql" in artifacts
        assert "spring-core" in artifacts

    def test_kotlin_excludes_test_dep(self):
        """testImplementation in Kotlin DSL should be excluded."""
        deps = self.parser.parse(str(_FIXTURES / "sample_build.gradle.kts"))
        assert not any(d.artifact_id == "junit" for d in deps)

    def test_kotlin_deduplication(self):
        """Duplicate Kotlin DSL declarations should result in one entry."""
        deps = self.parser.parse(str(_FIXTURES / "sample_build.gradle.kts"))
        log4j_count = sum(1 for d in deps if d.artifact_id == "log4j-core")
        assert log4j_count == 1

    def test_version_extracted_correctly(self):
        """Version should be extracted correctly from shorthand notation."""
        deps = self.parser.parse(str(_FIXTURES / "sample_build.gradle"))
        log4j = next(d for d in deps if d.artifact_id == "log4j-core")
        assert log4j.version == "2.14.1"

    def test_group_id_extracted_correctly(self):
        """GroupId should be extracted correctly."""
        deps = self.parser.parse(str(_FIXTURES / "sample_build.gradle"))
        log4j = next(d for d in deps if d.artifact_id == "log4j-core")
        assert log4j.group_id == "org.apache.logging.log4j"

    def test_file_not_found_returns_empty(self):
        """Non-existent file should return empty list, not raise."""
        deps = self.parser.parse("/nonexistent/build.gradle")
        assert deps == []

    def test_inline_comment_ignored(self, tmp_path):
        """Dependencies after // comments should not be parsed."""
        gradle = tmp_path / "build.gradle"
        gradle.write_text(
            "dependencies {\n"
            "    // implementation 'some.group:some-artifact:1.0'\n"
            "    implementation 'real.group:real-artifact:2.0'\n"
            "}\n",
            encoding="utf-8",
        )
        deps = self.parser.parse(str(gradle))
        assert len(deps) == 1
        assert deps[0].artifact_id == "real-artifact"

    def test_block_comment_ignored(self, tmp_path):
        """Dependencies inside block comments should not be parsed."""
        gradle = tmp_path / "build.gradle"
        gradle.write_text(
            "dependencies {\n"
            "    /* implementation 'ignored.group:ignored-artifact:1.0' */\n"
            "    implementation 'real.group:real-artifact:2.0'\n"
            "}\n",
            encoding="utf-8",
        )
        deps = self.parser.parse(str(gradle))
        assert len(deps) == 1
        assert deps[0].artifact_id == "real-artifact"

    def test_empty_file_returns_empty(self, tmp_path):
        """Empty Gradle file should return an empty list."""
        gradle = tmp_path / "build.gradle"
        gradle.write_text("", encoding="utf-8")
        deps = self.parser.parse(str(gradle))
        assert deps == []

    def test_groovy_resolves_ext_vars(self):
        """Dependencies whose version is an ext-block variable should be resolved."""
        deps = self.parser.parse(str(_FIXTURES / "sample_build.gradle"))
        assert any(d.artifact_id == "snakeyaml" for d in deps)
        snakeyaml = next(d for d in deps if d.artifact_id == "snakeyaml")
        assert snakeyaml.version == "3.9.1"
        assert snakeyaml.group_id == "org.yaml"

    def test_kotlin_resolves_val_vars(self):
        """Dependencies whose version is a val variable should be resolved."""
        deps = self.parser.parse(str(_FIXTURES / "sample_build.gradle.kts"))
        assert any(d.artifact_id == "snakeyaml" for d in deps)
        snakeyaml = next(d for d in deps if d.artifact_id == "snakeyaml")
        assert snakeyaml.version == "3.9.1"
        assert snakeyaml.group_id == "org.yaml"

    def test_unresolved_var_still_skipped(self, tmp_path):
        """A ${variable} with no matching definition should still be skipped."""
        gradle = tmp_path / "build.gradle"
        gradle.write_text(
            'dependencies {\n'
            '    implementation "com.example:unknown-lib:${undeclaredVar}"\n'
            '}\n',
            encoding="utf-8",
        )
        deps = self.parser.parse(str(gradle))
        assert not any(d.artifact_id == "unknown-lib" for d in deps)
