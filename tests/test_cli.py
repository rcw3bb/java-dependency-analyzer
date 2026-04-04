"""
test_cli module.

Tests for the CLI entry point.

:author: Ron Webb
:since: 1.0.0
"""

import re
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner
from pytest_httpx import HTTPXMock

from java_dependency_analyzer.cli import main

__author__ = "Ron Webb"
__since__ = "1.0.0"

_FIXTURES = Path(__file__).parent / "fixtures"

_OSV_EMPTY = {"vulns": []}
_GHSA_EMPTY: list = []

_GHSA_VULN = [
    {
        "ghsa_id": "GHSA-jfh8-c2jp-hdp9",
        "cve_id": "CVE-2021-44228",
        "summary": "Remote code execution in Apache Log4j2",
        "html_url": "https://github.com/advisories/GHSA-jfh8-c2jp-hdp9",
        "severity": "critical",
        "cvss": None,
        "cvss_severities": {"cvss_v3": None, "cvss_v4": None},
        "vulnerabilities": [
            {"vulnerable_version_range": ">= 2.0-beta9, < 2.15.0"}
        ],
    }
]

_OSV_VULN = {
    "vulns": [
        {
            "id": "CVE-2021-44228",
            "summary": "Remote code execution in Apache Log4j2",
            "severity": [{"type": "CVSS_V3", "score": "CRITICAL"}],
            "affected": [
                {
                    "ranges": [
                        {
                            "type": "ECOSYSTEM",
                            "events": [
                                {"introduced": "2.0-beta9"},
                                {"fixed": "2.15.0"},
                            ],
                        }
                    ],
                    "versions": [],
                }
            ],
            "references": [
                {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"}
            ],
        }
    ]
}


class TestMavenSubcommand:
    """Tests for the ``maven`` subcommand."""

    @pytest.fixture(autouse=True)
    def _patch_db(self, tmp_path, monkeypatch):
        """Redirect the cache database to a temporary directory for test isolation."""
        monkeypatch.setattr(
            "java_dependency_analyzer.cache.db.get_db_path",
            lambda: tmp_path / "cache.db",
        )

    def _mock_all_http(self, httpx_mock: HTTPXMock) -> None:
        """Register catch-all HTTP mocks so no real network calls are made."""
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/query",
            json=_OSV_EMPTY,
            is_reusable=True,
            is_optional=True,
        )
        httpx_mock.add_response(
            url=re.compile(r"https://api\.github\.com/advisories"),
            json=_GHSA_EMPTY,
            is_reusable=True,
            is_optional=True,
        )

    def test_cli_json_output(self, httpx_mock: HTTPXMock, tmp_path):
        """maven subcommand should create a JSON report for pom.xml."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "sample_pom-report.json").exists()

    def test_cli_html_output(self, httpx_mock: HTTPXMock, tmp_path):
        """maven subcommand should create an HTML report for pom.xml."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "html",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "sample_pom-report.html").exists()

    def test_cli_all_output(self, httpx_mock: HTTPXMock, tmp_path):
        """maven subcommand with --output-format all should create both reports."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "all",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "sample_pom-report.json").exists()
        assert (tmp_path / "sample_pom-report.html").exists()

    def test_cli_verbose_flag(self, httpx_mock: HTTPXMock, tmp_path):
        """--verbose flag should produce additional output."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
                "--verbose",
            ],
        )
        assert result.exit_code == 0
        assert "Parsing" in result.output

    def test_cli_scan_complete_message(self, httpx_mock: HTTPXMock, tmp_path):
        """CLI should print a scan complete summary at the end."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert "Scan complete" in result.output

    def test_rebuild_cache_deletes_database(self, httpx_mock: HTTPXMock, tmp_path):
        """--rebuild-cache should delete the cache database file if it exists."""
        self._mock_all_http(httpx_mock)
        db_path = tmp_path / "cache.db"
        db_path.touch()
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
                "--rebuild-cache",
                "--cache-ttl", "0",
            ],
        )
        assert result.exit_code == 0, result.output
        assert not db_path.exists()

    def test_rebuild_cache_verbose_prints_message(self, httpx_mock: HTTPXMock, tmp_path):
        """--rebuild-cache with --verbose should print confirmation."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
                "--rebuild-cache",
                "--cache-ttl", "0",
                "--verbose",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "cache cleared" in result.output.lower()

    def test_cache_ttl_zero_disables_caching(self, httpx_mock: HTTPXMock, tmp_path):
        """--cache-ttl 0 should run without writing to the database."""
        self._mock_all_http(httpx_mock)
        db_path = tmp_path / "cache.db"
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
                "--cache-ttl", "0",
            ],
        )
        assert not db_path.exists()

    def test_osv_not_called_when_ghsa_finds_results(self, httpx_mock: HTTPXMock, tmp_path):
        """OSV should not be queried when GHSA finds vulnerabilities."""
        httpx_mock.add_response(
            url=re.compile(r"https://api\.github\.com/advisories"),
            json=_GHSA_VULN,
            is_reusable=True,
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
                "--cache-ttl", "0",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_osv_used_as_fallback_when_ghsa_empty(self, httpx_mock: HTTPXMock, tmp_path):
        """OSV should be queried when GHSA returns an empty list."""
        httpx_mock.add_response(
            url=re.compile(r"https://api\.github\.com/advisories"),
            json=_GHSA_EMPTY,
            is_reusable=True,
        )
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/query",
            json=_OSV_VULN,
            is_reusable=True,
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
                "--cache-ttl", "0",
            ],
        )
        assert result.exit_code == 0, result.output
        assert "vulnerabilities found" in result.output

    def test_wrong_file_type_exits_with_usage_error(self, tmp_path):
        """A non-pom.xml file passed to maven subcommand should exit with error."""
        bad_file = tmp_path / "settings.xml"
        bad_file.write_text("<settings/>", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["maven", str(bad_file)])
        assert result.exit_code != 0

    def test_neither_file_nor_deps_exits_with_usage_error(self):
        """maven with no FILE and no --dependencies should show a usage error."""
        runner = CliRunner()
        result = runner.invoke(main, ["maven"])
        assert result.exit_code != 0

    def test_maven_with_dependencies_flag(self, httpx_mock: HTTPXMock, tmp_path):
        """--dependencies flag should use MavenDepTreeParser and skip transitive resolver."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        with patch("java_dependency_analyzer.cli.TransitiveResolver") as mock_resolver:
            result = runner.invoke(
                main,
                [
                    "maven",
                    "--dependencies", str(_FIXTURES / "sample_maven_deps.txt"),
                    "--output-format", "json",
                    "--output-dir", str(tmp_path),
                    "--cache-ttl", "0",
                ],
            )
        assert result.exit_code == 0, result.output
        mock_resolver.assert_not_called()
        assert (tmp_path / "sample_maven_deps-report.json").exists()


class TestGradleSubcommand:
    """Tests for the ``gradle`` subcommand."""

    @pytest.fixture(autouse=True)
    def _patch_db(self, tmp_path, monkeypatch):
        """Redirect the cache database to a temporary directory for test isolation."""
        monkeypatch.setattr(
            "java_dependency_analyzer.cache.db.get_db_path",
            lambda: tmp_path / "cache.db",
        )

    def _mock_all_http(self, httpx_mock: HTTPXMock) -> None:
        """Register catch-all HTTP mocks so no real network calls are made."""
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/query",
            json=_OSV_EMPTY,
            is_reusable=True,
            is_optional=True,
        )
        httpx_mock.add_response(
            url=re.compile(r"https://api\.github\.com/advisories"),
            json=_GHSA_EMPTY,
            is_reusable=True,
            is_optional=True,
        )

    def test_cli_gradle_file(self, httpx_mock: HTTPXMock, tmp_path):
        """gradle subcommand should accept a build.gradle file."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                str(_FIXTURES / "sample_build.gradle"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_cli_gradle_kts_file(self, httpx_mock: HTTPXMock, tmp_path):
        """gradle subcommand should accept a build.gradle.kts file."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                str(_FIXTURES / "sample_build.gradle.kts"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_wrong_file_type_exits_with_usage_error(self, tmp_path):
        """A settings.gradle file passed to gradle subcommand should exit with error."""
        bad_file = tmp_path / "settings.gradle"
        bad_file.write_text("rootProject.name = 'x'", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, ["gradle", str(bad_file)])
        assert result.exit_code != 0

    def test_neither_file_nor_deps_exits_with_usage_error(self):
        """gradle with no FILE and no --dependencies should show a usage error."""
        runner = CliRunner()
        result = runner.invoke(main, ["gradle"])
        assert result.exit_code != 0

    def test_gradle_with_dependencies_flag(self, httpx_mock: HTTPXMock, tmp_path):
        """--dependencies flag should use GradleDepTreeParser and skip transitive resolver."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        with patch("java_dependency_analyzer.cli.TransitiveResolver") as mock_resolver:
            result = runner.invoke(
                main,
                [
                    "gradle",
                    "--dependencies", str(_FIXTURES / "sample_gradle_deps.txt"),
                    "--output-format", "json",
                    "--output-dir", str(tmp_path),
                    "--cache-ttl", "0",
                ],
            )
        assert result.exit_code == 0, result.output
        mock_resolver.assert_not_called()
        assert (tmp_path / "sample_gradle_deps-report.json").exists()

    def test_scan_complete_message(self, httpx_mock: HTTPXMock, tmp_path):
        """gradle subcommand should print a scan complete summary."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                str(_FIXTURES / "sample_build.gradle"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert "Scan complete" in result.output
