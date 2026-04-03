"""
test_cli module.

Tests for the CLI entry point.

:author: Ron Webb
:since: 1.0.0
"""

from pathlib import Path

import re

import httpx
import pytest
from click.testing import CliRunner
from pytest_httpx import HTTPXMock

from java_dependency_analyzer.cli import main

__author__ = "Ron Webb"
__since__ = "1.0.0"

_FIXTURES = Path(__file__).parent / "fixtures"

# Minimal OSV empty response and mvnrepository clean page
_OSV_EMPTY = {"vulns": []}
_MVN_CLEAN_HTML = "<html><body><p>No issues.</p></body></html>"


class TestCli:
    """Tests for the CLI entry point."""

    def _mock_all_http(self, httpx_mock: HTTPXMock) -> None:
        """Register catch-all HTTP mocks so no real network calls are made."""
        httpx_mock.add_response(
            url="https://api.osv.dev/v1/query",
            json=_OSV_EMPTY,
            is_reusable=True,
            is_optional=True,
        )
        httpx_mock.add_response(
            url=re.compile(r"https://mvnrepository\.com/"),
            text=_MVN_CLEAN_HTML,
            is_reusable=True,
            is_optional=True,
        )
        httpx_mock.add_response(
            url=re.compile(r"https://repo1\.maven\.org/"),
            status_code=404,
            is_reusable=True,
            is_optional=True,
        )

    def test_cli_json_output(self, httpx_mock: HTTPXMock, tmp_path):
        """CLI should create a JSON report for pom.xml with --output-format json."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "sample_pom-report.json").exists()

    def test_cli_html_output(self, httpx_mock: HTTPXMock, tmp_path):
        """CLI should create an HTML report for pom.xml with --output-format html."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "html",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "sample_pom-report.html").exists()

    def test_cli_all_output(self, httpx_mock: HTTPXMock, tmp_path):
        """CLI with --output-format all should create both JSON and HTML reports."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "all",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "sample_pom-report.json").exists()
        assert (tmp_path / "sample_pom-report.html").exists()

    def test_cli_gradle_file(self, httpx_mock: HTTPXMock, tmp_path):
        """CLI should accept a build.gradle file."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(_FIXTURES / "sample_build.gradle"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_cli_gradle_kts_file(self, httpx_mock: HTTPXMock, tmp_path):
        """CLI should accept a build.gradle.kts file."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                str(_FIXTURES / "sample_build.gradle.kts"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert result.exit_code == 0, result.output

    def test_cli_unsupported_file_exits_with_code_1(self, tmp_path):
        """Unsupported file (e.g. settings.gradle) should exit with code 1."""
        bad_file = tmp_path / "settings.gradle"
        bad_file.write_text("rootProject.name = 'x'", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(main, [str(bad_file)])
        assert result.exit_code == 1

    def test_cli_verbose_flag(self, httpx_mock: HTTPXMock, tmp_path):
        """--verbose flag should produce additional output."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
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
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format", "json",
                "--output-dir", str(tmp_path),
                "--no-transitive",
            ],
        )
        assert "Scan complete" in result.output
