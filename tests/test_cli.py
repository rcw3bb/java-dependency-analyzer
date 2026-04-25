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
        "vulnerabilities": [{"vulnerable_version_range": ">= 2.0-beta9, < 2.15.0"}],
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
                {
                    "type": "WEB",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                }
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
                "--output-format",
                "json",
                "--output-dir",
                str(tmp_path),
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
                "--output-format",
                "html",
                "--output-dir",
                str(tmp_path),
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
                "--output-format",
                "all",
                "--output-dir",
                str(tmp_path),
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
                "--output-format",
                "json",
                "--output-dir",
                str(tmp_path),
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
                "--output-format",
                "json",
                "--output-dir",
                str(tmp_path),
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
                "--output-format",
                "json",
                "--output-dir",
                str(tmp_path),
                "--no-transitive",
                "--rebuild-cache",
                "--cache-ttl",
                "0",
            ],
        )
        assert result.exit_code == 0, result.output
        assert not db_path.exists()

    def test_rebuild_cache_verbose_prints_message(
        self, httpx_mock: HTTPXMock, tmp_path
    ):
        """--rebuild-cache with --verbose should print confirmation."""
        self._mock_all_http(httpx_mock)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--output-format",
                "json",
                "--output-dir",
                str(tmp_path),
                "--no-transitive",
                "--rebuild-cache",
                "--cache-ttl",
                "0",
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
                "--output-format",
                "json",
                "--output-dir",
                str(tmp_path),
                "--no-transitive",
                "--cache-ttl",
                "0",
            ],
        )
        assert not db_path.exists()

    def test_osv_not_called_when_ghsa_finds_results(
        self, httpx_mock: HTTPXMock, tmp_path
    ):
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
                "--output-format",
                "json",
                "--output-dir",
                str(tmp_path),
                "--no-transitive",
                "--cache-ttl",
                "0",
            ],
        )
        assert result.exit_code == 10, result.output

    def test_osv_used_as_fallback_when_ghsa_empty(
        self, httpx_mock: HTTPXMock, tmp_path
    ):
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
                "--output-format",
                "json",
                "--output-dir",
                str(tmp_path),
                "--no-transitive",
                "--cache-ttl",
                "0",
            ],
        )
        assert result.exit_code == 10, result.output
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
                    "--dependencies",
                    str(_FIXTURES / "sample_maven_deps.txt"),
                    "--output-format",
                    "json",
                    "--output-dir",
                    str(tmp_path),
                    "--cache-ttl",
                    "0",
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
                "--output-format",
                "json",
                "--output-dir",
                str(tmp_path),
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
                "--output-format",
                "json",
                "--output-dir",
                str(tmp_path),
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
                    "--dependencies",
                    str(_FIXTURES / "sample_gradle_deps.txt"),
                    "--output-format",
                    "json",
                    "--output-dir",
                    str(tmp_path),
                    "--cache-ttl",
                    "0",
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
                "--output-format",
                "json",
                "--output-dir",
                str(tmp_path),
                "--no-transitive",
            ],
        )
        assert "Scan complete" in result.output

    def test_exit_code_10_when_vulnerabilities_found(
        self, httpx_mock: HTTPXMock, tmp_path
    ):
        """gradle subcommand should exit with code 10 when vulnerabilities are detected."""
        httpx_mock.add_response(
            url=re.compile(r"https://api\.github\.com/advisories"),
            json=_GHSA_VULN,
            is_reusable=True,
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                str(_FIXTURES / "sample_build.gradle"),
                "--output-format",
                "json",
                "--output-dir",
                str(tmp_path),
                "--no-transitive",
                "--cache-ttl",
                "0",
            ],
        )
        assert result.exit_code == 10, result.output


class TestProjectParam:
    """Tests for the --project, --java-home, and --use-wrapper options."""

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

    # ------------------------------------------------------------------
    # Mutual exclusion: --java-home / --use-wrapper without --project
    # ------------------------------------------------------------------

    def test_java_home_without_project_raises_error_gradle(self, tmp_path):
        """--java-home without --project on gradle should raise UsageError."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                str(_FIXTURES / "sample_build.gradle"),
                "--java-home",
                "/fake/java",
                "--no-transitive",
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "--java-home" in result.output or "project" in result.output.lower()

    def test_use_wrapper_without_project_raises_error_gradle(self, tmp_path):
        """--use-wrapper without --project on gradle should raise UsageError."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                str(_FIXTURES / "sample_build.gradle"),
                "--use-wrapper",
                "--no-transitive",
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "--use-wrapper" in result.output or "project" in result.output.lower()

    def test_java_home_without_project_raises_error_maven(self, tmp_path):
        """--java-home without --project on maven should raise UsageError."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--java-home",
                "/fake/java",
                "--no-transitive",
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "--java-home" in result.output or "project" in result.output.lower()

    def test_use_wrapper_without_project_raises_error_maven(self, tmp_path):
        """--use-wrapper without --project on maven should raise UsageError."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--use-wrapper",
                "--no-transitive",
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "--use-wrapper" in result.output or "project" in result.output.lower()

    # ------------------------------------------------------------------
    # Mutual exclusion: --project combined with FILE or -d
    # ------------------------------------------------------------------

    def test_project_with_file_raises_error_gradle(self, tmp_path):
        """--project combined with FILE on gradle should raise UsageError."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                str(_FIXTURES / "sample_build.gradle"),
                "--project",
                str(project_dir),
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "--project" in result.output or "FILE" in result.output

    def test_project_with_dependencies_raises_error_gradle(self, tmp_path):
        """--project combined with -d on gradle should raise UsageError."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                "--project",
                str(project_dir),
                "--dependencies",
                str(_FIXTURES / "sample_gradle_deps.txt"),
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "--project" in result.output or "--dependencies" in result.output

    def test_project_with_file_raises_error_maven(self, tmp_path):
        """--project combined with FILE on maven should raise UsageError."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--project",
                str(project_dir),
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "--project" in result.output or "FILE" in result.output

    def test_project_with_dependencies_raises_error_maven(self, tmp_path):
        """--project combined with -d on maven should raise UsageError."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                "--project",
                str(project_dir),
                "--dependencies",
                str(_FIXTURES / "sample_maven_deps.txt"),
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "--project" in result.output or "--dependencies" in result.output

    # ------------------------------------------------------------------
    # JAVA_HOME resolution
    # ------------------------------------------------------------------

    def test_project_no_java_home_raises_error(self, tmp_path, monkeypatch):
        """--project with no JAVA_HOME in env and no --java-home should raise UsageError."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        monkeypatch.delenv("JAVA_HOME", raising=False)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                "--project",
                str(project_dir),
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "JAVA_HOME" in result.output

    # ------------------------------------------------------------------
    # use-wrapper: missing wrapper file
    # ------------------------------------------------------------------

    def test_use_wrapper_missing_gradlew_raises_error(self, tmp_path):
        """--use-wrapper on gradle when gradlew is absent should raise UsageError."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                "--project",
                str(project_dir),
                "--java-home",
                "/fake/java",
                "--use-wrapper",
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "wrapper" in result.output.lower() or "gradlew" in result.output.lower()

    def test_use_wrapper_missing_mvnw_raises_error(self, tmp_path):
        """--use-wrapper on maven when mvnw is absent should raise UsageError."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                "--project",
                str(project_dir),
                "--java-home",
                "/fake/java",
                "--use-wrapper",
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "wrapper" in result.output.lower() or "mvnw" in result.output.lower()

    # ------------------------------------------------------------------
    # Success cases: --project
    # ------------------------------------------------------------------

    def test_project_gradle_success(self, httpx_mock: HTTPXMock, tmp_path):
        """--project on gradle should generate dep-tree, write reports with project_dir."""
        import json as json_mod  # noqa: PLC0415

        self._mock_all_http(httpx_mock)
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        output_dir = tmp_path / "reports"
        fixture_content = (_FIXTURES / "sample_gradle_deps.txt").read_text(
            encoding="utf-8"
        )

        def _fake_execute(cmd, cwd, java_home, temp_file):
            temp_file.write_text(fixture_content, encoding="utf-8")

        runner = CliRunner()
        with patch(
            "java_dependency_analyzer.cli._execute_dep_tree_cmd",
            side_effect=_fake_execute,
        ):
            result = runner.invoke(
                main,
                [
                    "gradle",
                    "--project",
                    str(project_dir),
                    "--java-home",
                    "/fake/java",
                    "--output-format",
                    "all",
                    "--output-dir",
                    str(output_dir),
                    "--cache-ttl",
                    "0",
                ],
            )

        assert result.exit_code == 0, result.output
        assert "Scan complete" in result.output

        dep_tree_files = list(output_dir.glob("myproject-deps-*.txt"))
        assert dep_tree_files, "Expected a timestamped dep-tree .txt file"

        json_files = list(output_dir.glob("*-report.json"))
        assert json_files
        data = json_mod.loads(json_files[0].read_text(encoding="utf-8"))
        assert data["project_dir"] is not None
        assert "myproject" in data["project_dir"]

        html_files = list(output_dir.glob("*-report.html"))
        assert html_files
        assert "Project Directory:" in html_files[0].read_text(encoding="utf-8")

    def test_project_maven_success(self, httpx_mock: HTTPXMock, tmp_path):
        """--project on maven should generate dep-tree, write reports with project_dir."""
        import json as json_mod  # noqa: PLC0415

        self._mock_all_http(httpx_mock)
        project_dir = tmp_path / "mymavenproject"
        project_dir.mkdir()
        output_dir = tmp_path / "reports"
        fixture_content = (_FIXTURES / "sample_maven_deps.txt").read_text(
            encoding="utf-8"
        )

        def _fake_execute(cmd, cwd, java_home, temp_file):
            temp_file.write_text(fixture_content, encoding="utf-8")

        runner = CliRunner()
        with patch(
            "java_dependency_analyzer.cli._execute_dep_tree_cmd",
            side_effect=_fake_execute,
        ):
            result = runner.invoke(
                main,
                [
                    "maven",
                    "--project",
                    str(project_dir),
                    "--java-home",
                    "/fake/java",
                    "--output-format",
                    "all",
                    "--output-dir",
                    str(output_dir),
                    "--cache-ttl",
                    "0",
                ],
            )

        assert result.exit_code == 0, result.output
        assert "Scan complete" in result.output

        dep_tree_files = list(output_dir.glob("mymavenproject-deps-*.txt"))
        assert dep_tree_files, "Expected a timestamped dep-tree .txt file"

        json_files = list(output_dir.glob("*-report.json"))
        assert json_files
        data = json_mod.loads(json_files[0].read_text(encoding="utf-8"))
        assert data["project_dir"] is not None
        assert "mymavenproject" in data["project_dir"]

        html_files = list(output_dir.glob("*-report.html"))
        assert html_files
        assert "Project Directory:" in html_files[0].read_text(encoding="utf-8")

    def test_project_gradle_verbose(self, httpx_mock: HTTPXMock, tmp_path):
        """--project with --verbose on gradle should emit progress messages."""
        self._mock_all_http(httpx_mock)
        project_dir = tmp_path / "verboseproject"
        project_dir.mkdir()
        output_dir = tmp_path / "reports"
        fixture_content = (_FIXTURES / "sample_gradle_deps.txt").read_text(
            encoding="utf-8"
        )

        def _fake_execute(cmd, cwd, java_home, temp_file):
            temp_file.write_text(fixture_content, encoding="utf-8")

        runner = CliRunner()
        with patch(
            "java_dependency_analyzer.cli._execute_dep_tree_cmd",
            side_effect=_fake_execute,
        ):
            result = runner.invoke(
                main,
                [
                    "gradle",
                    "--project",
                    str(project_dir),
                    "--java-home",
                    "/fake/java",
                    "--output-format",
                    "json",
                    "--output-dir",
                    str(output_dir),
                    "--cache-ttl",
                    "0",
                    "--verbose",
                ],
            )

        assert result.exit_code == 0, result.output
        assert "Running:" in result.output
        assert "Dependency tree saved" in result.output

    def test_project_uses_java_home_option(self, httpx_mock: HTTPXMock, tmp_path):
        """--java-home value should be forwarded to the build-tool execution."""
        self._mock_all_http(httpx_mock)
        project_dir = tmp_path / "jhproject"
        project_dir.mkdir()
        output_dir = tmp_path / "reports"
        fixture_content = (_FIXTURES / "sample_gradle_deps.txt").read_text(
            encoding="utf-8"
        )
        captured = {}

        def _fake_execute(cmd, cwd, java_home, temp_file):
            captured["java_home"] = java_home
            temp_file.write_text(fixture_content, encoding="utf-8")

        runner = CliRunner()
        with patch(
            "java_dependency_analyzer.cli._execute_dep_tree_cmd",
            side_effect=_fake_execute,
        ):
            runner.invoke(
                main,
                [
                    "gradle",
                    "--project",
                    str(project_dir),
                    "--java-home",
                    "/custom/java/home",
                    "--output-format",
                    "json",
                    "--output-dir",
                    str(output_dir),
                    "--cache-ttl",
                    "0",
                ],
            )

        assert captured.get("java_home") == "/custom/java/home"


class TestWrapperParam:
    """Tests for the --wrapper option on both gradle and maven subcommands."""

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

    # ------------------------------------------------------------------
    # --wrapper without --use-wrapper
    # ------------------------------------------------------------------

    def test_wrapper_without_use_wrapper_raises_error_gradle(self, tmp_path):
        """--wrapper without --use-wrapper on gradle should raise UsageError."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                str(_FIXTURES / "sample_build.gradle"),
                "--wrapper",
                "custom_gradlew",
                "--no-transitive",
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "wrapper" in result.output.lower() or "use-wrapper" in result.output

    def test_wrapper_without_use_wrapper_raises_error_maven(self, tmp_path):
        """--wrapper without --use-wrapper on maven should raise UsageError."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                str(_FIXTURES / "sample_pom.xml"),
                "--wrapper",
                "custom_mvnw",
                "--no-transitive",
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "wrapper" in result.output.lower() or "use-wrapper" in result.output

    # ------------------------------------------------------------------
    # --wrapper with missing custom wrapper file
    # ------------------------------------------------------------------

    def test_wrapper_custom_file_missing_raises_error_gradle(self, tmp_path):
        """--wrapper with a missing custom script on gradle should raise UsageError."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                "--project",
                str(project_dir),
                "--java-home",
                "/fake/java",
                "--use-wrapper",
                "--wrapper",
                "my_gradlew",
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "wrapper" in result.output.lower()

    def test_wrapper_custom_file_missing_raises_error_maven(self, tmp_path):
        """--wrapper with a missing custom script on maven should raise UsageError."""
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "maven",
                "--project",
                str(project_dir),
                "--java-home",
                "/fake/java",
                "--use-wrapper",
                "--wrapper",
                "my_mvnw",
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "wrapper" in result.output.lower()

    # ------------------------------------------------------------------
    # --wrapper custom file success paths
    # ------------------------------------------------------------------

    def test_wrapper_custom_file_success_gradle(self, httpx_mock: HTTPXMock, tmp_path):
        """--wrapper with an existing script on gradle should succeed and use that script."""
        self._mock_all_http(httpx_mock)
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        custom_wrapper = project_dir / "my_gradlew"
        custom_wrapper.write_text("#!/bin/sh\ngradle $@", encoding="utf-8")

        output_dir = tmp_path / "reports"
        fixture_content = (_FIXTURES / "sample_gradle_deps.txt").read_text(
            encoding="utf-8"
        )
        captured = {}

        def _fake_execute(cmd, cwd, java_home, temp_file):
            captured["cmd"] = cmd
            temp_file.write_text(fixture_content, encoding="utf-8")

        runner = CliRunner()
        with patch(
            "java_dependency_analyzer.cli._execute_dep_tree_cmd",
            side_effect=_fake_execute,
        ):
            result = runner.invoke(
                main,
                [
                    "gradle",
                    "--project",
                    str(project_dir),
                    "--java-home",
                    "/fake/java",
                    "--use-wrapper",
                    "--wrapper",
                    "my_gradlew",
                    "--output-format",
                    "json",
                    "--output-dir",
                    str(output_dir),
                    "--cache-ttl",
                    "0",
                ],
            )

        assert result.exit_code == 0, result.output
        assert captured.get("cmd") is not None
        assert "my_gradlew" in " ".join(captured["cmd"])

    def test_wrapper_custom_file_success_maven(self, httpx_mock: HTTPXMock, tmp_path):
        """--wrapper with an existing script on maven should succeed and use that script."""
        self._mock_all_http(httpx_mock)
        project_dir = tmp_path / "mymavenproject"
        project_dir.mkdir()
        custom_wrapper = project_dir / "my_mvnw"
        custom_wrapper.write_text("#!/bin/sh\nmvn $@", encoding="utf-8")

        output_dir = tmp_path / "reports"
        fixture_content = (_FIXTURES / "sample_maven_deps.txt").read_text(
            encoding="utf-8"
        )
        captured = {}

        def _fake_execute(cmd, cwd, java_home, temp_file):
            captured["cmd"] = cmd
            temp_file.write_text(fixture_content, encoding="utf-8")

        runner = CliRunner()
        with patch(
            "java_dependency_analyzer.cli._execute_dep_tree_cmd",
            side_effect=_fake_execute,
        ):
            result = runner.invoke(
                main,
                [
                    "maven",
                    "--project",
                    str(project_dir),
                    "--java-home",
                    "/fake/java",
                    "--use-wrapper",
                    "--wrapper",
                    "my_mvnw",
                    "--output-format",
                    "json",
                    "--output-dir",
                    str(output_dir),
                    "--cache-ttl",
                    "0",
                ],
            )

        assert result.exit_code == 0, result.output
        assert captured.get("cmd") is not None
        assert "my_mvnw" in " ".join(captured["cmd"])


class TestModuleParam:
    """Tests for the --module option on the gradle subcommand."""

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

    def test_module_without_project_raises_error(self, tmp_path):
        """--module without --project on gradle should raise UsageError."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "gradle",
                str(_FIXTURES / "sample_build.gradle"),
                "--module",
                "mymod",
                "--no-transitive",
                "--output-dir",
                str(tmp_path),
            ],
        )
        assert result.exit_code != 0
        assert "module" in result.output.lower() or "project" in result.output.lower()

    def test_module_with_project_uses_module_task(
        self, httpx_mock: HTTPXMock, tmp_path
    ):
        """--module with --project should produce a task of the form <module>:dependencies."""
        self._mock_all_http(httpx_mock)
        project_dir = tmp_path / "myproject"
        project_dir.mkdir()
        output_dir = tmp_path / "reports"
        fixture_content = (_FIXTURES / "sample_gradle_deps.txt").read_text(
            encoding="utf-8"
        )
        captured = {}

        def _fake_execute(cmd, cwd, java_home, temp_file):
            captured["cmd"] = cmd
            temp_file.write_text(fixture_content, encoding="utf-8")

        runner = CliRunner()
        with patch(
            "java_dependency_analyzer.cli._execute_dep_tree_cmd",
            side_effect=_fake_execute,
        ):
            result = runner.invoke(
                main,
                [
                    "gradle",
                    "--project",
                    str(project_dir),
                    "--java-home",
                    "/fake/java",
                    "--module",
                    "mymod",
                    "--output-format",
                    "json",
                    "--output-dir",
                    str(output_dir),
                    "--cache-ttl",
                    "0",
                ],
            )

        assert result.exit_code == 0, result.output
        assert captured.get("cmd") is not None
        assert "mymod:dependencies" in " ".join(captured["cmd"])


class TestSbomSubcommand:
    """Tests for the ``sbom`` subcommand."""

    def test_sbom_spdx_creates_file(self, tmp_path):
        """sbom subcommand with --standard spdx should create a JSON SBOM file."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sbom",
                "--standard",
                "spdx",
                "--output-dir",
                str(tmp_path),
                str(_FIXTURES / "sample_report.json"),
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "sample_report-sbom-spdx.json").exists()

    def test_sbom_cyclonedx_creates_file(self, tmp_path):
        """sbom subcommand with --standard cyclonedx should create a CycloneDX SBOM file."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sbom",
                "--standard",
                "cyclonedx",
                "--output-dir",
                str(tmp_path),
                str(_FIXTURES / "sample_report.json"),
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "sample_report-sbom-cyclonedx.json").exists()

    def test_sbom_swid_creates_file(self, tmp_path):
        """sbom subcommand with --standard swid should create a SWID SBOM file."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sbom",
                "--standard",
                "swid",
                "--output-dir",
                str(tmp_path),
                str(_FIXTURES / "sample_report.json"),
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "sample_report-sbom-swid.json").exists()

    def test_sbom_output_message(self, tmp_path):
        """sbom subcommand should print the path of the generated SBOM file."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sbom",
                "--standard",
                "spdx",
                "--output-dir",
                str(tmp_path),
                str(_FIXTURES / "sample_report.json"),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "SBOM generated" in result.output

    def test_sbom_non_json_file_exits_with_usage_error(self, tmp_path):
        """sbom subcommand should reject a non-JSON file with a usage error."""
        bad_file = tmp_path / "report.txt"
        bad_file.write_text("not json", encoding="utf-8")
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sbom",
                "--standard",
                "spdx",
                str(bad_file),
            ],
        )
        assert result.exit_code != 0

    def test_sbom_missing_standard_exits_with_error(self, tmp_path):
        """sbom subcommand without --standard should exit with an error."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sbom",
                str(_FIXTURES / "sample_report.json"),
            ],
        )
        assert result.exit_code != 0

    def test_sbom_invalid_standard_exits_with_error(self, tmp_path):
        """sbom subcommand with an unsupported --standard value should exit with error."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sbom",
                "--standard",
                "invalid",
                str(_FIXTURES / "sample_report.json"),
            ],
        )
        assert result.exit_code != 0

    def test_sbom_short_option_s(self, tmp_path):
        """sbom subcommand should accept -s as a short form of --standard."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sbom",
                "-s",
                "cyclonedx",
                "--output-dir",
                str(tmp_path),
                str(_FIXTURES / "sample_report.json"),
            ],
        )
        assert result.exit_code == 0, result.output
        assert (tmp_path / "sample_report-sbom-cyclonedx.json").exists()

    def test_sbom_creates_output_dir(self, tmp_path):
        """sbom subcommand should create the output directory if it does not exist."""
        output_dir = tmp_path / "new_reports"
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "sbom",
                "--standard",
                "spdx",
                "--output-dir",
                str(output_dir),
                str(_FIXTURES / "sample_report.json"),
            ],
        )
        assert result.exit_code == 0, result.output
        assert output_dir.exists()
