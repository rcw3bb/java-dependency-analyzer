# Changelog

## [1.1.0] - 2026-04-05

### Added
- `LICENSE` file (MIT License) included in the repository and referenced in `pyproject.toml`.

### Changed
- CLI exits with status code `10` when at least one vulnerability is detected (exit code `0` means no vulnerabilities found).

## [1.0.1] - 2026-04-05

### Added
- Exposed `__version__` attribute in the main package, populated at runtime from installed package metadata via `importlib.metadata`.

### Changed
- Added `[tool.poetry]` section to `pyproject.toml` to declare the `java_dependency_analyzer` package and include `logging.ini` in the distribution.
- Renamed `is_kotlin_dsl` parameter to `_is_kotlin_dsl` in `GradleParser._strip_comments` to resolve the unused-argument lint warning without a disable comment.
- Applied Black code formatting across multiple modules (`cache`, `parsers`, `resolvers`, `scanners`) to comply with line-length rules.

## [1.0.0] - 2026-04-05

### Added
- `jda` CLI entry point (Click) with `gradle` and `maven` subcommands; options: `--dependencies` (`-d`), `--output-format` (`-f`), `--output-dir` (`-o`), `--no-transitive`, `--verbose` (`-v`), `--rebuild-cache`, and `--cache-ttl`.
- `MavenParser` for parsing `pom.xml` files, resolving `${property}` placeholders and filtering by runtime scopes.
- `GradleParser` for parsing `build.gradle` (Groovy DSL) and `build.gradle.kts` (Kotlin DSL) files.
- `MavenDepTreeParser` for parsing `mvn dependency:tree` text output into a full transitive dependency tree.
- `GradleDepTreeParser` for parsing `gradle dependencies` text output into a full transitive dependency tree.
- `DependencyParser` and `DepTreeParser` abstract base classes shared by all parsers.
- `TransitiveResolver` that fetches transitive dependencies from Maven Central POM files via HTTP.
- `OsvScanner` that queries the OSV.dev batch API to detect known vulnerabilities.
- `GhsaScanner` that queries the GitHub Advisory Database REST API for security advisories; supports `GITHUB_TOKEN` env var for increased API rate limits.
- `VulnerabilityScanner` abstract base class shared by all scanners.
- `VulnerabilityCache` SQLite-backed cache for vulnerability scan API responses with configurable TTL (default 7 days).
- `DatabaseManager` for SQLite connection lifecycle management (`cache/db.py`).
- `Dependency` and `Vulnerability` dataclasses for modelling dependency graph nodes and CVE entries.
- `ScanResult` dataclass with computed summary properties (`total_dependencies`, `vulnerable_count`, `vulnerability_summary`).
- `JsonReporter` that serialises a `ScanResult` to a JSON file.
- `HtmlReporter` that renders a `ScanResult` to a styled HTML report via a Jinja2 template.
- `Reporter` abstract base class shared by all reporters.
- `setup_logger(name)` utility for consistent `logging.ini`-backed logging across all modules.
- `logging.ini` configuration with `FileHandler` and `StreamHandler` writing to `java_dependency_analyzer.log`.
- `conftest.py` global pytest fixture activating `httpx_mock` for every test to block all real HTTP calls.
- Full test suite (pytest + pytest-httpx) for all packages with ≥ 80% coverage.
- Project configuration via PEP 621 `pyproject.toml` managed by Poetry 2.2.
