# Changelog

## 1.2.2 - 2026-04-09

### Added
- README installation section now lists PyPI (`pip install java-dependency-analyzer`) as the recommended installation method alongside the existing from-source instructions.

### Fixed
- `DepTreeParser` now detects encoding from BOM, enabling transparent handling of PowerShell-generated UTF-16 LE/BE and UTF-8-BOM dependency tree files alongside plain UTF-8 files.
- HTML report "Has Vulnerabilities" section is now correctly hidden when the user resets the view back to the dependency tree.

## 1.2.1 - 2026-04-08

### Added
- `util.xml_helpers` module with `POM_NS` constant and `detect_pom_namespace()` helper shared by Maven XML parsing components.

### Changed
- API base URLs (`MAVEN_CENTRAL_URL`, `GHSA_API_URL`, `OSV_QUERY_URL`, `OSV_VULN_URL`) are now configurable via environment variables, retaining their existing default values.
- HTTP error handling in `GhsaScanner` and `OsvScanner` refactored from a single `HTTPError` catch into separate `TimeoutException`, `HTTPStatusError`, and `RequestError` handlers.
- `MavenParser` and `TransitiveResolver` now use the shared `POM_NS` constant and `detect_pom_namespace()` from `util.xml_helpers`.
- `VulnerabilityScanner._parse_response()` parameter typed as `dict | list` instead of untyped.
- `OsvScanner` removes unused `_OSV_BATCH_URL` constant.
- XML parsing calls in `MavenParser` and `TransitiveResolver` reformatted for improved readability.

### Fixed
- `MavenParser` and `TransitiveResolver` POM XML parsing now uses a hardened `XMLParser` (`resolve_entities=False, no_network=True`) to prevent XXE injection.
- CLI `gradle` and `maven` subcommands now call `Path.resolve()` on input file paths for consistent absolute-path handling.
- `get_connection()` in `cache/db.py` now raises a descriptive `RuntimeError` on cache-directory creation or SQLite connection failures instead of propagating raw OS/SQLite errors.
- `setup_logger()` now falls back to `basicConfig` when loading `logging.ini` raises an exception, preventing silent failures.
- `GhsaScanner._parse_response()` now guards against non-list responses by iterating only when data is a list.
- `OsvScanner._parse_response()` now guards against non-dict responses by accessing `vulns` only when data is a dict.
- `detect_pom_namespace()` now matches the exact Maven namespace prefix instead of any brace-enclosed namespace, preventing false matches on non-Maven XML.

## 1.2.0 - 2026-04-07

### Added
- "Configuration" section in README documenting the `GITHUB_TOKEN` environment variable and its effect on GHSA rate limits.

### Changed
- HTML report "Has Vulnerabilities" view now renders a dedicated flat table with the full ancestor dependency chain and collapsible per-vulnerability details, replacing the previous in-place tree filtering.
- Row number column (`#`) added to the vulnerability list table in the HTML report.
- HTML report footer updated to reflect the current version.
- AGENTS.md version-sync rule updated to include the HTML report footer as a required version location.

## 1.1.1 - 2026-04-06

### Fixed
- `GradleDepTreeParser` now correctly handles Gradle coordinates in `group:artifact -> version` format (no inline version before the arrow).
- `GradleDepTreeParser` caches resolved versions from `->` arrows so repeated `(*)` dependency entries consistently use the resolved version.

### Changed
- `GhsaScanner` now treats HTTP 403 (in addition to 429) as a rate-limit signal and sets a persistent `rate_limited` flag for the run.
- CLI falls back to OSV for all remaining dependencies once the GHSA rate limit is hit, rather than silently skipping GHSA results.

## 1.1.0 - 2026-04-05

### Added
- `LICENSE` file (MIT License) included in the repository and referenced in `pyproject.toml`.

### Changed
- CLI exits with status code `10` when at least one vulnerability is detected (exit code `0` means no vulnerabilities found).

## 1.0.1 - 2026-04-05

### Added
- Exposed `__version__` attribute in the main package, populated at runtime from installed package metadata via `importlib.metadata`.

### Changed
- Added `[tool.poetry]` section to `pyproject.toml` to declare the `java_dependency_analyzer` package and include `logging.ini` in the distribution.
- Renamed `is_kotlin_dsl` parameter to `_is_kotlin_dsl` in `GradleParser._strip_comments` to resolve the unused-argument lint warning without a disable comment.
- Applied Black code formatting across multiple modules (`cache`, `parsers`, `resolvers`, `scanners`) to comply with line-length rules.

## 1.0.0 - 2026-04-05

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
