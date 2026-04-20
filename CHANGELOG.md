# Changelog

## 1.4.0 - 2026-04-21

### Added
- `--wrapper` option for both `gradle` and `maven` subcommands: specifies a custom wrapper script name to use instead of the default (`gradlew`/`gradlew.bat` for Gradle, `mvnw`/`mvnw.cmd` for Maven); can only be used with `--use-wrapper`.
- `--module` option for the `gradle` subcommand: specifies a Gradle module name so that the dependency task becomes `<module>:dependencies`; can only be used with `--project`.
- `GHSA_API_VERSION` environment variable to configure the GitHub Advisory API version header (defaults to `2026-03-10`).
- `JDA_CONFIG_DIR` environment variable: when set, `setup_logger()` creates the directory if absent, seeds it with the bundled `logging.ini` on first run, and loads config from there.
- Rich status spinner displayed in the terminal during dependency scanning and report writing.

### Changed
- `logging.ini` moved from the repository root into the `java_dependency_analyzer` package and loaded via `importlib.resources`; the root-level `logging.ini` has been removed.
- `logging.ini` now configures only `fileHandler`; `RichHandler` is attached programmatically by `setup_logger()` for all console output.
- `setup_logger()` resolves `logging.ini` from the package (or from `JDA_CONFIG_DIR`); the walk-up directory search has been removed.
- GHSA API version header updated from `2022-11-28` to `2026-03-10`.

### Removed
- Root-level `logging.ini` replaced by the bundled package version.

## 1.3.0 - 2026-04-19

### Added
- `--project` (`-p`) option for both `gradle` and `maven` subcommands: automatically generates the dependency tree from the project directory and runs the scan in one step.
- `--java-home` option: overrides the `JAVA_HOME` environment variable for the build-tool invocation; can only be used with `--project`.
- `--use-wrapper` flag: invokes the project wrapper script (`gradlew`/`gradlew.bat` for Gradle, `mvnw`/`mvnw.cmd` for Maven) instead of the system build tool; can only be used with `--project`.
- `GradleDepTreeParser` now parses every configuration section (e.g., `compileClasspath`,
  `runtimeClasspath`, `implementation`) from the Gradle dependency tree output; each
  dependency's `scope` reflects its Gradle configuration name.
- Dependencies annotated with the `(n)` unresolved marker in Gradle output are now
  parsed as leaf nodes with their clean declared version.
- Scope filter dropdown added to the HTML report, allowing the dependency tree to be
  filtered by scope (hidden automatically when all dependencies share the same scope).
- `ScanResult` dataclass gains a `project_dir` field to record the analysed project directory.
- HTML report now displays the project directory in the scan metadata when `--project` is used.

### Changed
- `DepTreeParser` exposes a new `_read_lines()` helper with BOM-aware encoding
  detection, enabling subclasses to reuse file reading without going through `parse()`.
- `GradleDepTreeParser.parse()` now iterates all configuration sections and stamps each
  dependency's `scope` with the configuration name instead of the hardcoded `"runtime"` value.
- JSON report now includes a `project_dir` field in the output.
- Vulnerability table header renamed from "Scope" to "Scopes" to reflect that a dependency can appear in multiple configuration sections.

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
