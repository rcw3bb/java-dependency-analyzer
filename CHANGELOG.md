# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-04-03

### Added
- `jda` CLI entry point (Click) with `--file`, `--output`, `--format`, `--scanner`, and `--no-transitive` options.
- `MavenParser` for parsing `pom.xml` files, resolving `${property}` placeholders and filtering by runtime scopes.
- `GradleParser` for parsing `build.gradle` (Groovy DSL) and `build.gradle.kts` (Kotlin DSL) files.
- `DependencyParser` abstract base class and `RUNTIME_SCOPES` constant shared by all parsers.
- `TransitiveResolver` that fetches transitive dependencies from Maven Central POM files via HTTP.
- `OsvScanner` that queries the OSV.dev batch API to detect known vulnerabilities.
- `MvnRepositoryScanner` that scrapes mvnrepository.com for vulnerability notices.
- `VulnerabilityScanner` abstract base class shared by all scanners.
- `Dependency` and `Vulnerability` dataclasses for modelling dependency graph nodes and CVE entries.
- `ScanResult` dataclass with computed summary properties (`total_dependencies`, `vulnerable_count`, `vulnerability_summary`).
- `JsonReporter` that serialises a `ScanResult` to a JSON file.
- `HtmlReporter` that renders a `ScanResult` to a styled HTML report via a Jinja2 template.
- `Reporter` abstract base class shared by all reporters.
- `setup_logger(name)` utility for consistent `logging.ini`-backed logging across all modules.
- `logging.ini` configuration with `FileHandler` and `StreamHandler` writing to `java_dependency_analyzer.log`.
- Full test suite (pytest + pytest-httpx) for parsers, resolvers, scanners, reporters, and CLI with ≥ 80 % coverage.
- Project configuration via PEP 621 `pyproject.toml` managed by Poetry 2.2.
