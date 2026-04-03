## Purpose

This repo is **Java Dependency Analyzer** (v1.0.0), a Python CLI tool that inspects Java dependency hierarchies. Built with Python ^3.14 and managed via Poetry 2.2 using PEP 621 config (`pyproject.toml`). Author: Ron Webb <ron@ronella.xyz>; main package: `java_dependency_analyzer`.

- Install deps: `poetry install`
- Run tests + coverage: `poetry run pytest --cov=java_dependency_analyzer tests --cov-report html`
- Format + lint: `poetry run black java_dependency_analyzer; poetry run pylint java_dependency_analyzer`

The linter must always score **10/10**. Minimum test coverage is **80%**.

## Tree

- `java_dependency_analyzer/` — main package; all new modules go here
- `java_dependency_analyzer/__init__.py` — package init with `__author__` and `__since__`
- `java_dependency_analyzer/util/` — utility sub-package
- `java_dependency_analyzer/util/__init__.py` — util package init
- `java_dependency_analyzer/util/logger.py` — `setup_logger(name)` for consistent logging via `logging.ini`
- `java_dependency_analyzer/models/` — data model sub-package
- `java_dependency_analyzer/models/__init__.py` — models package init
- `java_dependency_analyzer/models/dependency.py` — `Vulnerability` and `Dependency` dataclasses
- `java_dependency_analyzer/models/report.py` — `ScanResult` dataclass with computed summary properties
- `java_dependency_analyzer/parsers/` — parser sub-package
- `java_dependency_analyzer/parsers/__init__.py` — parsers package init
- `java_dependency_analyzer/parsers/base.py` — `DependencyParser` ABC and `RUNTIME_SCOPES` constant
- `java_dependency_analyzer/parsers/maven_parser.py` — `MavenParser` for pom.xml files
- `java_dependency_analyzer/parsers/gradle_parser.py` — `GradleParser` for build.gradle and build.gradle.kts
- `java_dependency_analyzer/resolvers/` — resolver sub-package
- `java_dependency_analyzer/resolvers/__init__.py` — resolvers package init
- `java_dependency_analyzer/resolvers/transitive.py` — `TransitiveResolver` using Maven Central POM fetching
- `java_dependency_analyzer/scanners/` — vulnerability scanner sub-package
- `java_dependency_analyzer/scanners/__init__.py` — scanners package init
- `java_dependency_analyzer/scanners/base.py` — `VulnerabilityScanner` ABC
- `java_dependency_analyzer/scanners/osv_scanner.py` — `OsvScanner` querying OSV.dev API
- `java_dependency_analyzer/scanners/mvn_repository.py` — `MvnRepositoryScanner` scraping mvnrepository.com
- `java_dependency_analyzer/reporters/` — report writer sub-package
- `java_dependency_analyzer/reporters/__init__.py` — reporters package init
- `java_dependency_analyzer/reporters/base.py` — `Reporter` ABC
- `java_dependency_analyzer/reporters/json_reporter.py` — `JsonReporter` outputting JSON
- `java_dependency_analyzer/reporters/html_reporter.py` — `HtmlReporter` rendering Jinja2 HTML
- `java_dependency_analyzer/reporters/templates/report.html` — Jinja2 HTML report template
- `java_dependency_analyzer/cli.py` — Click CLI entry point (`jda` command)
- `tests/` — test package mirroring the main package structure; all tests go here
- `tests/__init__.py` — test package init
- `tests/models/__init__.py` — models test package init
- `tests/models/test_dependency.py` — tests for `Vulnerability` and `Dependency`
- `tests/models/test_report.py` — tests for `ScanResult`
- `tests/parsers/__init__.py` — parsers test package init
- `tests/parsers/test_maven_parser.py` — tests for `MavenParser`
- `tests/parsers/test_gradle_parser.py` — tests for `GradleParser`
- `tests/resolvers/__init__.py` — resolvers test package init
- `tests/resolvers/test_transitive.py` — tests for `TransitiveResolver` (uses pytest-httpx)
- `tests/scanners/__init__.py` — scanners test package init
- `tests/scanners/test_osv_scanner.py` — tests for `OsvScanner` (uses pytest-httpx)
- `tests/scanners/test_mvn_repository.py` — tests for `MvnRepositoryScanner` (uses pytest-httpx)
- `tests/reporters/__init__.py` — reporters test package init
- `tests/reporters/test_json_reporter.py` — tests for `JsonReporter`
- `tests/reporters/test_html_reporter.py` — tests for `HtmlReporter`
- `tests/test_cli.py` — end-to-end CLI tests (uses pytest-httpx)
- `tests/fixtures/sample_pom.xml` — sample Maven POM fixture with properties and varied scopes
- `tests/fixtures/no_namespace_pom.xml` — POM fixture without Maven namespace
- `tests/fixtures/sample_build.gradle` — Groovy DSL Gradle fixture
- `tests/fixtures/sample_build.gradle.kts` — Kotlin DSL Gradle fixture
- `pyproject.toml` — Poetry PEP 621 project config; use `poetry add` / `poetry add --dev`
- `logging.ini` — logging config (FileHandler + StreamHandler); log file: `java_dependency_analyzer.log`
- `.pylintrc` — Pylint config based on rcw3bb's gist
- `.gitignore` — excludes IDE files, `__pycache__`, `.env`, log files, `htmlcov/`; preserves `poetry.lock`
- `.gitattributes` — enforces LF line endings for non-Windows files
- `CHANGELOG.md` — follows Keep a Changelog format; update on every release
- `README.md` — project overview, requirements, setup, and usage
- `poetry.toml` — Poetry local config; enables in-project virtualenv creation
- `poetry.lock` — locked dependency versions; must be committed

## Rules

- Before adding a dependency, use `poetry add <pkg>`; for dev deps use `poetry add --dev <pkg>`
- Place all new modules in `java_dependency_analyzer/`; all new tests in `tests/` mirroring the source structure
- Name test files `test_*.py`; mirror the sub-package structure inside `tests/`
- Use relative imports within `java_dependency_analyzer/`
- Follow SOLID and DRY; prefer composition over inheritance; use dependency injection where applicable
- Every module, class, and method must have a docstring, type hints, `:author: Ron Webb` and `:since: 1.0.0`
- For version > 1.0.0, add `:author:` and `:since:` only to new methods/classes in existing modules
- Use `snake_case` for methods/variables, `PascalCase` for classes, `UPPER_CASE` for constants
- Prefix private/protected members with `_`; decompose large methods into smaller private methods
- Use `collections.abc` instead of deprecated `typing` types; add inline comments only when non-obvious
- For logging in any module, call `setup_logger(__name__)` from `java_dependency_analyzer.util.logger`
- For environment variables, use `python-dotenv`; never hardcode secrets
- Never modify `.pylintrc` without approval; linter score must remain 10/10
- When creating or discovering new files, update the Tree section above

## Note-taking

- After each task, log any correction, preference, or pattern learned.
- Write to the matching docs file's "Session learnings" section; if none fits, add to Rules above. One dated line, plain language.
  e.g. `Pylint C0114 triggers when module docstring is missing the blank line after triple-quote (learned 4/3)`
- 3+ related notes on a topic → create a new `docs/` context file, move notes there, update the Tree. Keep this file under 100 lines.