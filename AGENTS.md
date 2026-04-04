## Purpose

This repo is **Java Dependency Analyzer** (v1.0.1), a Python CLI tool that inspects Java dependency hierarchies. Built with Python ^3.14 and managed via Poetry 2.2 using PEP 621 config (`pyproject.toml`). Author: Ron Webb <ron@ronella.xyz>; main package: `java_dependency_analyzer`.

- Install deps: `poetry install`
- Run tests + coverage: `poetry run pytest --cov=java_dependency_analyzer tests --cov-report html`
- Format + lint: `poetry run black java_dependency_analyzer; poetry run pylint java_dependency_analyzer`

The linter must always score **10/10**. Minimum test coverage is **80%**.

## Tree

- `java_dependency_analyzer/` — main package; all new modules go here
- `java_dependency_analyzer/util/` — utility sub-package
- `java_dependency_analyzer/models/` — data model sub-package
- `java_dependency_analyzer/parsers/` — parser sub-package
- `java_dependency_analyzer/resolvers/` — resolver sub-package
- `java_dependency_analyzer/scanners/` — vulnerability scanner sub-package
- `java_dependency_analyzer/cache/` — SQLite cache sub-package
- `java_dependency_analyzer/reporters/` — report writer sub-package
- `java_dependency_analyzer/reporters/templates/` — Jinja2 HTML report templates
- `java_dependency_analyzer/cli.py` — Click CLI entry point (`jda` group with `gradle` and `maven` subcommands)
- `tests/` — test package mirroring the main package structure; all tests go here
- `tests/conftest.py` — global pytest fixtures; activates `httpx_mock` for every test to block all real HTTP calls
- `tests/fixtures/` — sample fixture files for parsers and CLI tests
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
- On every version bump: the version in `pyproject.toml`, the title of `README.md`, the first entry in `CHANGELOG.md`, and the version in the Purpose section of `AGENTS.md` must all match

## Note-taking

- After each task, log any correction, preference, or pattern learned.
- Write to the matching docs file's "Session learnings" section; if none fits, add to Rules above. One dated line, plain language.
  e.g. `Pylint C0114 triggers when module docstring is missing the blank line after triple-quote (learned 4/3)`
- 3+ related notes on a topic → create a new `docs/` context file, move notes there, update the Tree. Keep this file under 100 lines.