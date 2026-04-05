"""
cli module.

Command-line interface entry point for the Java Dependency Analyzer.

:author: Ron Webb
:since: 1.0.0
"""

import sys
from pathlib import Path

import click

from . import __version__
from .cache.db import delete_database
from .cache.vulnerability_cache import VulnerabilityCache
from .models.dependency import Dependency
from .models.report import ScanResult
from .parsers.gradle_dep_tree_parser import GradleDepTreeParser
from .parsers.gradle_parser import GradleParser
from .parsers.maven_dep_tree_parser import MavenDepTreeParser
from .parsers.maven_parser import MavenParser
from .reporters.html_reporter import HtmlReporter
from .reporters.json_reporter import JsonReporter
from .resolvers.transitive import TransitiveResolver
from .scanners.ghsa_scanner import GhsaScanner
from .scanners.osv_scanner import OsvScanner
from .util.logger import setup_logger

__author__ = "Ron Webb"
__since__ = "1.0.0"

_logger = setup_logger(__name__)

EXIT_VULNERABILITIES_FOUND = 10
"""Exit status returned when vulnerabilities are detected."""

# ---------------------------------------------------------------------------
# Shared CLI options applied to both subcommands
# ---------------------------------------------------------------------------

_COMMON_OPTIONS = [
    click.option(
        "--output-format",
        "-f",
        type=click.Choice(["json", "html", "all"], case_sensitive=False),
        default="all",
        show_default=True,
        help="Output format for the vulnerability report.",
    ),
    click.option(
        "--output-dir",
        "-o",
        default="./reports",
        show_default=True,
        type=click.Path(file_okay=False),
        help="Directory to write the report file(s) into.",
    ),
    click.option(
        "--no-transitive",
        is_flag=True,
        default=False,
        help="Skip transitive dependency resolution (direct dependencies only).",
    ),
    click.option(
        "--verbose",
        "-v",
        is_flag=True,
        default=False,
        help="Enable verbose progress output.",
    ),
    click.option(
        "--rebuild-cache",
        is_flag=True,
        default=False,
        help="Delete the vulnerability cache database before scanning.",
    ),
    click.option(
        "--cache-ttl",
        default=7,
        show_default=True,
        type=int,
        help="Cache TTL in days. Set to 0 to disable caching.",
    ),
]


def _common_options(func):
    """Apply all shared options to a Click command."""
    for option in reversed(_COMMON_OPTIONS):
        func = option(func)
    return func


# ---------------------------------------------------------------------------
# Click group
# ---------------------------------------------------------------------------


@click.group()
def main() -> None:
    """Java Dependency Analyzer -- inspect Java dependency trees for known vulnerabilities."""
    _logger.info("Java Dependency Analyzer v%s", __version__)


# ---------------------------------------------------------------------------
# gradle subcommand
# ---------------------------------------------------------------------------


@main.command()
@click.argument(
    "file",
    required=False,
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True),
)
@click.option(
    "--dependencies",
    "-d",
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help=(
        "Path to a pre-resolved Gradle dependency tree text file "
        "(output of ``gradle dependencies``). When supplied, transitive "
        "resolution is skipped."
    ),
)
@_common_options
def gradle(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    file: str | None,
    dependencies: str | None,
    output_format: str,
    output_dir: str,
    no_transitive: bool,
    verbose: bool,
    rebuild_cache: bool,
    cache_ttl: int,
) -> None:
    """
    Analyse a Gradle build file (build.gradle or build.gradle.kts) for known
    dependency vulnerabilities.

    FILE is the path to a build.gradle or build.gradle.kts file.  Alternatively,
    supply a pre-resolved dependency tree via --dependencies to skip both parsing
    and transitive resolution.

    :author: Ron Webb
    :since: 1.0.0
    """
    if file is None and dependencies is None:
        raise click.UsageError("Provide FILE or --dependencies (or both).")

    if file is not None:
        file_path = Path(file)
        name = file_path.name
        if not (name.endswith("build.gradle.kts") or name.endswith("build.gradle")):
            raise click.UsageError(
                f"Unsupported file: {name}. Expected build.gradle or build.gradle.kts."
            )

    cache = _init_cache(rebuild_cache, cache_ttl, verbose)

    try:
        if dependencies is not None:
            if verbose:
                click.echo(f"Loading dependency tree from {dependencies}...")
            parsed_deps = GradleDepTreeParser().parse(dependencies)
            source = file if file is not None else dependencies
            found = _run_analysis(
                parsed_deps,
                source_file=source,
                output_format=output_format,
                output_dir=output_dir,
                no_transitive=True,
                verbose=verbose,
                cache=cache,
            )
        else:
            if verbose:
                click.echo(f"Parsing {Path(file).name}...")  # type: ignore[arg-type]
            parsed_deps = GradleParser().parse(file)  # type: ignore[arg-type]
            found = _run_analysis(
                parsed_deps,
                source_file=file,  # type: ignore[arg-type]
                output_format=output_format,
                output_dir=output_dir,
                no_transitive=no_transitive,
                verbose=verbose,
                cache=cache,
            )
    finally:
        if cache is not None:
            cache.close()

    if found:
        sys.exit(EXIT_VULNERABILITIES_FOUND)


# ---------------------------------------------------------------------------
# maven subcommand
# ---------------------------------------------------------------------------


@main.command()
@click.argument(
    "file",
    required=False,
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True),
)
@click.option(
    "--dependencies",
    "-d",
    default=None,
    type=click.Path(exists=True, dir_okay=False, readable=True),
    help=(
        "Path to a pre-resolved Maven dependency tree text file "
        "(output of ``mvn dependency:tree``). When supplied, transitive "
        "resolution is skipped."
    ),
)
@_common_options
def maven(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    file: str | None,
    dependencies: str | None,
    output_format: str,
    output_dir: str,
    no_transitive: bool,
    verbose: bool,
    rebuild_cache: bool,
    cache_ttl: int,
) -> None:
    """
    Analyse a Maven POM file (pom.xml) for known dependency vulnerabilities.

    FILE is the path to a pom.xml file.  Alternatively, supply a pre-resolved
    dependency tree via --dependencies to skip both parsing and transitive
    resolution.

    :author: Ron Webb
    :since: 1.0.0
    """
    if file is None and dependencies is None:
        raise click.UsageError("Provide FILE or --dependencies (or both).")

    if file is not None:
        file_path = Path(file)
        if not file_path.name.endswith("pom.xml"):
            raise click.UsageError(
                f"Unsupported file: {file_path.name}. Expected pom.xml."
            )

    cache = _init_cache(rebuild_cache, cache_ttl, verbose)

    try:
        if dependencies is not None:
            if verbose:
                click.echo(f"Loading dependency tree from {dependencies}...")
            parsed_deps = MavenDepTreeParser().parse(dependencies)
            source = file if file is not None else dependencies
            found = _run_analysis(
                parsed_deps,
                source_file=source,
                output_format=output_format,
                output_dir=output_dir,
                no_transitive=True,
                verbose=verbose,
                cache=cache,
            )
        else:
            if verbose:
                click.echo(f"Parsing {Path(file).name}...")  # type: ignore[arg-type]
            parsed_deps = MavenParser().parse(file)  # type: ignore[arg-type]
            found = _run_analysis(
                parsed_deps,
                source_file=file,  # type: ignore[arg-type]
                output_format=output_format,
                output_dir=output_dir,
                no_transitive=no_transitive,
                verbose=verbose,
                cache=cache,
            )
    finally:
        if cache is not None:
            cache.close()

    if found:
        sys.exit(EXIT_VULNERABILITIES_FOUND)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _init_cache(
    rebuild_cache: bool, cache_ttl: int, verbose: bool
) -> VulnerabilityCache | None:
    """
    Optionally clear and then create the vulnerability cache.

    :author: Ron Webb
    :since: 1.0.0
    """
    if rebuild_cache:
        delete_database()
        if verbose:
            click.echo("Vulnerability cache cleared.")

    return VulnerabilityCache(ttl_days=cache_ttl) if cache_ttl > 0 else None


def _run_analysis(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    dependencies: list[Dependency],
    source_file: str,
    output_format: str,
    output_dir: str,
    no_transitive: bool,
    verbose: bool,
    cache: VulnerabilityCache | None,
) -> bool:
    """
    Resolve transitive dependencies (unless skipped), scan for vulnerabilities,
    and write the requested reports.

    Returns True when at least one vulnerability was detected, False otherwise.

    :author: Ron Webb
    :since: 1.0.0
    """
    if not dependencies:
        click.echo("No runtime dependencies found.", err=True)

    if verbose:
        click.echo(f"Found {len(dependencies)} direct dependencies.")

    if not no_transitive:
        if verbose:
            click.echo("Resolving transitive dependencies from Maven Central...")
        TransitiveResolver().resolve_all(dependencies)

    if verbose:
        click.echo("Scanning for vulnerabilities...")

    osv = OsvScanner(cache=cache)
    ghsa = GhsaScanner(cache=cache)
    _scan_all(dependencies, osv, ghsa, verbose)

    result = ScanResult(source_file=source_file, dependencies=dependencies)

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    _write_reports(result, Path(output_dir), output_format, verbose)

    click.echo(
        f"\nScan complete. "
        f"{result.total_dependencies} dependencies, "
        f"{result.total_vulnerabilities} vulnerabilities found."
    )

    return result.total_vulnerabilities > 0


def _scan_all(
    dependencies: list[Dependency],
    osv: OsvScanner,
    ghsa: GhsaScanner,
    verbose: bool,
) -> None:
    """
    Recursively scan all dependencies (direct + transitive) for vulnerabilities.

    Uses the GitHub Advisory Database (GHSA) as the primary source.  When GHSA
    returns no results -- either because the API failed or no advisories were
    found -- the OSV.dev scanner is used as a fallback.

    :author: Ron Webb
    :since: 1.0.0
    """
    for dep in dependencies:
        if verbose:
            click.echo(f"  Scanning {dep.coordinates}...")
        if not ghsa.rate_limited:
            ghsa_vulns = ghsa.scan(dep)
            if ghsa.rate_limited:
                click.echo(
                    "  GHSA rate limit exceeded; "
                    "falling back to OSV for remaining dependencies.",
                    err=True,
                )
                ghsa_vulns = []
        else:
            ghsa_vulns = []
        dep.vulnerabilities = ghsa_vulns if ghsa_vulns else osv.scan(dep)
        _scan_all(dep.transitive_dependencies, osv, ghsa, verbose)


def _write_reports(
    result: ScanResult, output_dir: Path, output_format: str, verbose: bool
) -> None:
    """
    Write one or both report formats based on the --output-format flag.

    :author: Ron Webb
    :since: 1.0.0
    """
    stem = Path(result.source_file).stem

    if output_format in ("json", "all"):
        json_path = output_dir / f"{stem}-report.json"
        JsonReporter().report(result, str(json_path))
        if verbose:
            click.echo(f"JSON report: {json_path}")

    if output_format in ("html", "all"):
        html_path = output_dir / f"{stem}-report.html"
        HtmlReporter().report(result, str(html_path))
        if verbose:
            click.echo(f"HTML report: {html_path}")
