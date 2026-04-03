"""
cli module.

Command-line interface entry point for the Java Dependency Analyzer.

:author: Ron Webb
:since: 1.0.0
"""

import sys
from pathlib import Path

import click

from .models.report import ScanResult
from .parsers.gradle_parser import GradleParser
from .parsers.maven_parser import MavenParser
from .reporters.html_reporter import HtmlReporter
from .reporters.json_reporter import JsonReporter
from .resolvers.transitive import TransitiveResolver
from .scanners.mvn_repository import MvnRepositoryScanner
from .scanners.osv_scanner import OsvScanner
from .util.logger import setup_logger

__author__ = "Ron Webb"
__since__ = "1.0.0"

_logger = setup_logger(__name__)


@click.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option(
    "--output-format",
    "-f",
    type=click.Choice(["json", "html", "all"], case_sensitive=False),
    default="all",
    show_default=True,
    help="Output format for the vulnerability report.",
)
@click.option(
    "--output-dir",
    "-o",
    default=".",
    show_default=True,
    type=click.Path(file_okay=False),
    help="Directory to write the report file(s) into.",
)
@click.option(
    "--no-transitive",
    is_flag=True,
    default=False,
    help="Skip transitive dependency resolution (direct dependencies only).",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable verbose progress output.",
)
def main(
    file: str,
    output_format: str,
    output_dir: str,
    no_transitive: bool,
    verbose: bool,
) -> None:
    """
    Analyse a Maven pom.xml or Gradle build.gradle(.kts) file for known dependency vulnerabilities.

    FILE is the path to the pom.xml, build.gradle, or build.gradle.kts file to analyse.

    :author: Ron Webb
    :since: 1.0.0
    """
    file_path = Path(file)
    _logger.info("Starting analysis of: %s", file_path)

    parser = _get_parser(file_path)
    if parser is None:
        click.echo(
            f"Unsupported file: {file_path.name}. "
            "Expected pom.xml, build.gradle, or build.gradle.kts.",
            err=True,
        )
        sys.exit(1)

    if verbose:
        click.echo(f"Parsing {file_path.name}...")

    dependencies = parser.parse(str(file_path))
    if not dependencies:
        click.echo("No runtime dependencies found.", err=True)

    if verbose:
        click.echo(f"Found {len(dependencies)} direct dependencies.")

    if not no_transitive:
        if verbose:
            click.echo("Resolving transitive dependencies from Maven Central...")
        resolver = TransitiveResolver()
        resolver.resolve_all(dependencies)

    if verbose:
        click.echo("Scanning for vulnerabilities...")

    osv = OsvScanner()
    mvnrepo = MvnRepositoryScanner()
    _scan_all(dependencies, osv, mvnrepo, verbose)

    result = ScanResult(source_file=str(file_path), dependencies=dependencies)

    output_dir_path = Path(output_dir)
    output_dir_path.mkdir(parents=True, exist_ok=True)

    _write_reports(result, output_dir_path, output_format, verbose)

    click.echo(
        f"\nScan complete. "
        f"{result.total_dependencies} dependencies, "
        f"{result.total_vulnerabilities} vulnerabilities found."
    )


def _get_parser(file_path: Path):
    """
    Return the appropriate DependencyParser for the given file, or None if unsupported.

    Matches by filename suffix so both ``pom.xml`` and ``my-app-pom.xml`` are accepted.

    :author: Ron Webb
    :since: 1.0.0
    """
    name = file_path.name
    if name.endswith("pom.xml"):
        return MavenParser()
    if name.endswith("build.gradle.kts"):
        return GradleParser()
    if name.endswith("build.gradle"):
        return GradleParser()
    return None


def _scan_all(dependencies, osv: OsvScanner, mvnrepo: MvnRepositoryScanner, verbose: bool) -> None:
    """
    Recursively scan all dependencies (direct + transitive) for vulnerabilities.

    Merges results from OSV.dev and mvnrepository.com, deduplicating by CVE ID.

    :author: Ron Webb
    :since: 1.0.0
    """
    for dep in dependencies:
        if verbose:
            click.echo(f"  Scanning {dep.coordinates}...")
        osv_vulns = osv.scan(dep)
        mvn_vulns = mvnrepo.scan(dep)
        dep.vulnerabilities = _merge_vulns(osv_vulns, mvn_vulns)
        _scan_all(dep.transitive_dependencies, osv, mvnrepo, verbose)


def _merge_vulns(primary, secondary) -> list:
    """
    Merge two vulnerability lists, deduplicating by CVE ID.

    OSV results take precedence; only mvnrepository entries with unknown/new IDs are added.

    :author: Ron Webb
    :since: 1.0.0
    """
    seen_ids = {v.cve_id for v in primary}
    merged = list(primary)
    for vuln in secondary:
        if vuln.cve_id not in seen_ids:
            merged.append(vuln)
            seen_ids.add(vuln.cve_id)
    return merged


def _write_reports(result: ScanResult, output_dir: Path, output_format: str, verbose: bool) -> None:
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
