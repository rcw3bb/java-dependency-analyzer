"""
cli module.

Command-line interface entry point for the Java Dependency Analyzer.

:author: Ron Webb
:since: 1.0.0
"""

import os
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime
from functools import partial
from pathlib import Path

import click
from rich.console import Console
from rich.status import Status

from . import __version__
from .cache.db import delete_database
from .cache.vulnerability_cache import VulnerabilityCache
from .models.dependency import Dependency
from .models.report import ScanResult
from .parsers.base import DependencyParser
from .parsers.gradle_dep_tree_parser import GradleDepTreeParser
from .parsers.gradle_parser import GradleParser
from .parsers.maven_dep_tree_parser import MavenDepTreeParser
from .parsers.maven_parser import MavenParser
from .parsers.sbom_parser import SbomParser
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
    click.option(
        "--project",
        "-p",
        default=None,
        type=click.Path(exists=True, file_okay=False, readable=True),
        help=(
            "Root directory of the project to analyse. When supplied, the dependency "
            "tree is generated automatically and FILE / --dependencies must not be used."
        ),
    ),
    click.option(
        "--java-home",
        default=None,
        type=str,
        help=(
            "Directory to use as JAVA_HOME. Defaults to the system JAVA_HOME "
            "environment variable. Can only be used with --project."
        ),
    ),
    click.option(
        "--use-wrapper",
        is_flag=True,
        default=False,
        help=(
            "Use the project wrapper script (gradlew/mvnw) instead of the "
            "system build tool. Can only be used with --project."
        ),
    ),
    click.option(
        "--wrapper",
        default=None,
        type=str,
        help=(
            "Custom wrapper script name to use instead of the default "
            "(gradlew/gradlew.bat or mvnw/mvnw.cmd). "
            "Can only be used with --use-wrapper."
        ),
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
@click.option(
    "--module",
    default=None,
    type=str,
    help=(
        "Gradle module name. When supplied, the dependency task becomes "
        "``<module>:dependencies``. Can only be used with --project."
    ),
)
@_common_options
def gradle(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    file: str | None,
    dependencies: str | None,
    module: str | None,
    output_format: str,
    output_dir: str,
    no_transitive: bool,
    verbose: bool,
    rebuild_cache: bool,
    cache_ttl: int,
    project: str | None,
    java_home: str | None,
    use_wrapper: bool,
    wrapper: str | None,
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
    _validate_project_params(
        project, java_home, use_wrapper, file, dependencies, wrapper
    )

    if module is not None and project is None:
        raise click.UsageError("--module can only be used with --project.")

    if file is not None:
        file_path = Path(file).resolve()
        name = file_path.name
        if not (name.endswith("build.gradle.kts") or name.endswith("build.gradle")):
            raise click.UsageError(
                f"Unsupported file: {name}. Expected build.gradle or build.gradle.kts."
            )

    cache = _init_cache(rebuild_cache, cache_ttl, verbose)

    try:
        found = _run_tool_analysis(
            file,
            dependencies,
            output_format,
            output_dir,
            no_transitive,
            verbose,
            cache,
            project,
            java_home,
            use_wrapper,
            dep_tree_parser_cls=GradleDepTreeParser,
            file_parser_cls=GradleParser,
            build_cmd_fn=partial(_build_gradle_dep_cmd, module=module, wrapper=wrapper),
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
def maven(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    file: str | None,
    dependencies: str | None,
    output_format: str,
    output_dir: str,
    no_transitive: bool,
    verbose: bool,
    rebuild_cache: bool,
    cache_ttl: int,
    project: str | None,
    java_home: str | None,
    use_wrapper: bool,
    wrapper: str | None,
) -> None:
    """
    Analyse a Maven POM file (pom.xml) for known dependency vulnerabilities.

    FILE is the path to a pom.xml file.  Alternatively, supply a pre-resolved
    dependency tree via --dependencies to skip both parsing and transitive
    resolution.

    :author: Ron Webb
    :since: 1.0.0
    """
    _validate_project_params(
        project, java_home, use_wrapper, file, dependencies, wrapper
    )

    if file is not None:
        file_path = Path(file).resolve()
        if not file_path.name.endswith("pom.xml"):
            raise click.UsageError(
                f"Unsupported file: {file_path.name}. Expected pom.xml."
            )

    cache = _init_cache(rebuild_cache, cache_ttl, verbose)

    try:
        found = _run_tool_analysis(
            file,
            dependencies,
            output_format,
            output_dir,
            no_transitive,
            verbose,
            cache,
            project,
            java_home,
            use_wrapper,
            dep_tree_parser_cls=MavenDepTreeParser,
            file_parser_cls=MavenParser,
            build_cmd_fn=partial(_build_maven_dep_cmd, wrapper=wrapper),
        )
    finally:
        if cache is not None:
            cache.close()

    if found:
        sys.exit(EXIT_VULNERABILITIES_FOUND)


# ---------------------------------------------------------------------------
# sbom subcommand
# ---------------------------------------------------------------------------


@main.command()
@click.option(
    "--standard",
    "-s",
    type=click.Choice(["spdx", "cyclonedx", "swid"], case_sensitive=False),
    required=True,
    help="SBOM standard of the input file (spdx, cyclonedx, or swid).",
)
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
    default="./reports",
    show_default=True,
    type=click.Path(file_okay=False),
    help="Directory to write the report file(s) into.",
)
@click.option(
    "--no-transitive",
    is_flag=True,
    default=False,
    help="Skip transitive dependency resolution.",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable verbose progress output.",
)
@click.option(
    "--rebuild-cache",
    is_flag=True,
    default=False,
    help="Delete the vulnerability cache database before scanning.",
)
@click.option(
    "--cache-ttl",
    default=7,
    show_default=True,
    type=int,
    help="Cache TTL in days. Set to 0 to disable caching.",
)
@click.argument(
    "file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True),
)
def sbom(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    standard: str,
    output_format: str,
    output_dir: str,
    no_transitive: bool,
    verbose: bool,
    rebuild_cache: bool,
    cache_ttl: int,
    file: str,
) -> None:
    """
    Scan an SBOM (Software Bill of Materials) file for known dependency vulnerabilities.

    FILE is the path to an SBOM JSON file whose format matches --standard.
    Supported standards: spdx (SPDX 2.3), cyclonedx (CycloneDX 1.6), swid (ISO/IEC 19770-2).

    :author: Ron Webb
    :since: 1.4.0
    """
    file_path = Path(file).resolve()
    if file_path.suffix.lower() != ".json":
        raise click.UsageError(
            f"Unsupported file: {file_path.name}. FILE must be a JSON file."
        )

    if verbose:
        click.echo(f"Parsing {file_path.name} as {standard.upper()} SBOM...")

    cache = _init_cache(rebuild_cache, cache_ttl, verbose)

    try:
        parsed_deps = SbomParser(standard).parse(str(file_path))
        found = _run_analysis(
            parsed_deps,
            source_file=str(file_path),
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


def _validate_project_params(  # pylint: disable=too-many-positional-arguments,too-many-arguments
    project: str | None,
    java_home: str | None,
    use_wrapper: bool,
    file: str | None,
    dependencies: str | None,
    wrapper: str | None = None,
) -> None:
    """
    Validate mutual exclusion rules for --project, --java-home, --use-wrapper, and --wrapper.

    Raises ``click.UsageError`` when incompatible options are combined or when
    no input source at all is provided.

    :author: Ron Webb
    :since: 1.3.0
    """
    if wrapper is not None and not use_wrapper:
        raise click.UsageError("--wrapper can only be used with --use-wrapper.")
    if (java_home is not None or use_wrapper) and project is None:
        raise click.UsageError(
            "--java-home and --use-wrapper can only be used with --project."
        )
    if project is not None and (file is not None or dependencies is not None):
        raise click.UsageError(
            "--project cannot be combined with FILE or --dependencies (-d)."
        )
    if project is None and file is None and dependencies is None:
        raise click.UsageError("Provide FILE, --dependencies (-d), or --project.")


def _resolve_java_home(java_home: str | None) -> str:
    """
    Return the JAVA_HOME to use for the build-tool invocation.

    Checks *java_home* first, then the ``JAVA_HOME`` environment variable.
    Raises ``click.UsageError`` when neither is available.

    :author: Ron Webb
    :since: 1.3.0
    """
    value = java_home or os.environ.get("JAVA_HOME")
    if not value:
        raise click.UsageError(
            "JAVA_HOME is not set. Supply --java-home or set the JAVA_HOME "
            "environment variable."
        )
    return value


def _build_dep_cmd(  # pylint: disable=too-many-arguments
    project_dir: Path,
    use_wrapper: bool,
    *,
    wrapper_win: str,
    wrapper_unix: str,
    tool: str,
    task: str,
    wrapper: str | None = None,
) -> list[str]:
    """
    Build a build-tool command list, shared by Gradle and Maven.

    On Windows the wrapper is invoked via ``cmd /c``; on other platforms it is
    called directly.  Raises ``click.UsageError`` when ``use_wrapper`` is
    ``True`` but the expected wrapper script is absent from *project_dir*.

    When *wrapper* is supplied it overrides the default platform wrapper script name.

    :author: Ron Webb
    :since: 1.3.0
    """
    if use_wrapper:
        if wrapper is not None:
            wrapper_path = project_dir / wrapper
        else:
            wrapper_path = project_dir / (
                wrapper_win if sys.platform == "win32" else wrapper_unix
            )
        if not wrapper_path.exists():
            raise click.UsageError(
                f"Build tool wrapper not found at {wrapper_path}. "
                "Ensure it exists in the project directory or disable --use-wrapper."
            )
        prefix = (
            ["cmd", "/c", str(wrapper_path)]
            if sys.platform == "win32"
            else [str(wrapper_path)]
        )
        return prefix + [task]
    if sys.platform == "win32":
        return ["cmd", "/c", tool, task]
    return [tool, task]


def _build_gradle_dep_cmd(
    project_dir: Path,
    use_wrapper: bool,
    *,
    module: str | None = None,
    wrapper: str | None = None,
) -> list[str]:
    """
    Build the command list for generating a Gradle dependency tree.

    On Windows the wrapper is ``gradlew.bat`` and is invoked via ``cmd /c``;
    on other platforms it is ``gradlew`` and called directly.

    When *module* is supplied the task becomes ``<module>:dependencies``.
    When *wrapper* is supplied it overrides the default wrapper script name.

    Raises ``click.UsageError`` when ``use_wrapper`` is ``True`` but no
    wrapper script is found in *project_dir*.

    :author: Ron Webb
    :since: 1.3.0
    """
    task = f"{module}:dependencies" if module else "dependencies"
    return _build_dep_cmd(
        project_dir,
        use_wrapper,
        wrapper_win="gradlew.bat",
        wrapper_unix="gradlew",
        tool="gradle",
        task=task,
        wrapper=wrapper,
    )


def _build_maven_dep_cmd(
    project_dir: Path,
    use_wrapper: bool,
    *,
    wrapper: str | None = None,
) -> list[str]:
    """
    Build the command list for generating a Maven dependency tree.

    On Windows the wrapper is ``mvnw.cmd`` and is invoked via ``cmd /c``;
    on other platforms it is ``mvnw`` and called directly.

    When *wrapper* is supplied it overrides the default wrapper script name.

    Raises ``click.UsageError`` when ``use_wrapper`` is ``True`` but no
    wrapper script is found in *project_dir*.

    :author: Ron Webb
    :since: 1.3.0
    """
    return _build_dep_cmd(
        project_dir,
        use_wrapper,
        wrapper_win="mvnw.cmd",
        wrapper_unix="mvnw",
        tool="mvn",
        task="dependency:tree",
        wrapper=wrapper,
    )


def _execute_dep_tree_cmd(
    cmd: list[str], project_dir: Path, java_home: str, temp_file: Path
) -> None:
    """
    Execute *cmd* in *project_dir* with ``JAVA_HOME`` set, writing stdout to *temp_file*.

    Raises ``click.ClickException`` when the process exits with a non-zero return code.
    Raises ``click.UsageError`` when the build-tool executable is not found on PATH.

    :author: Ron Webb
    :since: 1.3.0
    """
    env = os.environ.copy()
    env["JAVA_HOME"] = java_home
    try:
        with open(temp_file, "w", encoding="utf-8") as out_file:
            proc = subprocess.run(
                cmd,
                cwd=str(project_dir),
                env=env,
                stdout=out_file,
                stderr=subprocess.PIPE,
                check=False,
            )
        if proc.returncode != 0:
            stderr_text = proc.stderr.decode("utf-8", errors="replace").strip()
            raise click.ClickException(
                f"Build tool exited with code {proc.returncode}. "
                f"stderr: {stderr_text}"
            )
    except FileNotFoundError as exc:
        raise click.UsageError(
            f"Build tool not found: {cmd[0]}. "
            "Ensure it is installed and available on PATH."
        ) from exc


def _generate_dep_tree(  # pylint: disable=too-many-arguments,too-many-positional-arguments
    project: str,
    java_home: str | None,
    use_wrapper: bool,
    build_cmd_fn: Callable[[Path, bool], list[str]],
    output_dir: str,
    verbose: bool,
) -> Path:
    """
    Generate a dependency tree for *project* and save it to a timestamped file.

    Creates *output_dir* when it does not already exist and returns the path of
    the generated dependency-tree file (the TEMP_FILE).

    :author: Ron Webb
    :since: 1.3.0
    """
    project_dir = Path(project).resolve()
    java_home_str = _resolve_java_home(java_home)
    cmd = build_cmd_fn(project_dir, use_wrapper)

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    temp_file = Path(output_dir) / f"{project_dir.name}-deps-{timestamp}.txt"

    if verbose:
        click.echo(f"Running: {' '.join(cmd)} in {project_dir}...")

    _execute_dep_tree_cmd(cmd, project_dir, java_home_str, temp_file)

    if verbose:
        click.echo(f"Dependency tree saved to {temp_file}")

    return temp_file


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
    project_dir: str | None = None,
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
    _console = Console(stderr=True)
    with _console.status("Scanning dependencies...") as _status:
        _scan_all(dependencies, osv, ghsa, verbose, _status)

    result = ScanResult(
        source_file=source_file,
        dependencies=dependencies,
        project_dir=project_dir,
    )

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    with _console.status("Writing reports...") as _status:
        _write_reports(result, Path(output_dir), output_format, verbose, _status)

    click.echo(
        f"\nScan complete. "
        f"{result.total_dependencies} dependencies, "
        f"{result.total_vulnerabilities} vulnerabilities found."
    )

    return result.total_vulnerabilities > 0


def _run_tool_analysis(  # pylint: disable=too-many-arguments,too-many-positional-arguments,too-many-locals
    file: str | None,
    dependencies: str | None,
    output_format: str,
    output_dir: str,
    no_transitive: bool,
    verbose: bool,
    cache: VulnerabilityCache | None,
    project: str | None,
    java_home: str | None,
    use_wrapper: bool,
    dep_tree_parser_cls: type[DependencyParser],
    file_parser_cls: type[DependencyParser],
    build_cmd_fn: Callable[[Path, bool], list[str]],
) -> bool:
    """
    Execute the shared ``if project / elif dependencies / else`` analysis flow.

    Selects the appropriate parser based on the supplied arguments, runs the
    analysis via :func:`_run_analysis`, and returns ``True`` when at least one
    vulnerability was found.

    :author: Ron Webb
    :since: 1.3.0
    """
    if project is not None:
        temp_file = _generate_dep_tree(
            project,
            java_home,
            use_wrapper,
            build_cmd_fn,
            output_dir,
            verbose,
        )
        parsed_deps = dep_tree_parser_cls().parse(str(temp_file))
        return _run_analysis(
            parsed_deps,
            source_file=str(temp_file),
            output_format=output_format,
            output_dir=output_dir,
            no_transitive=True,
            verbose=verbose,
            cache=cache,
            project_dir=project,
        )
    if dependencies is not None:
        if verbose:
            click.echo(f"Loading dependency tree from {dependencies}...")
        parsed_deps = dep_tree_parser_cls().parse(dependencies)
        source = file if file is not None else dependencies
        return _run_analysis(
            parsed_deps,
            source_file=source,
            output_format=output_format,
            output_dir=output_dir,
            no_transitive=True,
            verbose=verbose,
            cache=cache,
        )
    if verbose:
        click.echo(f"Parsing {Path(file).name}...")  # type: ignore[arg-type]
    parsed_deps = file_parser_cls().parse(file)  # type: ignore[arg-type]
    return _run_analysis(
        parsed_deps,
        source_file=file,  # type: ignore[arg-type]
        output_format=output_format,
        output_dir=output_dir,
        no_transitive=no_transitive,
        verbose=verbose,
        cache=cache,
    )


def _scan_all(  # pylint: disable=too-many-positional-arguments,too-many-arguments
    dependencies: list[Dependency],
    osv: OsvScanner,
    ghsa: GhsaScanner,
    verbose: bool,
    status: Status | None = None,
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
        if status is not None:
            status.update(f"Scanning {dep.coordinates}...")
        elif verbose:
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
        _scan_all(dep.transitive_dependencies, osv, ghsa, verbose, status)


def _write_reports(  # pylint: disable=too-many-positional-arguments,too-many-arguments
    result: ScanResult,
    output_dir: Path,
    output_format: str,
    verbose: bool,
    status: Status | None = None,
) -> None:
    """
    Write one or both report formats based on the --output-format flag.

    :author: Ron Webb
    :since: 1.0.0
    """
    stem = Path(result.source_file).stem

    if output_format in ("json", "all"):
        json_path = output_dir / f"{stem}-report.json"
        if status is not None:
            status.update(f"Writing JSON report to {json_path}...")
        JsonReporter().report(result, str(json_path))
        if verbose:
            click.echo(f"JSON report: {json_path}")

    if output_format in ("html", "all"):
        html_path = output_dir / f"{stem}-report.html"
        if status is not None:
            status.update(f"Writing HTML report to {html_path}...")
        HtmlReporter().report(result, str(html_path))
        if verbose:
            click.echo(f"HTML report: {html_path}")
