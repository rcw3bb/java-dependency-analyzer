"""
html_reporter module.

Renders vulnerability scan results as an HTML report using Jinja2.

:author: Ron Webb
:since: 1.0.0
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..models.dependency import Dependency
from ..models.report import ScanResult
from ..util.logger import setup_logger
from .base import Reporter

__author__ = "Ron Webb"
__since__ = "1.0.0"

_logger = setup_logger(__name__)
_TEMPLATES_DIR = Path(__file__).parent / "templates"


class HtmlReporter(Reporter):
    """
    Renders a ScanResult to an HTML report file using the Jinja2 template engine.

    :author: Ron Webb
    :since: 1.0.0
    """

    def __init__(self) -> None:
        """
        Initialise the Jinja2 environment pointing at the bundled templates directory.

        :author: Ron Webb
        :since: 1.0.0
        """
        self._env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=select_autoescape(["html"]),
        )

    def report(self, result: ScanResult, output_path: str) -> None:
        """
        Render the scan result to an HTML file at the given output path.

        :author: Ron Webb
        :since: 1.0.0
        """
        template = self._env.get_template("report.html")
        all_deps = self._flatten_dependencies(result.dependencies)
        vuln_scopes = self._compute_vuln_scopes(
            all_deps, result.vulnerable_dependencies
        )
        html = template.render(
            result=result, all_deps=all_deps, vuln_scopes=vuln_scopes
        )

        _logger.info("Writing HTML report to %s", output_path)
        with open(output_path, "w", encoding="utf-8") as file_handle:
            file_handle.write(html)
        _logger.info("HTML report written: %s", output_path)

    def _flatten_dependencies(self, deps: list[Dependency]) -> list[Dependency]:
        """
        Flatten the dependency tree into a single ordered list for tabular display.

        :author: Ron Webb
        :since: 1.0.0
        """
        result: list[Dependency] = []
        self._collect(deps, result)
        return result

    def _collect(self, deps: list[Dependency], result: list[Dependency]) -> None:
        """
        Recursively append dependencies to the result list (pre-order traversal).

        :author: Ron Webb
        :since: 1.0.0
        """
        for dep in deps:
            result.append(dep)
            self._collect(dep.transitive_dependencies, result)

    def _compute_vuln_scopes(
        self,
        all_flat_deps: list[Dependency],
        vulnerable_deps: list[Dependency],
    ) -> dict[str, list[str]]:
        """
        Build a mapping from dependency coordinates to sorted list of all scopes
        in which that dependency appears, restricted to vulnerable dependencies.

        :author: Ron Webb
        :since: 1.3.0
        """
        vuln_keys = {(d.group_id, d.artifact_id, d.version) for d in vulnerable_deps}
        scopes_map: dict[str, set[str]] = {}
        for dep in all_flat_deps:
            key = (dep.group_id, dep.artifact_id, dep.version)
            if key in vuln_keys:
                coord_str = f"{dep.group_id}:{dep.artifact_id}:{dep.version}"
                scopes_map.setdefault(coord_str, set()).add(dep.scope)
        return {k: sorted(v) for k, v in scopes_map.items()}
