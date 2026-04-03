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
        html = template.render(result=result, all_deps=all_deps)

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
