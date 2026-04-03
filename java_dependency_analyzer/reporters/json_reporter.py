"""
json_reporter module.

Writes vulnerability scan results to a JSON file.

:author: Ron Webb
:since: 1.0.0
"""

import json
from dataclasses import asdict

from ..models.report import ScanResult
from ..util.logger import setup_logger
from .base import Reporter

__author__ = "Ron Webb"
__since__ = "1.0.0"

_logger = setup_logger(__name__)


class JsonReporter(Reporter):
    """
    Serialises a ScanResult to a formatted JSON file.

    :author: Ron Webb
    :since: 1.0.0
    """

    def report(self, result: ScanResult, output_path: str) -> None:
        """
        Write the scan result as pretty-printed JSON to the given path.

        :author: Ron Webb
        :since: 1.0.0
        """
        data = {
            "source_file": result.source_file,
            "scanned_at": result.scanned_at,
            "summary": {
                "total_dependencies": result.total_dependencies,
                "total_vulnerabilities": result.total_vulnerabilities,
                "vulnerable_dependency_count": len(result.vulnerable_dependencies),
            },
            "dependencies": [asdict(dep) for dep in result.dependencies],
        }

        _logger.info("Writing JSON report to %s", output_path)
        with open(output_path, "w", encoding="utf-8") as file_handle:
            json.dump(data, file_handle, indent=2, default=str)
        _logger.info("JSON report written: %s", output_path)
