"""
base module.

Defines the abstract base class for scan result reporters.

:author: Ron Webb
:since: 1.0.0
"""

from abc import ABC, abstractmethod

from ..models.report import ScanResult

__author__ = "Ron Webb"
__since__ = "1.0.0"


class Reporter(ABC):
    """
    Abstract base class for all scan result reporters.

    :author: Ron Webb
    :since: 1.0.0
    """

    @abstractmethod
    def report(self, result: ScanResult, output_path: str) -> None:
        """
        Write the scan result to the given output path.

        :author: Ron Webb
        :since: 1.0.0
        """
