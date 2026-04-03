"""
report module.

Defines the ScanResult model for aggregating vulnerability scan findings.

:author: Ron Webb
:since: 1.0.0
"""

from dataclasses import dataclass, field
from datetime import datetime

from .dependency import Dependency

__author__ = "Ron Webb"
__since__ = "1.0.0"


@dataclass
class ScanResult:
    """
    Aggregates all findings from a dependency vulnerability scan.

    :author: Ron Webb
    :since: 1.0.0
    """

    source_file: str
    scanned_at: str = field(default_factory=lambda: datetime.now().isoformat())
    dependencies: list[Dependency] = field(default_factory=list)

    @property
    def total_dependencies(self) -> int:
        """
        Return the total count of all direct and transitive dependencies.

        :author: Ron Webb
        :since: 1.0.0
        """
        return self._count_dependencies(self.dependencies)

    @property
    def vulnerable_dependencies(self) -> list[Dependency]:
        """
        Return a flat list of all dependencies that have vulnerabilities.

        :author: Ron Webb
        :since: 1.0.0
        """
        result: list[Dependency] = []
        self._collect_vulnerable(self.dependencies, result)
        return result

    @property
    def total_vulnerabilities(self) -> int:
        """
        Return the total number of individual vulnerabilities found.

        :author: Ron Webb
        :since: 1.0.0
        """
        return sum(len(dep.vulnerabilities) for dep in self.vulnerable_dependencies)

    def _count_dependencies(self, deps: list[Dependency]) -> int:
        """
        Recursively count all dependencies in the tree.

        :author: Ron Webb
        :since: 1.0.0
        """
        count = len(deps)
        for dep in deps:
            count += self._count_dependencies(dep.transitive_dependencies)
        return count

    def _collect_vulnerable(
        self, deps: list[Dependency], result: list[Dependency]
    ) -> None:
        """
        Recursively collect all dependencies that have vulnerabilities.

        :author: Ron Webb
        :since: 1.0.0
        """
        for dep in deps:
            if dep.vulnerabilities:
                result.append(dep)
            self._collect_vulnerable(dep.transitive_dependencies, result)
