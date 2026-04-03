"""
base module.

Defines the abstract base class for vulnerability scanners.

:author: Ron Webb
:since: 1.0.0
"""

from abc import ABC, abstractmethod

from ..models.dependency import Dependency, Vulnerability

__author__ = "Ron Webb"
__since__ = "1.0.0"


class VulnerabilityScanner(ABC):
    """
    Abstract base class for all vulnerability scanners.

    :author: Ron Webb
    :since: 1.0.0
    """

    @abstractmethod
    def scan(self, dependency: Dependency) -> list[Vulnerability]:
        """
        Scan the given dependency for known vulnerabilities.

        Returns a list of Vulnerability objects found for this exact version.

        :author: Ron Webb
        :since: 1.0.0
        """
