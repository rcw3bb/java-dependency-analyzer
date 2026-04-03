"""
base module.

Defines the abstract base class for dependency file parsers.

:author: Ron Webb
:since: 1.0.0
"""

from abc import ABC, abstractmethod

from ..models.dependency import Dependency

__author__ = "Ron Webb"
__since__ = "1.0.0"

# Runtime scopes that contribute to the executable classpath
RUNTIME_SCOPES = frozenset({"compile", "runtime", "implementation", "api", "runtimeOnly"})


class DependencyParser(ABC):
    """
    Abstract base class for all dependency file parsers.

    :author: Ron Webb
    :since: 1.0.0
    """

    @abstractmethod
    def parse(self, file_path: str) -> list[Dependency]:
        """
        Parse the given build file and return a list of direct dependencies.

        Only runtime-relevant scopes are returned (compile, runtime,
        implementation, api, runtimeOnly).

        :author: Ron Webb
        :since: 1.0.0
        """
