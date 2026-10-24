"""
java_dependency_analyzer package.

Java Dependency Analyzer is a tool that inspects dependencies.

:author: Ron Webb
:since: 1.0.0
"""

from importlib.metadata import version, PackageNotFoundError

__author__ = "Ron Webb"
__since__ = "1.0.0"
__app_name__ = "Java Dependency Analyzer"
try:
    __version__ = version("java-dependency-analyzer")
except PackageNotFoundError:
    __version__ = "unknown"
