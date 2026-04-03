"""
dependency module.

Defines the core data models for dependencies and vulnerabilities.

:author: Ron Webb
:since: 1.0.0
"""

from dataclasses import dataclass, field

__author__ = "Ron Webb"
__since__ = "1.0.0"


@dataclass
class Vulnerability:
    """
    Represents a single vulnerability found in a dependency.

    :author: Ron Webb
    :since: 1.0.0
    """

    cve_id: str
    summary: str
    severity: str
    affected_versions: list[str] = field(default_factory=list)
    source: str = "osv"
    reference_url: str = ""


@dataclass
class Dependency:
    """
    Represents a Java dependency with group, artifact, and version coordinates.

    :author: Ron Webb
    :since: 1.0.0
    """

    group_id: str
    artifact_id: str
    version: str
    scope: str = "compile"
    depth: int = 0
    transitive_dependencies: list["Dependency"] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @property
    def coordinates(self) -> str:
        """
        Return Maven coordinates string in group:artifact:version format.

        :author: Ron Webb
        :since: 1.0.0
        """
        return f"{self.group_id}:{self.artifact_id}:{self.version}"

    @property
    def maven_path(self) -> str:
        """
        Return the relative path to this artifact in a Maven repository.

        :author: Ron Webb
        :since: 1.0.0
        """
        group_path = self.group_id.replace(".", "/")
        return f"{group_path}/{self.artifact_id}/{self.version}"

    def has_vulnerabilities(self) -> bool:
        """
        Return True if this dependency or any transitive dependency has vulnerabilities.

        :author: Ron Webb
        :since: 1.0.0
        """
        if self.vulnerabilities:
            return True
        return any(dep.has_vulnerabilities() for dep in self.transitive_dependencies)
