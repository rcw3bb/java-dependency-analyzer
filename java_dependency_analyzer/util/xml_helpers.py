"""
xml_helpers module.

Shared utilities for working with Maven POM XML documents.

:author: Ron Webb
:since: 1.2.1
"""

from lxml import etree  # pylint: disable=c-extension-no-member

__author__ = "Ron Webb"
__since__ = "1.2.1"

# Standard Maven POM XML namespace
POM_NS = "http://maven.apache.org/POM/4.0.0"


def detect_pom_namespace(
    root: etree._Element,
) -> dict[str, str]:  # pylint: disable=c-extension-no-member
    """
    Return the namespace map when the POM root element uses the standard Maven namespace.

    Returns ``{"m": POM_NS}`` when the root tag uses the standard Maven namespace,
    or an empty dict for namespace-free or non-Maven XML documents.

    :author: Ron Webb
    :since: 1.2.1
    """
    return {"m": POM_NS} if root.tag.startswith(f"{{{POM_NS}}}") else {}
