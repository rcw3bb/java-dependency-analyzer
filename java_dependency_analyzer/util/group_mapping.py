"""
group_mapping module.

Loads a group mapping file that tells the jar resolver which Maven group an
artifact belongs to.

:author: Ron Webb
:since: 1.6.0
"""

from pathlib import Path

from .logger import setup_logger

__author__ = "Ron Webb"
__since__ = "1.6.0"

_logger = setup_logger(__name__)


def load_group_mapping(file_path: str) -> dict[str, list[str]]:
    """
    Read *file_path* and return the groups of each artifact, in file order.

    Every line is ``<group>:<artifact>``.  Blank lines and lines starting with
    ``#`` are ignored; malformed lines are skipped with a warning.  An artifact
    listed under several groups keeps all of them, without duplicates.

    :author: Ron Webb
    :since: 1.6.0
    """
    content = Path(file_path).read_text(encoding="utf-8-sig")
    mapping: dict[str, list[str]] = {}
    for number, raw in enumerate(content.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        group, _, artifact = (part.strip() for part in line.partition(":"))
        if not group or not artifact or ":" in artifact:
            _logger.warning(
                "Skipping line %d of %s: expected <group>:<artifact>", number, file_path
            )
            continue
        groups = mapping.setdefault(artifact, [])
        if group not in groups:
            groups.append(group)
    return mapping
