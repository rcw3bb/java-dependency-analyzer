"""
logger module.

Provides a setup_logger function for consistent logging configuration.

:author: Ron Webb
:since: 1.0.0
"""

import importlib.resources
import logging
import logging.config
import os
import shutil
from pathlib import Path

from rich.logging import RichHandler

__author__ = "Ron Webb"
__since__ = "1.0.0"


def _load_config(config_path: str) -> None:
    """
    Load ``logging.ini`` from *config_path* via :func:`logging.config.fileConfig`.

    Falls back to :func:`logging.basicConfig` and emits a warning when the file
    cannot be parsed.

    :author: Ron Webb
    :since: 1.4.0
    """
    try:
        logging.config.fileConfig(config_path, disable_existing_loggers=False)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logging.basicConfig(level=logging.INFO)
        logging.warning(
            "Failed to load logging config from %s: %s. Using basic configuration.",
            config_path,
            exc,
        )


def _load_packaged_config() -> None:
    """
    Load the ``logging.ini`` that is bundled inside the ``java_dependency_analyzer``
    package using :mod:`importlib.resources`.

    :author: Ron Webb
    :since: 1.4.0
    """
    pkg_ref = importlib.resources.files("java_dependency_analyzer").joinpath(
        "logging.ini"
    )
    with importlib.resources.as_file(pkg_ref) as src_path:
        _load_config(str(src_path))


def _ensure_config_dir(config_dir: Path) -> Path:
    """
    Create *config_dir* if it does not exist and copy the packaged
    ``logging.ini`` into it when the file is absent.

    Returns the path to ``logging.ini`` inside *config_dir*.

    :author: Ron Webb
    :since: 1.4.0
    """
    config_dir.mkdir(parents=True, exist_ok=True)
    target = config_dir / "logging.ini"
    if not target.exists():
        pkg_ref = importlib.resources.files("java_dependency_analyzer").joinpath(
            "logging.ini"
        )
        with importlib.resources.as_file(pkg_ref) as src_path:
            shutil.copy2(str(src_path), str(target))
    return target


def _add_rich_handler_once() -> None:
    """
    Attach a :class:`rich.logging.RichHandler` to the root logger exactly once.

    Subsequent calls are no-ops, guarded by an ``isinstance`` check.

    :author: Ron Webb
    :since: 1.4.0
    """
    root = logging.getLogger()
    if not any(isinstance(h, RichHandler) for h in root.handlers):
        rich_handler = RichHandler(rich_tracebacks=True, show_path=False)
        rich_handler.setLevel(logging.DEBUG)
        root.addHandler(rich_handler)


def setup_logger(name: str) -> logging.Logger:
    """
    Set up and return a logger with consistent configuration.

    Resolution order for ``logging.ini``:

    1. ``JDA_CONFIG_DIR`` environment variable — when set, the directory is
       created if necessary, the packaged ``logging.ini`` is seeded into it on
       first run, and the file is loaded from there.
    2. Bundled ``logging.ini`` inside the ``java_dependency_analyzer`` package —
       used directly via :mod:`importlib.resources` when ``JDA_CONFIG_DIR`` is
       not set.

    A :class:`rich.logging.RichHandler` is attached to the root logger once,
    replacing the plain ``StreamHandler`` that ``logging.ini`` previously
    provided for console output.

    :author: Ron Webb
    :since: 1.0.0
    """
    jda_config_dir = os.environ.get("JDA_CONFIG_DIR")

    if jda_config_dir:
        config_path = str(_ensure_config_dir(Path(jda_config_dir)))
        _load_config(config_path)
    else:
        _load_packaged_config()

    _add_rich_handler_once()

    return logging.getLogger(name)
