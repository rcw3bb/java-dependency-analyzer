"""
test_logger module.

Tests for the logger utility module.

:author: Ron Webb
:since: 1.4.0
"""

import logging
from pathlib import Path

from rich.logging import RichHandler

from java_dependency_analyzer.util.logger import (
    _add_rich_handler_once,
    _ensure_config_dir,
    setup_logger,
)

__author__ = "Ron Webb"
__since__ = "1.4.0"


class TestEnsureConfigDir:
    """Tests for :func:`_ensure_config_dir`."""

    def test_creates_directory_when_absent(self, tmp_path):
        """_ensure_config_dir should create the directory if it does not exist."""
        target_dir = tmp_path / "jda_config" / "nested"
        _ensure_config_dir(target_dir)
        assert target_dir.is_dir()

    def test_copies_logging_ini_when_absent(self, tmp_path):
        """_ensure_config_dir should copy logging.ini into a new directory."""
        target_dir = tmp_path / "jda_config"
        ini_path = _ensure_config_dir(target_dir)
        assert ini_path.exists()
        assert ini_path.name == "logging.ini"
        assert "fileHandler" in ini_path.read_text(encoding="utf-8")

    def test_does_not_overwrite_existing_logging_ini(self, tmp_path):
        """_ensure_config_dir should not overwrite logging.ini that already exists."""
        target_dir = tmp_path / "jda_config"
        target_dir.mkdir(parents=True)
        existing_ini = target_dir / "logging.ini"
        sentinel = "[custom sentinel content]"
        existing_ini.write_text(sentinel, encoding="utf-8")

        _ensure_config_dir(target_dir)

        assert existing_ini.read_text(encoding="utf-8") == sentinel

    def test_returns_ini_path(self, tmp_path):
        """_ensure_config_dir should return the Path to logging.ini."""
        target_dir = tmp_path / "jda_config"
        result = _ensure_config_dir(target_dir)
        assert isinstance(result, Path)
        assert result == target_dir / "logging.ini"


class TestAddRichHandlerOnce:
    """Tests for :func:`_add_rich_handler_once`."""

    def test_adds_rich_handler_to_root(self):
        """_add_rich_handler_once should add a RichHandler to the root logger."""
        root = logging.getLogger()
        # Remove any existing RichHandlers to start clean
        root.handlers = [h for h in root.handlers if not isinstance(h, RichHandler)]
        _add_rich_handler_once()
        assert any(isinstance(h, RichHandler) for h in root.handlers)

    def test_idempotent_on_repeated_calls(self):
        """_add_rich_handler_once should not add duplicate RichHandlers."""
        root = logging.getLogger()
        root.handlers = [h for h in root.handlers if not isinstance(h, RichHandler)]
        _add_rich_handler_once()
        _add_rich_handler_once()
        rich_handlers = [h for h in root.handlers if isinstance(h, RichHandler)]
        assert len(rich_handlers) == 1


class TestSetupLogger:
    """Tests for :func:`setup_logger`."""

    def test_returns_logger_with_correct_name(self, monkeypatch):
        """setup_logger should return a logger with the supplied name."""
        monkeypatch.delenv("JDA_CONFIG_DIR", raising=False)
        logger = setup_logger("test.module")
        assert logger.name == "test.module"

    def test_jda_config_dir_not_set_uses_packaged_ini(self, monkeypatch):
        """When JDA_CONFIG_DIR is unset, setup_logger should load the bundled logging.ini."""
        monkeypatch.delenv("JDA_CONFIG_DIR", raising=False)
        # Should not raise; file handler configured from the packaged ini
        logger = setup_logger("test.packaged_ini")
        assert logger is not None

    def test_jda_config_dir_creates_dir_and_copies_ini(self, monkeypatch, tmp_path):
        """When JDA_CONFIG_DIR points to a non-existent path, the dir and ini are created."""
        config_dir = tmp_path / "jda_cfg"
        monkeypatch.setenv("JDA_CONFIG_DIR", str(config_dir))
        setup_logger("test.jda_config_dir")
        assert config_dir.is_dir()
        assert (config_dir / "logging.ini").exists()

    def test_jda_config_dir_uses_existing_ini(self, monkeypatch, tmp_path):
        """When JDA_CONFIG_DIR has an existing logging.ini it should not be replaced."""
        config_dir = tmp_path / "jda_existing"
        config_dir.mkdir(parents=True)
        ini_file = config_dir / "logging.ini"
        # Write a minimal valid INI so fileConfig doesn't raise
        ini_file.write_text(
            "[loggers]\nkeys=root\n\n"
            "[handlers]\nkeys=\n\n"
            "[formatters]\nkeys=\n\n"
            "[logger_root]\nlevel=WARNING\nhandlers=\n",
            encoding="utf-8",
        )
        original_content = ini_file.read_text(encoding="utf-8")
        monkeypatch.setenv("JDA_CONFIG_DIR", str(config_dir))
        setup_logger("test.existing_ini")
        assert ini_file.read_text(encoding="utf-8") == original_content

    def test_rich_handler_present_after_setup(self, monkeypatch):
        """setup_logger should ensure a RichHandler is attached to the root logger."""
        monkeypatch.delenv("JDA_CONFIG_DIR", raising=False)
        root = logging.getLogger()
        root.handlers = [h for h in root.handlers if not isinstance(h, RichHandler)]
        setup_logger("test.rich")
        assert any(isinstance(h, RichHandler) for h in root.handlers)

    def test_setup_logger_repeated_calls_single_rich_handler(
        self, monkeypatch
    ):
        """Calling setup_logger multiple times should not duplicate RichHandlers."""
        monkeypatch.delenv("JDA_CONFIG_DIR", raising=False)
        root = logging.getLogger()
        root.handlers = [h for h in root.handlers if not isinstance(h, RichHandler)]
        setup_logger("test.repeat1")
        setup_logger("test.repeat2")
        rich_count = sum(1 for h in root.handlers if isinstance(h, RichHandler))
        assert rich_count == 1
