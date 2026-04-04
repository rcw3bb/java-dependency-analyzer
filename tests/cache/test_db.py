"""
test_db module.

Tests for the cache db module.

:author: Ron Webb
:since: 1.0.0
"""

import sqlite3
from pathlib import Path

import pytest

from java_dependency_analyzer.cache.db import (
    delete_database,
    get_connection,
    get_db_path,
)

__author__ = "Ron Webb"
__since__ = "1.0.0"


class TestGetDbPath:
    """Tests for get_db_path()."""

    def test_returns_path_inside_jda_dir(self):
        """get_db_path() should return a path inside ~/.jda."""
        path = get_db_path()
        assert path.parent.name == ".jda"

    def test_returns_cache_db_filename(self):
        """get_db_path() should return a file named cache.db."""
        assert get_db_path().name == "cache.db"

    def test_returns_absolute_path(self):
        """get_db_path() should return an absolute Path."""
        assert get_db_path().is_absolute()


class TestGetConnection:
    """Tests for get_connection()."""

    def test_creates_connection(self, monkeypatch, tmp_path):
        """get_connection() should return a sqlite3.Connection."""
        monkeypatch.setattr(
            "java_dependency_analyzer.cache.db.get_db_path",
            lambda: tmp_path / "cache.db",
        )
        conn = get_connection()
        assert isinstance(conn, sqlite3.Connection)
        conn.close()

    def test_creates_database_file(self, monkeypatch, tmp_path):
        """get_connection() should create the database file on disk."""
        db_path = tmp_path / "cache.db"
        monkeypatch.setattr(
            "java_dependency_analyzer.cache.db.get_db_path",
            lambda: db_path,
        )
        conn = get_connection()
        conn.close()
        assert db_path.exists()

    def test_creates_table(self, monkeypatch, tmp_path):
        """get_connection() should create the vulnerability_cache table."""
        monkeypatch.setattr(
            "java_dependency_analyzer.cache.db.get_db_path",
            lambda: tmp_path / "cache.db",
        )
        conn = get_connection()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='vulnerability_cache'"
        )
        assert cursor.fetchone() is not None
        conn.close()

    def test_creates_index(self, monkeypatch, tmp_path):
        """get_connection() should create the idx_cache_lookup index."""
        monkeypatch.setattr(
            "java_dependency_analyzer.cache.db.get_db_path",
            lambda: tmp_path / "cache.db",
        )
        conn = get_connection()
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_cache_lookup'"
        )
        assert cursor.fetchone() is not None
        conn.close()

    def test_creates_parent_directory(self, monkeypatch, tmp_path):
        """get_connection() should create nested parent directories if needed."""
        deep_path = tmp_path / "nested" / "dirs" / "cache.db"
        monkeypatch.setattr(
            "java_dependency_analyzer.cache.db.get_db_path",
            lambda: deep_path,
        )
        conn = get_connection()
        conn.close()
        assert deep_path.exists()


class TestDeleteDatabase:
    """Tests for delete_database()."""

    def test_returns_true_when_file_exists(self, monkeypatch, tmp_path):
        """delete_database() should return True when the db file was deleted."""
        db_path = tmp_path / "cache.db"
        db_path.touch()
        monkeypatch.setattr(
            "java_dependency_analyzer.cache.db.get_db_path",
            lambda: db_path,
        )
        assert delete_database() is True

    def test_deletes_file(self, monkeypatch, tmp_path):
        """delete_database() should remove the db file."""
        db_path = tmp_path / "cache.db"
        db_path.touch()
        monkeypatch.setattr(
            "java_dependency_analyzer.cache.db.get_db_path",
            lambda: db_path,
        )
        delete_database()
        assert not db_path.exists()

    def test_returns_false_when_file_missing(self, monkeypatch, tmp_path):
        """delete_database() should return False when the db file does not exist."""
        monkeypatch.setattr(
            "java_dependency_analyzer.cache.db.get_db_path",
            lambda: tmp_path / "missing.db",
        )
        assert delete_database() is False
