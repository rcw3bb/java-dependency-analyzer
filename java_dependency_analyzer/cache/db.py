"""
db module.

Manages the SQLite database lifecycle: path resolution, connection,
schema creation, and deletion.

:author: Ron Webb
:since: 1.0.0
"""

import sqlite3
from pathlib import Path

from ..util.logger import setup_logger

__author__ = "Ron Webb"
__since__ = "1.0.0"

_logger = setup_logger(__name__)

_DB_DIR = Path.home() / ".jda"
_DB_FILE = "cache.db"

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS vulnerability_cache (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    source      TEXT    NOT NULL,
    group_id    TEXT    NOT NULL,
    artifact_id TEXT    NOT NULL,
    version     TEXT    NOT NULL,
    payload     TEXT    NOT NULL,
    cached_at   TEXT    NOT NULL,
    UNIQUE(source, group_id, artifact_id, version)
)
"""

_CREATE_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_cache_lookup
ON vulnerability_cache(group_id, artifact_id, version, source)
"""


def get_db_path() -> Path:
    """
    Return the absolute path to the SQLite cache database file.

    The default location is ``~/.jda/cache.db``.

    :author: Ron Webb
    :since: 1.0.0
    """
    return _DB_DIR / _DB_FILE


def get_connection() -> sqlite3.Connection:
    """
    Open (and initialise) the SQLite database, creating the parent directory
    and schema if they do not yet exist.

    Returns a ``sqlite3.Connection`` with ``check_same_thread=False`` so the
    connection can be shared within a single CLI invocation.

    :author: Ron Webb
    :since: 1.0.0
    """
    db_path = get_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    _logger.debug("Opening cache database at %s", db_path)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    _initialise_schema(conn)
    return conn


def _initialise_schema(conn: sqlite3.Connection) -> None:
    """
    Create the cache table and lookup index when they do not already exist.

    :author: Ron Webb
    :since: 1.0.0
    """
    with conn:
        conn.execute(_CREATE_TABLE_SQL)
        conn.execute(_CREATE_INDEX_SQL)


def delete_database() -> bool:
    """
    Delete the SQLite cache database file.

    Returns ``True`` if the file was deleted, ``False`` if it did not exist.

    :author: Ron Webb
    :since: 1.0.0
    """
    db_path = get_db_path()
    if db_path.exists():
        db_path.unlink()
        _logger.info("Deleted cache database at %s", db_path)
        return True
    _logger.debug("Cache database not found at %s, nothing to delete", db_path)
    return False
