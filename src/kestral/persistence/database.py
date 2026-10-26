"""Database connection manager for kestral persistence."""

from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

from kestral.exceptions import PersistenceError
from kestral.persistence.migrations import CURRENT_VERSION, MIGRATIONS

if TYPE_CHECKING:
    from collections.abc import Generator


class DatabaseManager:
    """Manages a SQLite database used for scan history, feedback, and audit logs.

    The manager enables WAL mode for concurrent read access and automatically
    applies any pending schema migrations on initialisation. The connection is
    opened with ``check_same_thread=False`` and every access is serialised by
    an internal ``threading.Lock`` — this lets sync scans run safely from a
    worker thread (e.g., under ``anyio.to_thread.run_sync`` in async hosts
    like the MCP server) without ``sqlite3.ProgrammingError`` or lost audit
    rows.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._ensure_parent_dir()
        self._lock = threading.Lock()
        self._conn = self._create_connection()
        self._apply_migrations()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _ensure_parent_dir(self) -> None:
        """Create the parent directory for the database file if it does not exist."""
        parent = Path(self._db_path).parent
        parent.mkdir(parents=True, exist_ok=True)

    def _create_connection(self) -> sqlite3.Connection:
        """Open a SQLite connection with WAL journal mode.

        ``check_same_thread=False`` lets the connection be used from any thread;
        actual serialisation is handled by ``self._lock`` in :meth:`connection`.
        """
        try:
            conn = sqlite3.connect(self._db_path, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.Error as exc:
            raise PersistenceError(f"Failed to open database at {self._db_path}: {exc}") from exc

    def _current_schema_version(self) -> int:
        """Return the highest applied schema version, or 0 if none."""
        cursor = self._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version';"
        )
        if cursor.fetchone() is None:
            return 0
        row = self._conn.execute("SELECT MAX(version) AS v FROM schema_version;").fetchone()
        return row["v"] if row["v"] is not None else 0

    def _apply_migrations(self) -> None:
        """Apply all unapplied migrations up to *CURRENT_VERSION*."""
        try:
            current = self._current_schema_version()
            for version in range(current + 1, CURRENT_VERSION + 1):
                sql = MIGRATIONS.get(version)
                if sql is None:
                    raise PersistenceError(f"Missing migration for schema version {version}")
                self._conn.executescript(sql)
                self._conn.execute(
                    "INSERT INTO schema_version (version) VALUES (?);",
                    (version,),
                )
                self._conn.commit()
        except sqlite3.Error as exc:
            raise PersistenceError(f"Migration failed: {exc}") from exc

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @contextmanager
    def connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield the managed *sqlite3.Connection* with *Row* row-factory.

        The connection is shared across calls; callers should **not** close it.
        Access is serialised by an internal lock so callers from multiple
        threads (e.g., async hosts offloading sync scans via
        ``anyio.to_thread.run_sync``) do not corrupt cursor state or lose
        audit-log rows.
        """
        if self._conn is None:
            raise PersistenceError("DatabaseManager has been closed")
        with self._lock:
            try:
                yield self._conn
            except sqlite3.Error as exc:
                self._conn.rollback()
                raise PersistenceError(f"Database operation failed: {exc}") from exc

    def prune_scan_history(self, retention_days: int) -> int:
        """Delete scan-history rows older than *retention_days* days.

        Returns the number of rows deleted.
        """
        try:
            cursor = self._conn.execute(
                "DELETE FROM scan_history WHERE timestamp < datetime('now', ? || ' days');",
                (f"-{retention_days}",),
            )
            self._conn.commit()
            return cursor.rowcount
        except sqlite3.Error as exc:
            raise PersistenceError(f"Failed to prune scan history: {exc}") from exc

    def close(self) -> None:
        """Close the underlying database connection."""
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error as exc:
                raise PersistenceError(f"Error closing database: {exc}") from exc
            finally:
                self._conn = None
