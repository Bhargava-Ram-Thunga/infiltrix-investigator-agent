"""SQLite access layer for the Investigator Agent.

Responsibilities
----------------
* Own the `events` table schema and its indexes (created idempotently on
  construction — safe to instantiate against an existing DB).
* Provide strictly time-bounded, indexed queries for related telemetry.
* Be safe to share across threads (per-thread connections via
  `threading.local`).

Timestamp storage strategy
--------------------------
Timestamps are stored as **ISO-8601 UTC strings** (e.g.
``2026-08-14T12:00:00+00:00``). Because every stored value is normalized to
UTC with a fixed format by `to_utc_iso`, lexicographic string comparison is
equivalent to chronological comparison — which is what makes the
``timestamp >= :window_start AND timestamp <= :window_end`` predicates
correct AND index-friendly. Consequences for future developers:

* NEVER insert a timestamp string directly; always go through
  `insert_event` (or `to_utc_iso` if you add a new write path). A row stored
  in local time or a different format would silently sort incorrectly.
* Both window bounds are INCLUSIVE by spec — events exactly at
  `window_start` or `window_end` are returned. Tests pin this behavior.

Indexing
--------
`idx_events_source_time (source_ip, timestamp)` and
`idx_events_session_time (session_id, timestamp)` cover the two branches of
the OR in `RELATED_EVENTS_SQL`. If you add a new lookup dimension (e.g.
user_id), add a matching composite index or the query will degrade to a
full table scan as telemetry grows.

Scaling beyond SQLite
---------------------
This class is deliberately thin so it can be swapped for
Postgres/ClickHouse later: keep the public surface (`insert_event`,
`query_related_events`, `close`) identical, return rows that are
mapping-accessible by column name, and the agent needs no changes.
"""

import sqlite3
import threading
from datetime import datetime, timezone
from typing import List, Optional

# Idempotent schema — executed on every EventDatabase construction.
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    method TEXT NOT NULL,
    status_code INTEGER NOT NULL,
    session_id TEXT,
    timestamp TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_source_time ON events(source_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_events_session_time ON events(session_id, timestamp);
"""

# Matches by source_ip OR session_id (when provided). The
# ":session_id IS NOT NULL" guard prevents NULL session rows from matching a
# NULL parameter — without it, a detection with no session_id would join
# against every sessionless row in the table.
RELATED_EVENTS_SQL = """
SELECT id, source_ip, endpoint, method, status_code, session_id, timestamp
FROM events
WHERE (source_ip = :source_ip OR (:session_id IS NOT NULL AND session_id = :session_id))
  AND timestamp >= :window_start
  AND timestamp <= :window_end
ORDER BY timestamp DESC;
"""


def to_utc_iso(dt: datetime) -> str:
    """Normalize a datetime to the canonical ISO-8601 UTC storage string.

    Naive datetimes are assumed UTC (mirrors `schemas._ensure_utc`); aware
    ones are converted. This is the ONLY sanctioned way to produce a
    timestamp string for the `events` table.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat()


class EventDatabase:
    """Thread-safe SQLite access layer for the `events` telemetry table.

    Thread-safety model: SQLite connections must not cross threads, so each
    thread lazily opens its own connection (stored in `threading.local`).
    Writes use `with conn:` for automatic commit/rollback. For
    multi-process deployments (e.g. gunicorn workers), each process gets its
    own EventDatabase; SQLite's file locking serializes writes — acceptable
    for moderate volume, migrate to a server DB beyond that (see module
    docstring).
    """

    def __init__(self, db_path: str = "events.db"):
        """Open (or create) the database at `db_path` and ensure the schema.

        Args:
            db_path: Filesystem path to the SQLite file. Use ":memory:" only
                for single-threaded tests — an in-memory DB is per-connection,
                so other threads would see an empty database.
        """
        self.db_path = db_path
        self._local = threading.local()
        self._init_schema()

    def _connection(self) -> sqlite3.Connection:
        """Return this thread's connection, creating it on first use."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(self.db_path)
            # Row factory gives name-based access (row["endpoint"]) — the
            # agent and any future backend swap rely on this, not on column
            # positions.
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return conn

    def _init_schema(self) -> None:
        conn = self._connection()
        with conn:
            conn.executescript(SCHEMA_SQL)

    def insert_event(
        self,
        source_ip: str,
        endpoint: str,
        method: str,
        status_code: int,
        timestamp: datetime,
        session_id: Optional[str] = None,
    ) -> int:
        """Insert one telemetry row and return its primary key.

        The timestamp is normalized via `to_utc_iso` — callers pass
        datetimes, never strings.
        """
        conn = self._connection()
        with conn:
            cursor = conn.execute(
                "INSERT INTO events (source_ip, endpoint, method, status_code, session_id, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (source_ip, endpoint, method, status_code, session_id, to_utc_iso(timestamp)),
            )
        return int(cursor.lastrowid)

    def query_related_events(
        self,
        source_ip: str,
        window_start: datetime,
        window_end: datetime,
        session_id: Optional[str] = None,
    ) -> List[sqlite3.Row]:
        """Fetch events related to a detection, strictly time-bounded.

        Matches rows whose `source_ip` equals the detection's, OR (when a
        session_id is supplied) whose `session_id` matches — the session
        branch catches attackers rotating IPs within one session. Both
        window bounds are inclusive; the upper bound prevents future
        telemetry from leaking into an investigation.

        Returns rows newest-first. Rows are NOT deduplicated here — a row
        matching both branches appears once in SQL semantics anyway, but the
        agent still dedups defensively by primary key (see agent.py).
        """
        conn = self._connection()
        cursor = conn.execute(
            RELATED_EVENTS_SQL,
            {
                "source_ip": source_ip,
                "session_id": session_id,
                "window_start": to_utc_iso(window_start),
                "window_end": to_utc_iso(window_end),
            },
        )
        return cursor.fetchall()

    def close(self) -> None:
        """Close the CURRENT thread's connection (other threads' connections
        are closed when their threads exit or by calling close() from them)."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            conn.close()
            self._local.conn = None
