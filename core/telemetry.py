"""
AgentSentry — Phase 2 telemetry storage.

Every tool call the proxy intercepts gets written here BEFORE the result is
returned to the agent. This ordering matters: if logging happened after
forwarding, a crash between "call executed" and "call logged" would create a
blind spot — exactly the kind of gap a runtime security monitor cannot have.

The schema is extended additively: tool calls and proxy-verified tool-definition
changes retain their existing records, while the MCP inventory tables persist
observed downstream servers and their proxy-session connections.
"""

from __future__ import annotations

import json
import hashlib
import re
import sqlite3
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

DB_PATH = Path(__file__).parent.parent / "agentsentry.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id   TEXT PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    started_at   REAL NOT NULL,
    ended_at     REAL
);

CREATE TABLE IF NOT EXISTS tool_calls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT NOT NULL,
    sequence_num    INTEGER NOT NULL,
    tool_name       TEXT NOT NULL,
    arguments_json  TEXT NOT NULL,
    called_at       REAL NOT NULL,
    duration_ms     REAL,
    is_error        INTEGER NOT NULL DEFAULT 0,
    result_summary  TEXT,
    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
);

CREATE INDEX IF NOT EXISTS idx_tool_calls_session_sequence
    ON tool_calls (session_id, sequence_num);

CREATE TABLE IF NOT EXISTS tool_definition_events (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id              TEXT NOT NULL,
    sequence_num            REAL NOT NULL,
    event_type              TEXT NOT NULL,
    tool_name               TEXT NOT NULL,
    notification_method     TEXT NOT NULL,
    before_definition_json  TEXT,
    after_definition_json   TEXT,
    before_schema_json      TEXT,
    after_schema_json       TEXT,
    recorded_at             REAL NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
);

CREATE INDEX IF NOT EXISTS idx_tool_definition_events_session
    ON tool_definition_events (session_id, sequence_num);

CREATE TABLE IF NOT EXISTS mcp_servers (
    server_id        TEXT PRIMARY KEY,
    server_name      TEXT NOT NULL,
    transport        TEXT NOT NULL,
    first_seen       REAL NOT NULL,
    last_seen        REAL NOT NULL,
    connection_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mcp_server_connections (
    connection_id  TEXT PRIMARY KEY,
    server_id      TEXT NOT NULL,
    session_id     TEXT NOT NULL,
    connected_at   REAL NOT NULL,
    disconnected_at REAL,
    FOREIGN KEY (server_id) REFERENCES mcp_servers (server_id),
    FOREIGN KEY (session_id) REFERENCES sessions (session_id)
);

CREATE INDEX IF NOT EXISTS idx_mcp_server_connections_server
    ON mcp_server_connections (server_id, connected_at);
CREATE INDEX IF NOT EXISTS idx_mcp_server_connections_session
    ON mcp_server_connections (session_id);

CREATE TABLE IF NOT EXISTS session_reviews (
    session_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reviewer TEXT NOT NULL,
    reviewed_at REAL NOT NULL,
    review_note TEXT NOT NULL DEFAULT '',
    evidence_sha256 TEXT NOT NULL,
    FOREIGN KEY (session_id) REFERENCES sessions(session_id)
);

CREATE TABLE IF NOT EXISTS session_review_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    reviewer TEXT NOT NULL,
    reviewed_at REAL NOT NULL,
    review_note TEXT NOT NULL DEFAULT '',
    evidence_sha256 TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_review_events_session
    ON session_review_events (session_id, id);
"""

PERFORMANCE_INDEXES = (
    "CREATE INDEX IF NOT EXISTS idx_sessions_started_at "
    "ON sessions (started_at DESC, session_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_agent_started_at "
    "ON sessions (agent_id, started_at DESC, session_id)",
    "CREATE INDEX IF NOT EXISTS idx_tool_calls_called_at "
    "ON tool_calls (called_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_tool_definition_events_recorded_at "
    "ON tool_definition_events (recorded_at DESC)",
)

_SERVER_SECRET_TEXT_RE = re.compile(
    r"(?i)\b((?:password|passwd|secret|token|credential|private[_-]?key|api[_-]?key|access[_-]?key|authorization)"
    r"\s*[:=]\s*)"
    r"""['"]?[^\s,;'" ]+"""
)


def _safe_server_name(server_name: str) -> str:
    safe_name = _SERVER_SECRET_TEXT_RE.sub(r"\1[REDACTED]", server_name)
    return "".join(char for char in safe_name if char.isprintable()).strip()[:200]


def _redact_sensitive_values(value: Any, sensitive_values: tuple[str, ...]) -> Any:
    if isinstance(value, str):
        redacted = value
        for secret in sensitive_values:
            if secret:
                redacted = redacted.replace(secret, "[REDACTED]")
        return redacted
    if isinstance(value, dict):
        return {
            key: _redact_sensitive_values(item, sensitive_values)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_sensitive_values(item, sensitive_values) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_sensitive_values(item, sensitive_values) for item in value)
    return value


@contextmanager
def _connect(db_path: Path = DB_PATH) -> Iterator[sqlite3.Connection]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db(db_path: Path = DB_PATH) -> None:
    with _connect(db_path) as conn:
        conn.executescript(SCHEMA)


def apply_performance_indexes(db_path: Path = DB_PATH) -> None:
    """Apply additive query indexes after the operator has made a backup."""
    conn = sqlite3.connect(db_path, timeout=5.0)
    try:
        conn.execute("BEGIN IMMEDIATE")
        tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        required = {"sessions", "tool_calls", "tool_definition_events"}
        if not required.issubset(tables):
            raise sqlite3.OperationalError("Telemetry schema is incomplete.")
        for statement in PERFORMANCE_INDEXES:
            conn.execute(statement)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_tool_calls_session_sequence "
            "ON tool_calls (session_id, sequence_num)"
        )
        conn.execute("DROP INDEX IF EXISTS idx_tool_calls_session")
        conn.commit()
    finally:
        if conn.in_transaction:
            conn.rollback()
        conn.close()


class TelemetryStore:
    """Thin wrapper the proxy uses to record a session's tool calls."""

    def __init__(self, agent_id: str, db_path: Path = DB_PATH):
        self.agent_id = agent_id
        self.db_path = db_path
        self.session_id = str(uuid.uuid4())
        self._sequence_num = 0
        init_db(db_path)
        with _connect(db_path) as conn:
            conn.execute(
                "INSERT INTO sessions (session_id, agent_id, started_at) VALUES (?, ?, ?)",
                (self.session_id, self.agent_id, time.time()),
            )

    def log_call(
        self,
        tool_name: str,
        arguments: dict[str, Any],
        duration_ms: float,
        is_error: bool,
        result_summary: str,
        sensitive_values: tuple[str, ...] = (),
        sequence_num: int | None = None,
    ) -> None:
        """Persist a single tool call. Called for EVERY call, success or failure."""
        if sequence_num is None:
            sequence_num = self.reserve_call_sequence()
        elif sequence_num > self._sequence_num:
            raise ValueError("Tool-call sequence number must be reserved before logging")
        safe_arguments = _redact_sensitive_values(arguments, sensitive_values)
        safe_result = _redact_sensitive_values(result_summary or "", sensitive_values)
        # Truncate result_summary defensively — a malicious/huge tool result
        # should never be able to blow up the telemetry DB.
        safe_summary = safe_result[:2000]
        arguments_json = json.dumps(safe_arguments, default=str)
        if len(arguments_json) > 4000:
            arguments_json = json.dumps({"_truncated": True})
        with _connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO tool_calls
                   (session_id, sequence_num, tool_name, arguments_json,
                    called_at, duration_ms, is_error, result_summary)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    self.session_id,
                    sequence_num,
                    tool_name,
                    arguments_json,
                    time.time(),
                    duration_ms,
                    1 if is_error else 0,
                    safe_summary,
                ),
            )

    def log_tool_definition_change(
        self,
        tool_name: str,
        before_definition: dict[str, Any] | None,
        after_definition: dict[str, Any] | None,
        sequence_num: float,
    ) -> None:
        """Record a downstream-notification-backed tool-definition change."""
        before_schema = (
            before_definition.get("inputSchema") if before_definition is not None else None
        )
        after_schema = after_definition.get("inputSchema") if after_definition is not None else None

        def encode(value: Any) -> str | None:
            if value is None:
                return None
            return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

        with _connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO tool_definition_events
                   (session_id, sequence_num, event_type, tool_name, notification_method,
                    before_definition_json, after_definition_json,
                    before_schema_json, after_schema_json, recorded_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    self.session_id,
                    sequence_num,
                    "tool_definition_changed",
                    tool_name,
                    "notifications/tools/list_changed",
                    encode(before_definition),
                    encode(after_definition),
                    encode(before_schema),
                    encode(after_schema),
                    time.time(),
                ),
            )

    def end_session(self) -> None:
        with _connect(self.db_path) as conn:
            conn.execute(
                "UPDATE sessions SET ended_at = ? WHERE session_id = ?",
                (time.time(), self.session_id),
            )

    def register_mcp_server(self, server_name: str, transport: str) -> str:
        """Persist a proxy-observed downstream server connection."""
        safe_name = _safe_server_name(server_name)
        if not safe_name:
            raise ValueError("MCP server identity must have a non-empty name")
        if not transport or not transport.isascii() or not transport.isalnum():
            raise ValueError("MCP server transport must be a non-empty alphanumeric value")

        identity = f"{transport.lower()}:{safe_name.casefold()}"
        server_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        now = time.time()
        with _connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO mcp_servers
                   (server_id, server_name, transport, first_seen, last_seen, connection_count)
                   VALUES (?, ?, ?, ?, ?, 0)
                   ON CONFLICT(server_id) DO NOTHING""",
                (server_id, safe_name, transport.lower(), now, now),
            )
            inserted = conn.execute(
                """INSERT OR IGNORE INTO mcp_server_connections
                   (connection_id, server_id, session_id, connected_at)
                   VALUES (?, ?, ?, ?)""",
                (self.session_id, server_id, self.session_id, now),
            ).rowcount
            if inserted:
                conn.execute(
                    """UPDATE mcp_servers
                       SET last_seen = ?, connection_count = connection_count + 1
                       WHERE server_id = ?""",
                    (now, server_id),
                )
        return server_id

    def disconnect_mcp_server(self) -> None:
        """Record the end of this proxy's observed downstream connection."""
        now = time.time()
        with _connect(self.db_path) as conn:
            rows = conn.execute(
                """SELECT server_id FROM mcp_server_connections
                   WHERE connection_id = ? AND disconnected_at IS NULL""",
                (self.session_id,),
            ).fetchall()
            conn.execute(
                """UPDATE mcp_server_connections SET disconnected_at = ?
                   WHERE connection_id = ? AND disconnected_at IS NULL""",
                (now, self.session_id),
            )
            for row in rows:
                conn.execute(
                    "UPDATE mcp_servers SET last_seen = ? WHERE server_id = ?",
                    (now, row["server_id"]),
                )

    def call_count(self) -> int:
        return self._sequence_num

    def reserve_call_sequence(self) -> int:
        """Allocate a stable sequence number when a proxied call begins."""
        self._sequence_num += 1
        return self._sequence_num


def get_session_calls(session_id: str, db_path: Path = DB_PATH) -> list[sqlite3.Row]:
    """Read back every logged call for a session, in order. Used by tests and (later) the dashboard."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM tool_calls WHERE session_id = ? ORDER BY sequence_num ASC",
            (session_id,),
        ).fetchall()
        return rows


def get_session_tool_definition_events(
    session_id: str, db_path: Path = DB_PATH
) -> list[sqlite3.Row]:
    """Read trusted tool-definition changes observed by the proxy."""
    with _connect(db_path) as conn:
        return conn.execute(
            """SELECT * FROM tool_definition_events
               WHERE session_id = ? ORDER BY sequence_num ASC, id ASC""",
            (session_id,),
        ).fetchall()


def get_session_timeline(session_id: str, db_path: Path = DB_PATH) -> list[dict[str, Any]]:
    """Return tool calls and observed definition changes in session order."""
    calls = [dict(row) for row in get_session_calls(session_id, db_path)]
    with _connect(db_path) as conn:
        events = conn.execute(
            """SELECT * FROM tool_definition_events
               WHERE session_id = ? ORDER BY sequence_num ASC, id ASC""",
            (session_id,),
        ).fetchall()

    timeline = calls + [
        {
            "id": event["id"],
            "session_id": event["session_id"],
            "sequence_num": event["sequence_num"],
            "event_type": event["event_type"],
            "tool_name": event["tool_name"],
            "notification_method": event["notification_method"],
            "before_definition_json": event["before_definition_json"],
            "after_definition_json": event["after_definition_json"],
            "before_schema_json": event["before_schema_json"],
            "after_schema_json": event["after_schema_json"],
            "called_at": event["recorded_at"],
            "arguments_json": "{}",
            "duration_ms": None,
            "is_error": 0,
            "result_summary": None,
        }
        for event in events
    ]
    timeline.sort(key=lambda row: row["sequence_num"])
    return timeline
