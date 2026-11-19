"""Human review and tamper-evident snapshot gating for baseline sessions."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any

from core.telemetry import DB_PATH, init_db

_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")

REVIEW_SCHEMA = """
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
    ON session_review_events(session_id, id);
"""


def ensure_review_schema(db_path: Path = DB_PATH) -> None:
    init_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.executescript(REVIEW_SCHEMA)


def session_evidence(conn: sqlite3.Connection, session_id: str) -> tuple[sqlite3.Row, list[sqlite3.Row], list[sqlite3.Row]]:
    conn.row_factory = sqlite3.Row
    session = conn.execute(
        "SELECT session_id, agent_id, started_at, ended_at FROM sessions WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    if session is None:
        raise ValueError("Session not found.")
    calls = conn.execute(
        """SELECT sequence_num, tool_name, arguments_json, called_at, duration_ms,
                  is_error, result_summary FROM tool_calls
           WHERE session_id = ? ORDER BY sequence_num, id""", (session_id,),
    ).fetchall()
    events = conn.execute(
        """SELECT sequence_num, event_type, tool_name, notification_method,
                  before_definition_json, after_definition_json, before_schema_json,
                  after_schema_json, recorded_at FROM tool_definition_events
           WHERE session_id = ? ORDER BY sequence_num, id""", (session_id,),
    ).fetchall()
    return session, calls, events


def evidence_digest(session: sqlite3.Row, calls: list[sqlite3.Row], events: list[sqlite3.Row]) -> str:
    payload = {
        "session": dict(session),
        "calls": [dict(row) for row in calls],
        "tool_definition_events": [dict(row) for row in events],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(encoded).hexdigest()


def review_session(
    db_path: Path, session_id: str, decision: str, reviewer: str,
    note: str = "", confirm_reviewed: bool = False,
) -> dict[str, Any]:
    if not isinstance(session_id, str) or not _SAFE_ID.fullmatch(session_id):
        raise ValueError("Invalid session_id.")
    if not isinstance(decision, str) or decision not in {"approved", "rejected"}:
        raise ValueError("decision must be 'approved' or 'rejected'.")
    if not isinstance(reviewer, str):
        raise ValueError("A reviewer identifier (1-120 characters) is required.")
    if not isinstance(note, str):
        raise ValueError("Review note must be text.")
    reviewer = reviewer.strip()
    if not reviewer or len(reviewer) > 120:
        raise ValueError("A reviewer identifier (1-120 characters) is required.")
    if not confirm_reviewed:
        raise ValueError("Explicit confirmation that the session evidence was reviewed is required.")
    if len(note) > 2000:
        raise ValueError("Review note must be 2000 characters or fewer.")

    ensure_review_schema(db_path)
    with sqlite3.connect(str(db_path), timeout=5) as conn:
        conn.row_factory = sqlite3.Row
        session, calls, events = session_evidence(conn, session_id)
        if session["ended_at"] is None:
            raise ValueError("Active sessions cannot be reviewed for baseline training.")
        if not calls:
            raise ValueError("Sessions without tool-call telemetry cannot be approved.")
        digest = evidence_digest(session, calls, events)
        now = time.time()
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(
            """INSERT INTO session_reviews
               (session_id, agent_id, decision, reviewer, reviewed_at, review_note, evidence_sha256)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(session_id) DO UPDATE SET agent_id=excluded.agent_id,
                 decision=excluded.decision, reviewer=excluded.reviewer,
                 reviewed_at=excluded.reviewed_at, review_note=excluded.review_note,
                 evidence_sha256=excluded.evidence_sha256""",
            (session_id, session["agent_id"], decision, reviewer, now, note.strip(), digest),
        )
        conn.execute(
            """INSERT INTO session_review_events
               (session_id, agent_id, decision, reviewer, reviewed_at, review_note, evidence_sha256)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (session_id, session["agent_id"], decision, reviewer, now, note.strip(), digest),
        )
        return {
            "session_id": session_id, "agent_id": session["agent_id"],
            "decision": decision, "reviewer": reviewer, "reviewed_at": now,
            "evidence_sha256": digest,
        }


def get_review_status(conn: sqlite3.Connection, session_id: str) -> dict[str, Any]:
    row = conn.execute(
        """SELECT decision, reviewer, reviewed_at, review_note, evidence_sha256
           FROM session_reviews WHERE session_id = ?""", (session_id,),
    ).fetchone()
    if row is None:
        return {"decision": "unreviewed", "reviewer": None, "reviewed_at": None,
                "review_note": "", "evidence_current": False}
    session, calls, events = session_evidence(conn, session_id)
    current = evidence_digest(session, calls, events)
    return {"decision": row["decision"], "reviewer": row["reviewer"],
            "reviewed_at": row["reviewed_at"], "review_note": row["review_note"],
            "evidence_current": current == row["evidence_sha256"]}
