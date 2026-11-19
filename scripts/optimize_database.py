"""Back up the telemetry database and add query-driven indexes."""
from __future__ import annotations

import argparse
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.telemetry import DB_PATH, apply_performance_indexes


def _read_only_connection(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{path.resolve().as_uri()}?mode=ro", uri=True)


def _table_counts(connection: sqlite3.Connection) -> dict[str, int]:
    tables = {
        row[0]
        for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    return {
        table: int(connection.execute(f'SELECT COUNT(*) FROM "{table}"').fetchone()[0])
        for table in sorted(
            tables
            & {
                "sessions",
                "tool_calls",
                "tool_definition_events",
                "mcp_servers",
                "mcp_server_connections",
                "session_reviews",
                "session_review_events",
            }
        )
    }


def _create_backup(database: Path, backup: Path) -> dict[str, int]:
    if backup.exists():
        raise FileExistsError(f"Refusing to overwrite existing backup: {backup}")
    backup.parent.mkdir(parents=True, exist_ok=True)
    with closing(_read_only_connection(database)) as source:
        before = _table_counts(source)
        destination = sqlite3.connect(backup)
        try:
            source.backup(destination)
        finally:
            destination.close()
    with closing(_read_only_connection(backup)) as copy:
        integrity = copy.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise sqlite3.DatabaseError(f"Backup integrity check failed: {integrity}")
        if _table_counts(copy) != before:
            raise sqlite3.DatabaseError("Backup row counts differ from the source database.")
    return before


def _verify_query_plans(database: Path) -> dict[str, list[str]]:
    queries = {
        "sessions_latest": (
            "SELECT session_id FROM sessions ORDER BY started_at DESC LIMIT 50",
            (),
        ),
        "sessions_by_agent": (
            "SELECT session_id FROM sessions WHERE agent_id = ? "
            "ORDER BY started_at DESC LIMIT 50",
            ("benchmark-agent",),
        ),
        "calls_by_session": (
            "SELECT sequence_num FROM tool_calls WHERE session_id = ? "
            "ORDER BY sequence_num",
            ("benchmark-session",),
        ),
        "recent_calls": (
            "SELECT id FROM tool_calls ORDER BY called_at DESC LIMIT 50",
            (),
        ),
        "recent_tool_changes": (
            "SELECT id FROM tool_definition_events ORDER BY recorded_at DESC LIMIT 50",
            (),
        ),
    }
    plans: dict[str, list[str]] = {}
    with closing(_read_only_connection(database)) as connection:
        for name, (query, params) in queries.items():
            plans[name] = [
                row[3]
                for row in connection.execute("EXPLAIN QUERY PLAN " + query, params)
            ]
    return plans


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Back up AgentSentry telemetry and apply read-query indexes."
    )
    parser.add_argument("--db", type=Path, default=DB_PATH, help="Existing telemetry DB")
    parser.add_argument(
        "--backup",
        type=Path,
        help="Backup path (default: timestamped sibling; existing files are never overwritten)",
    )
    args = parser.parse_args(argv)
    database = args.db.expanduser().resolve()
    if not database.is_file():
        parser.error(f"Database does not exist: {database}")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = (
        args.backup.expanduser().resolve()
        if args.backup
        else database.with_name(f"{database.name}.pre-indexes-{timestamp}.bak")
    )

    try:
        counts = _create_backup(database, backup)
        apply_performance_indexes(database)
        plans = _verify_query_plans(database)
        with closing(_read_only_connection(database)) as connection:
            if _table_counts(connection) != counts:
                raise sqlite3.DatabaseError("Row counts changed while creating indexes.")
        expected_indexes = {
            "sessions_latest": "idx_sessions_started_at",
            "sessions_by_agent": "idx_sessions_agent_started_at",
            "calls_by_session": "idx_tool_calls_session_sequence",
            "recent_calls": "idx_tool_calls_called_at",
            "recent_tool_changes": "idx_tool_definition_events_recorded_at",
        }
        for query, index in expected_indexes.items():
            if not any(index in step for step in plans[query]):
                raise sqlite3.DatabaseError(
                    f"SQLite did not select expected index {index} for {query}."
                )
    except (OSError, sqlite3.Error) as exc:
        print(f"Database optimization failed; backup retained at {backup}: {exc}", file=sys.stderr)
        return 1

    print(f"Verified backup: {backup}")
    print(f"Existing row counts preserved: {counts}")
    for query, steps in plans.items():
        print(f"{query}: {'; '.join(steps)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
