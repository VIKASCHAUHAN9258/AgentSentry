from __future__ import annotations

import sqlite3

from core.telemetry import apply_performance_indexes, init_db


def test_query_indexes_preserve_telemetry_and_improve_expected_plans(tmp_path):
    database = tmp_path / "optimization.db"
    init_db(database)
    with sqlite3.connect(database) as connection:
        connection.execute(
            "INSERT INTO sessions VALUES ('session-1', 'agent-1', 1.0, 2.0)"
        )
        connection.execute(
            """INSERT INTO tool_calls
               (session_id, sequence_num, tool_name, arguments_json, called_at, is_error)
               VALUES ('session-1', 1, 'read_file', '{}', 1.5, 0)"""
        )
        connection.execute(
            """INSERT INTO tool_definition_events
               (session_id, sequence_num, event_type, tool_name,
                notification_method, recorded_at)
               VALUES ('session-1', 1.5, 'tool_definition_changed',
                       'read_file', 'notifications/tools/list_changed', 1.7)"""
        )
        connection.execute(
            "DROP INDEX idx_tool_calls_session_sequence"
        )
        connection.execute(
            "CREATE INDEX idx_tool_calls_session ON tool_calls(session_id)"
        )

    apply_performance_indexes(database)
    apply_performance_indexes(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0] == 1
        assert (
            connection.execute("SELECT COUNT(*) FROM tool_definition_events").fetchone()[0]
            == 1
        )
        index_names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            )
        }
        assert "idx_tool_calls_session" not in index_names

        plans = {
            "latest_sessions": connection.execute(
                "EXPLAIN QUERY PLAN SELECT session_id FROM sessions "
                "ORDER BY started_at DESC LIMIT 50"
            ).fetchall(),
            "agent_sessions": connection.execute(
                "EXPLAIN QUERY PLAN SELECT session_id FROM sessions "
                "WHERE agent_id=? ORDER BY started_at DESC LIMIT 50",
                ("agent-1",),
            ).fetchall(),
            "ordered_calls": connection.execute(
                "EXPLAIN QUERY PLAN SELECT sequence_num FROM tool_calls "
                "WHERE session_id=? ORDER BY sequence_num",
                ("session-1",),
            ).fetchall(),
            "recent_calls": connection.execute(
                "EXPLAIN QUERY PLAN SELECT id FROM tool_calls "
                "ORDER BY called_at DESC LIMIT 50"
            ).fetchall(),
            "recent_events": connection.execute(
                "EXPLAIN QUERY PLAN SELECT id FROM tool_definition_events "
                "ORDER BY recorded_at DESC LIMIT 50"
            ).fetchall(),
        }

    expected = {
        "latest_sessions": "idx_sessions_started_at",
        "agent_sessions": "idx_sessions_agent_started_at",
        "ordered_calls": "idx_tool_calls_session_sequence",
        "recent_calls": "idx_tool_calls_called_at",
        "recent_events": "idx_tool_definition_events_recorded_at",
    }
    for query, index in expected.items():
        assert any(index in row[3] for row in plans[query]), plans[query]
