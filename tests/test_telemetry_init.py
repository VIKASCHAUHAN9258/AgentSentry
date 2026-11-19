"""Database initialization is idempotent and creates schema without telemetry."""
import sqlite3

from core.telemetry import init_db


def test_init_db_is_idempotent_and_creates_expected_schema(tmp_path):
    database = tmp_path / "telemetry.db"

    init_db(database)
    init_db(database)

    with sqlite3.connect(database) as connection:
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        assert {
            "sessions",
            "tool_calls",
            "tool_definition_events",
            "mcp_servers",
            "mcp_server_connections",
        } <= tables
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0] == 0
        assert (
            connection.execute("SELECT COUNT(*) FROM tool_definition_events").fetchone()[0]
            == 0
        )
