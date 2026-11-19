from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from agent.demo_agent import _proxied_server_params
from api.app import create_app
from core.telemetry import TelemetryStore, init_db
from mcp import ClientSession, stdio_client


@pytest.mark.asyncio
async def test_proxy_inventory_records_real_identity_and_shutdown(
    tmp_path: Path,
) -> None:
    database = tmp_path / "proxy-inventory.db"
    params = _proxied_server_params("inventory-agent", str(database))

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            initialized = await session.initialize()
            assert initialized.server_info.name == "agentsentry-proxy"
            await session.list_tools()

            with sqlite3.connect(database) as connection:
                row = connection.execute(
                    """SELECT server_name, transport, connection_count
                       FROM mcp_servers"""
                ).fetchone()
                assert row == ("agentsentry-lab-file-tools", "stdio", 1)
                active = connection.execute(
                    "SELECT disconnected_at FROM mcp_server_connections"
                ).fetchone()
                assert active == (None,)
            live_inventory = create_app(
                {"TESTING": True, "DATABASE": str(database)}
            ).test_client().get("/api/mcp/servers").get_json()
            assert live_inventory["available"] is True
            assert live_inventory["servers"][0]["connection_status"] == "connected"
            assert live_inventory["servers"][0]["sessions"][0]["agent_id"] == "inventory-agent"

    with sqlite3.connect(database) as connection:
        server = connection.execute(
            """SELECT server_id, server_name, transport, first_seen, last_seen,
                      connection_count
               FROM mcp_servers"""
        ).fetchone()
        session = connection.execute(
            """SELECT c.session_id, s.agent_id, c.connected_at, c.disconnected_at
               FROM mcp_server_connections AS c
               JOIN sessions AS s ON s.session_id = c.session_id"""
        ).fetchone()

    assert server is not None
    assert server[2] == "stdio"
    assert server[3] <= server[4]
    assert server[5] == 1
    assert session is not None
    assert session[1] == "inventory-agent"
    assert session[2] <= session[3]


@pytest.mark.asyncio
async def test_repeated_proxy_connections_aggregate_and_associate_sessions(
    tmp_path: Path,
) -> None:
    database = tmp_path / "repeated-inventory.db"
    for agent_id in ("inventory-agent-a", "inventory-agent-b"):
        params = _proxied_server_params(agent_id, str(database))
        async with stdio_client(params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                await session.list_tools()

    with sqlite3.connect(database) as connection:
        server = connection.execute(
            """SELECT server_name, connection_count FROM mcp_servers"""
        ).fetchone()
        associations = connection.execute(
            """SELECT s.agent_id, c.disconnected_at
               FROM mcp_server_connections AS c
               JOIN sessions AS s ON s.session_id = c.session_id
               ORDER BY s.agent_id"""
        ).fetchall()

    assert server == ("agentsentry-lab-file-tools", 2)
    assert [row[0] for row in associations] == [
        "inventory-agent-a",
        "inventory-agent-b",
    ]
    assert all(row[1] is not None for row in associations)


def test_mcp_inventory_api_redacts_secrets_and_returns_session_association(
    tmp_path: Path,
) -> None:
    database = tmp_path / "inventory-api.db"
    store = TelemetryStore("inventory-api-agent", db_path=database)
    store.register_mcp_server("test-server api_key=FAKE-DO-NOT-EXPOSE", "stdio")
    store.disconnect_mcp_server()

    response = create_app(
        {"TESTING": True, "DATABASE": str(database)}
    ).test_client().get("/api/mcp/servers")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["available"] is True
    assert payload["status"] == "available"
    server = payload["servers"][0]
    assert server["server_name"] == "test-server api_key=[REDACTED]"
    assert server["transport"] == "stdio"
    assert server["connection_count"] == 1
    assert server["connection_status"] == "disconnected"
    assert server["agents"] == [{"agent_id": "inventory-api-agent", "connection_count": 1}]
    assert server["sessions"][0]["session_id"] == store.session_id
    assert server["sessions"][0]["agent_id"] == "inventory-api-agent"
    assert server["sessions"][0]["connection_status"] == "disconnected"
    assert "FAKE-DO-NOT-EXPOSE" not in response.get_data(as_text=True)
    assert not {"command", "args", "env"} & set(server)


def test_mcp_inventory_api_distinguishes_empty_from_unavailable(tmp_path: Path) -> None:
    initialized_database = tmp_path / "empty-inventory.db"
    init_db(initialized_database)
    empty_response = create_app(
        {"TESTING": True, "DATABASE": str(initialized_database)}
    ).test_client().get("/api/mcp/servers")
    assert empty_response.status_code == 200
    assert empty_response.get_json() == {
        "available": False,
        "status": "empty",
        "servers": [],
        "reason": "No MCP servers have been observed by the proxy.",
    }

    legacy_database = tmp_path / "legacy-inventory.db"
    missing_response = create_app(
        {"TESTING": True, "DATABASE": str(legacy_database)}
    ).test_client().get("/api/mcp/servers")
    assert missing_response.status_code == 200
    assert missing_response.get_json()["status"] == "unavailable"
    assert missing_response.get_json()["servers"] == []


def test_inventory_migration_preserves_existing_telemetry_and_is_idempotent(
    tmp_path: Path,
) -> None:
    database = tmp_path / "legacy-telemetry.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            """
            CREATE TABLE sessions (
                session_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                started_at REAL NOT NULL,
                ended_at REAL
            );
            CREATE TABLE tool_calls (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                sequence_num INTEGER NOT NULL,
                tool_name TEXT NOT NULL,
                arguments_json TEXT NOT NULL,
                called_at REAL NOT NULL,
                duration_ms REAL,
                is_error INTEGER NOT NULL DEFAULT 0,
                result_summary TEXT
            );
            CREATE TABLE tool_definition_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                sequence_num REAL NOT NULL,
                event_type TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                notification_method TEXT NOT NULL,
                before_definition_json TEXT,
                after_definition_json TEXT,
                before_schema_json TEXT,
                after_schema_json TEXT,
                recorded_at REAL NOT NULL
            );
            INSERT INTO sessions VALUES ('old-session', 'old-agent', 1.0, 2.0);
            INSERT INTO tool_calls
              (session_id, sequence_num, tool_name, arguments_json, called_at, is_error)
              VALUES ('old-session', 1, 'read_file', '{}', 1.5, 0);
            INSERT INTO tool_definition_events
              (session_id, sequence_num, event_type, tool_name, notification_method, recorded_at)
              VALUES ('old-session', 1.5, 'tool_definition_changed', 'read_file',
                      'notifications/tools/list_changed', 1.7);
            """
        )

    init_db(database)
    init_db(database)

    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT agent_id, started_at, ended_at FROM sessions WHERE session_id='old-session'"
        ).fetchone() == ("old-agent", 1.0, 2.0)
        assert connection.execute(
            "SELECT tool_name FROM tool_calls WHERE session_id='old-session'"
        ).fetchone() == ("read_file",)
        assert connection.execute(
            "SELECT tool_name FROM tool_definition_events WHERE session_id='old-session'"
        ).fetchone() == ("read_file",)
        tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
    assert {"mcp_servers", "mcp_server_connections"} <= tables


def test_inventory_registration_is_idempotent_for_one_proxy_session(tmp_path: Path) -> None:
    database = tmp_path / "idempotent-registration.db"
    store = TelemetryStore("inventory-idempotent-agent", db_path=database)

    first_id = store.register_mcp_server("test-server", "stdio")
    second_id = store.register_mcp_server("test-server", "stdio")

    assert first_id == second_id
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            "SELECT connection_count FROM mcp_servers"
        ).fetchone() == (1,)
        assert connection.execute(
            "SELECT COUNT(*) FROM mcp_server_connections"
        ).fetchone() == (1,)


def test_inventory_transport_rejects_noncanonical_values(tmp_path: Path) -> None:
    store = TelemetryStore(
        "inventory-transport-agent", db_path=tmp_path / "transport.db"
    )
    with pytest.raises(ValueError, match="transport"):
        store.register_mcp_server("test-server", "stdio --token=secret")
