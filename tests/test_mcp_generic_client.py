from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import sys
from pathlib import Path

import pytest

from api.app import create_app
from mcp import ClientSession, StdioServerParameters, stdio_client

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.asyncio
async def test_independent_python_mcp_client_uses_proxy_without_gemini(
    tmp_path: Path,
) -> None:
    database = tmp_path / "generic-python-client.db"
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "core.proxy",
            "--agent-id",
            "independent-python-client",
            "--",
            sys.executable,
            str(ROOT / "mcp_lab" / "file_tools_server.py"),
        ],
        cwd=str(ROOT),
        env={
            **os.environ,
            "AGENTSENTRY_DB_PATH": str(database),
        },
    )

    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as client:
            initialized = await client.initialize()
            assert initialized.server_info.name == "agentsentry-proxy"
            assert initialized.capabilities.tools is not None
            tools = await client.list_tools()
            assert {tool.name for tool in tools.tools} == {
                "read_file",
                "search_code",
                "report",
            }
            search = await client.call_tool("search_code", {"query": "TODO"})
            assert not search.is_error
            assert "notes.txt" in search.content[0].text

            unknown = await client.call_tool("no_such_tool", {})
            assert unknown.is_error

    with sqlite3.connect(database) as connection:
        session = connection.execute(
            """SELECT s.agent_id, s.ended_at, server.server_name, server.transport
               FROM sessions AS s
               JOIN mcp_server_connections AS c ON c.session_id = s.session_id
               JOIN mcp_servers AS server ON server.server_id = c.server_id"""
        ).fetchone()
        calls = connection.execute(
            "SELECT tool_name, is_error FROM tool_calls ORDER BY sequence_num"
        ).fetchall()
    assert session is not None
    assert session[:1] == ("independent-python-client",)
    assert session[1] is not None
    assert session[2:] == ("agentsentry-lab-file-tools", "stdio")
    assert calls == [("search_code", 0), ("no_such_tool", 1)]

    inventory = create_app(
        {"TESTING": True, "DATABASE": str(database)}
    ).test_client().get("/api/mcp/servers").get_json()
    assert inventory["available"] is True
    assert inventory["servers"][0]["agents"] == [
        {"agent_id": "independent-python-client", "connection_count": 1}
    ]


@pytest.mark.asyncio
async def test_raw_jsonrpc_stdio_client_can_initialize_list_call_error_and_exit(
    tmp_path: Path,
) -> None:
    database = tmp_path / "raw-jsonrpc-client.db"
    environment = os.environ.copy()
    environment["AGENTSENTRY_DB_PATH"] = str(database)
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "core.proxy",
        "--agent-id",
        "raw-jsonrpc-client",
        "--",
        sys.executable,
        str(ROOT / "mcp_lab" / "file_tools_server.py"),
        cwd=str(ROOT),
        env=environment,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert process.stdin is not None
    assert process.stdout is not None

    async def send(payload: dict[str, object]) -> None:
        process.stdin.write((json.dumps(payload) + "\n").encode())
        await process.stdin.drain()

    async def receive_response(request_id: int) -> dict[str, object]:
        while True:
            line = await asyncio.wait_for(process.stdout.readline(), timeout=10)
            assert line, "Proxy exited before returning the JSON-RPC response"
            message = json.loads(line)
            if message.get("id") == request_id:
                return message

    try:
        await send(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "raw-jsonrpc-client", "version": "1"},
                },
            }
        )
        initialized = await receive_response(1)
        assert initialized["result"]["serverInfo"]["name"] == "agentsentry-proxy"
        assert initialized["result"]["capabilities"]["tools"]["listChanged"] is True
        await send({"jsonrpc": "2.0", "method": "notifications/initialized"})

        await send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = await receive_response(2)
        assert {tool["name"] for tool in tools["result"]["tools"]} == {
            "read_file",
            "search_code",
            "report",
        }

        await send(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "search_code", "arguments": {"query": "TODO"}},
            }
        )
        call = await receive_response(3)
        assert call["result"]["isError"] is False
        assert "notes.txt" in call["result"]["content"][0]["text"]

        await send(
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {"name": "unknown", "arguments": {}},
            }
        )
        error = await receive_response(4)
        assert "error" in error or error.get("result", {}).get("isError") is True

        await send({"jsonrpc": "2.0", "method": "exit"})
        process.stdin.close()
        await asyncio.wait_for(process.wait(), timeout=15)
        assert process.returncode == 0
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()

    with sqlite3.connect(database) as connection:
        session = connection.execute(
            "SELECT agent_id, ended_at FROM sessions"
        ).fetchone()
        call = connection.execute(
            "SELECT tool_name, is_error FROM tool_calls"
        ).fetchone()
    assert session is not None and session[0] == "raw-jsonrpc-client"
    assert session[1] is not None
    assert call == ("search_code", 0)


@pytest.mark.asyncio
async def test_allowlisted_downstream_secret_is_not_persisted_or_returned_by_api(
    tmp_path: Path,
) -> None:
    database = tmp_path / "secret-redaction.db"
    server_script = tmp_path / "secret_server.py"
    server_script.write_text(
        """import os
from mcp.server import MCPServer

server = MCPServer(name="secret-test-server", description="test server")

@server.tool()
def reveal() -> str:
    return os.environ["TEST_DOWNSTREAM_SECRET"]

if __name__ == "__main__":
    server.run()
""",
        encoding="utf-8",
    )
    secret = "FAKE-ENV-SECRET-DO-NOT-PERSIST"
    parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "core.proxy",
            "--agent-id",
            "secret-redaction-client",
            "--pass-env",
            "TEST_DOWNSTREAM_SECRET",
            "--",
            sys.executable,
            str(server_script),
        ],
        cwd=str(ROOT),
        env={
            **os.environ,
            "AGENTSENTRY_DB_PATH": str(database),
            "TEST_DOWNSTREAM_SECRET": secret,
        },
    )

    async with stdio_client(parameters) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as client:
            await client.initialize()
            result = await client.call_tool("reveal", {})
            assert result.content[0].text == secret

    with sqlite3.connect(database) as connection:
        stored_arguments, stored_result = connection.execute(
            "SELECT arguments_json, result_summary FROM tool_calls"
        ).fetchone()
    assert secret not in stored_arguments
    assert secret not in stored_result

    api_client = create_app(
        {"TESTING": True, "DATABASE": str(database)}
    ).test_client()
    activity = api_client.get("/api/dashboard/activity").get_data(as_text=True)
    inventory = api_client.get("/api/mcp/servers").get_data(as_text=True)
    assert secret not in activity
    assert secret not in inventory
    assert "[REDACTED]" in activity
