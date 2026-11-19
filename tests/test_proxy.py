"""
Phase 2 tests: interception proxy correctness + telemetry integrity.

Run:
    pytest tests/ -v --asyncio-mode=auto
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from types import SimpleNamespace
from pathlib import Path

import pytest

from mcp import ClientSession, StdioServerParameters, stdio_client, types
from core import telemetry
from core.chain_detector import detect_chains
from core.proxy import AgentSentryProxy, _changed_tool_definitions
from agent.demo_agent import _proxied_server_params

PROJECT_ROOT = Path(__file__).parent.parent


@pytest.fixture
def temp_db(tmp_path):
    """A throwaway DB path per test so tests never share state.

    NOTE: the proxy runs as a real subprocess (spawned via stdio_client), so a
    plain monkeypatch on telemetry.DB_PATH in this process would NOT reach it.
    We pass the path via the AGENTSENTRY_DB_PATH env var instead — see
    _proxied_server_params(db_path=...) and core/proxy.py.
    """
    return tmp_path / "test_agentsentry.db"


@pytest.mark.asyncio
async def test_proxy_is_transparent_same_tools_as_direct(temp_db):
    """The agent should see the exact same tool list through the proxy as direct."""
    params = _proxied_server_params(agent_id="test-transparency", db_path=str(temp_db))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            tools = await session.list_tools()
            tool_names = {t.name for t in tools.tools}
            assert tool_names == {"read_file", "search_code", "report"}


@pytest.mark.asyncio
async def test_proxy_forwards_correct_result(temp_db):
    params = _proxied_server_params(agent_id="test-forwarding", db_path=str(temp_db))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            result = await session.call_tool("read_file", {"path": "notes.txt"})
            assert "TODO" in result.content[0].text


@pytest.mark.asyncio
async def test_every_call_is_logged_no_drops(temp_db):
    """Core Phase 2 guarantee: N calls made => N calls logged. Zero blind spots."""
    params = _proxied_server_params(agent_id="test-no-drops", db_path=str(temp_db))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            await session.call_tool("read_file", {"path": "notes.txt"})
            await session.call_tool("search_code", {"query": "TODO"})
            await session.call_tool("report", {"summary": "done"})

    # Read the DB directly (fresh connection, mirrors what the dashboard will do later)
    rows = telemetry.get_session_calls(_latest_session_id(temp_db), db_path=temp_db)
    assert len(rows) == 3
    assert [r["tool_name"] for r in rows] == ["read_file", "search_code", "report"]
    assert [r["sequence_num"] for r in rows] == [1, 2, 3]


@pytest.mark.asyncio
async def test_arguments_are_captured_accurately(temp_db):
    params = _proxied_server_params(agent_id="test-args", db_path=str(temp_db))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            await session.call_tool("read_file", {"path": "notes.txt"})

    rows = telemetry.get_session_calls(_latest_session_id(temp_db), db_path=temp_db)
    assert '"path": "notes.txt"' in rows[0]["arguments_json"]


@pytest.mark.asyncio
async def test_exception_path_is_still_logged(temp_db):
    """A downstream exception (e.g. blocked path traversal) must not create a blind spot."""
    params = _proxied_server_params(agent_id="test-exception-logged", db_path=str(temp_db))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            result = await session.call_tool("read_file", {"path": "../../../etc/passwd"})
            assert result.is_error is True

    rows = telemetry.get_session_calls(_latest_session_id(temp_db), db_path=temp_db)
    assert len(rows) == 1
    assert rows[0]["is_error"] == 1
    assert "traversal blocked" in rows[0]["result_summary"].lower()


@pytest.mark.asyncio
async def test_concurrent_calls_keep_request_order_when_completion_is_reversed(temp_db):
    class DelayedDownstream:
        async def call_tool(self, name, arguments):
            if name == "first":
                await asyncio.sleep(0.05)
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=name)]
            )

    proxy = AgentSentryProxy("test-concurrent-order", sys.executable, [], db_path=temp_db)
    proxy.downstream_session = DelayedDownstream()
    ctx = SimpleNamespace(session=None)

    await asyncio.gather(
        proxy._on_call_tool(
            ctx, types.CallToolRequestParams(name="first", arguments={})
        ),
        proxy._on_call_tool(
            ctx, types.CallToolRequestParams(name="second", arguments={})
        ),
    )

    rows = telemetry.get_session_calls(proxy.telemetry.session_id, db_path=temp_db)
    assert [row["sequence_num"] for row in rows] == [1, 2]
    assert [row["result_summary"] for row in rows] == ["first", "second"]


@pytest.mark.asyncio
async def test_session_end_time_is_recorded(temp_db):
    params = _proxied_server_params(agent_id="test-session-end", db_path=str(temp_db))
    async with stdio_client(params) as (r, w):
        async with ClientSession(r, w) as session:
            await session.initialize()
            await session.call_tool("report", {"summary": "x"})

    import sqlite3
    conn = sqlite3.connect(temp_db)
    row = conn.execute("SELECT ended_at FROM sessions").fetchone()
    assert row[0] is not None


def test_tool_definition_comparison_detects_schema_changes():
    before = {
        "read_document": {
            "name": "read_document",
            "inputSchema": {"properties": {"doc_id": {"type": "string"}}},
        }
    }
    after = {
        "read_document": {
            "name": "read_document",
            "inputSchema": {
                "properties": {
                    "doc_id": {"type": "string"},
                    "access_grant": {"type": "string"},
                }
            },
        }
    }

    changes = _changed_tool_definitions(before, after)
    assert changes == [("read_document", before["read_document"], after["read_document"])]


@pytest.mark.asyncio
async def test_proxy_observes_and_forwards_real_tool_schema_change(temp_db):
    env = os.environ.copy()
    env["AGENTSENTRY_DB_PATH"] = str(temp_db)
    env["AGENTSENTRY_LAB_RUG_PULL_AFTER_CALLS"] = "2"
    params = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "core.proxy",
            "--agent-id",
            "test-real-rug-pull",
            "--",
            sys.executable,
            str(PROJECT_ROOT / "mcp_lab" / "vulnerable_server.py"),
        ],
        cwd=str(PROJECT_ROOT),
        env=env,
    )
    received_notifications = []
    notification_received = asyncio.Event()

    async def on_message(message):
        if isinstance(message, types.ToolListChangedNotification):
            received_notifications.append(message)
            notification_received.set()

    async with stdio_client(params) as (read_stream, write_stream):
        async with ClientSession(
            read_stream, write_stream, message_handler=on_message
        ) as session:
            initialized = await session.initialize()
            assert initialized.capabilities.tools.list_changed is True
            initial_tools = await session.list_tools()
            initial_tool = next(tool for tool in initial_tools.tools if tool.name == "read_document")
            before_schema = initial_tool.model_dump(by_alias=True, mode="json")["inputSchema"]

            await session.call_tool("read_document", {"doc_id": "q3-report"})
            await session.call_tool("read_document", {"doc_id": "q3-report"})
            await asyncio.wait_for(notification_received.wait(), timeout=5)

            updated_tools = await session.list_tools()
            updated_tool = next(tool for tool in updated_tools.tools if tool.name == "read_document")
            after_schema = updated_tool.model_dump(by_alias=True, mode="json")["inputSchema"]
            assert after_schema != before_schema
            assert "access_grant" in after_schema["required"]

            result = await session.call_tool(
                "read_document",
                {
                    "doc_id": "q3-report",
                    "include_secrets": True,
                    "access_grant": "SIMULATED-LAB-ACCESS",
                },
            )
            assert "FAKE-LAB-TOKEN-0000" in result.content[0].text

    assert len(received_notifications) == 1
    sid = _latest_session_id(temp_db)
    events = telemetry.get_session_tool_definition_events(sid, db_path=temp_db)
    assert len(events) == 1
    assert events[0]["event_type"] == "tool_definition_changed"
    assert events[0]["notification_method"] == "notifications/tools/list_changed"
    assert events[0]["tool_name"] == "read_document"
    assert json.loads(events[0]["before_schema_json"]) == before_schema
    assert json.loads(events[0]["after_schema_json"]) == after_schema

    rows = telemetry.get_session_timeline(sid, db_path=temp_db)
    assert [row["tool_name"] for row in rows if row.get("event_type") is None] == [
        "read_document",
        "read_document",
        "read_document",
    ]
    assert any(chain.chain_id == "tool_definition_changed" for chain in detect_chains(rows))

    from api.app import create_app

    api_client = create_app(
        {
            "TESTING": True,
            "DATABASE": str(temp_db),
            "MODEL_DIR": str(temp_db.parent / "models"),
        }
    ).test_client()
    api_changes = api_client.get("/api/mcp/tool-changes")
    assert api_changes.status_code == 200
    assert api_changes.json[0]["session_id"] == sid
    api_assessment = api_client.get(f"/api/sessions/{sid}/assessment")
    assert api_assessment.status_code == 200
    assert any(
        chain["chain_id"] == "tool_definition_changed"
        for chain in api_assessment.json["attack_chains"]
    )


def _latest_session_id(db_path: Path) -> str:
    import sqlite3
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT session_id FROM sessions ORDER BY started_at DESC LIMIT 1").fetchone()
    return row["session_id"]
