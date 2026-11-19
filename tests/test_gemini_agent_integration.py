from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from agent import gemini_agent
from core.telemetry import DB_PATH


def _function_response(name: str, args: dict[str, str]) -> Any:
    call = SimpleNamespace(name=name, args=args)
    part = SimpleNamespace(function_call=call)
    candidate = SimpleNamespace(content=SimpleNamespace(parts=[part]))
    return SimpleNamespace(candidates=[candidate])


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.asyncio
async def test_gemini_agent_records_real_proxy_tool_calls_in_temporary_database(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    production_db = DB_PATH.resolve()
    production_db_hash = _sha256(production_db)
    test_db = (tmp_path / "gemini-integration.db").resolve()
    assert test_db != production_db
    monkeypatch.setenv("GEMINI_API_KEY", "integration-test-key")
    stdio_client = gemini_agent.stdio_client
    proxy_shutdown_completed = False

    @asynccontextmanager
    async def proxy_without_api_key(params: Any) -> Any:
        nonlocal proxy_shutdown_completed
        assert params.env is not None
        assert "GEMINI_API_KEY" not in params.env
        async with stdio_client(params) as streams:
            yield streams
        proxy_shutdown_completed = True

    generation_count = 0

    async def deterministic_generation(*generation_args: Any) -> Any:
        nonlocal generation_count
        generation_count += 1
        contents = generation_args[2]
        declarations = generation_args[3]

        assert {declaration.name for declaration in declarations} == {
            "read_file",
            "search_code",
            "report",
        }
        returned_tool_results = [
            part.function_response.response
            for content in contents
            if hasattr(content, "parts")
            for part in content.parts
            if getattr(part, "function_response", None) is not None
        ]

        if generation_count == 1:
            return _function_response("read_file", {"path": "notes.txt"})
        if generation_count == 2:
            assert returned_tool_results
            assert "TODO" in json.dumps(returned_tool_results[0])
            return _function_response("search_code", {"query": "TODO"})

        assert generation_count == 3
        assert len(returned_tool_results) == 2
        return SimpleNamespace(text="Read the sandbox notes and searched for TODO.")

    monkeypatch.setattr(gemini_agent, "_generate", deterministic_generation)
    monkeypatch.setattr(gemini_agent, "stdio_client", proxy_without_api_key)

    result = await gemini_agent.run_task(
        "Read notes.txt and search it for TODO.",
        db_path=str(test_db),
        required_tool_sequence=("read_file", "search_code"),
    )

    assert result["status"] == "completed"
    assert result["tool_calls"] == 2
    assert generation_count == 3
    assert proxy_shutdown_completed, "run_task returned before the proxy stdio client shut down"

    with sqlite3.connect(test_db) as connection:
        session_rows = connection.execute(
            "SELECT session_id, agent_id, ended_at FROM sessions"
        ).fetchall()
        assert len(session_rows) == 1
        session_id, agent_id, ended_at = session_rows[0]
        assert agent_id == gemini_agent.AGENT_ID
        assert ended_at is not None

        tool_rows = connection.execute(
            """SELECT sequence_num, tool_name, arguments_json, is_error, result_summary
               FROM tool_calls WHERE session_id = ? ORDER BY sequence_num""",
            (session_id,),
        ).fetchall()

    assert [row[0] for row in tool_rows] == [1, 2]
    assert [row[1] for row in tool_rows] == ["read_file", "search_code"]
    assert [json.loads(row[2]) for row in tool_rows] == [
        {"path": "notes.txt"},
        {"query": "TODO"},
    ]
    assert [row[3] for row in tool_rows] == [0, 0]
    assert all(row[4] for row in tool_rows)
    assert _sha256(production_db) == production_db_hash


@pytest.mark.asyncio
async def test_required_tool_sequence_rejects_unexpected_tool_before_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    test_db = (tmp_path / "gemini-sequence-guard.db").resolve()
    monkeypatch.setenv("GEMINI_API_KEY", "integration-test-key")

    async def unexpected_tool(*_generation_args: Any) -> Any:
        return _function_response("read_file", {"path": "notes.txt"})

    monkeypatch.setattr(gemini_agent, "_generate", unexpected_tool)

    with pytest.raises(BaseExceptionGroup) as raised:
        await gemini_agent.run_task(
            "Search the sandbox, then report.",
            db_path=str(test_db),
            required_tool_sequence=("search_code", "report"),
        )
    pending = list(raised.value.exceptions)
    while pending:
        exception = pending.pop()
        if isinstance(exception, BaseExceptionGroup):
            pending.extend(exception.exceptions)
        else:
            assert isinstance(exception, gemini_agent.AgentError)
            assert "outside the required sequence" in str(exception)

    with sqlite3.connect(test_db) as connection:
        session_rows = connection.execute(
            "SELECT ended_at FROM sessions"
        ).fetchall()
        call_count = connection.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
    assert len(session_rows) == 1
    assert session_rows[0][0] is not None
    assert call_count == 0
