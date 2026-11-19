from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest
from dotenv import load_dotenv

from agent import gemini_agent
from core.telemetry import DB_PATH
from scripts.verify_gemini_dashboard import verify_session_via_api

LIVE_TEST_FLAG = "AGENTSENTRY_RUN_LIVE_GEMINI"
KNOWN_STRING = "TODO"
LIVE_TASK_TIMEOUT_SECONDS = 300


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.asyncio
async def test_live_gemini_uses_proxy_and_persists_sandbox_search(tmp_path: Path) -> None:
    if os.getenv(LIVE_TEST_FLAG) != "1":
        pytest.skip(f"Set {LIVE_TEST_FLAG}=1 to enable the live Gemini API test")

    load_dotenv(gemini_agent.ROOT / ".env")
    if not os.getenv("GEMINI_API_KEY"):
        pytest.skip("GEMINI_API_KEY is unavailable")

    production_db = DB_PATH.resolve()
    production_db_hash = _sha256(production_db)
    test_db = (tmp_path / "live-gemini-agentsentry.db").resolve()
    assert test_db != production_db
    task = (
        f"Use the search_code tool to search the sandbox for the exact literal "
        f"string {KNOWN_STRING!r}. After receiving the search result, call the "
        "report tool with a concise summary stating whether it was found and, "
        "if found, the matching file path. Use exactly these tools in this "
        "order: search_code, report. Do not use any other tool."
    )

    try:
        result = await asyncio.wait_for(
            gemini_agent.run_task(
                task,
                db_path=str(test_db),
                required_tool_sequence=("search_code", "report"),
            ),
            timeout=LIVE_TASK_TIMEOUT_SECONDS,
        )
    finally:
        assert _sha256(production_db) == production_db_hash

    assert result["status"] == "completed"
    assert 1 <= result["tool_calls"] <= gemini_agent.MAX_TOOL_CALLS

    with sqlite3.connect(test_db) as connection:
        sessions = connection.execute(
            "SELECT session_id, agent_id, ended_at FROM sessions"
        ).fetchall()
        assert len(sessions) == 1
        session_id, agent_id, ended_at = sessions[0]
        assert agent_id == gemini_agent.AGENT_ID
        assert ended_at is not None

        calls = connection.execute(
            """SELECT sequence_num, tool_name, arguments_json, is_error, result_summary
               FROM tool_calls WHERE session_id = ? ORDER BY sequence_num""",
            (session_id,),
        ).fetchall()

    assert len(calls) == result["tool_calls"]
    assert len(calls) <= gemini_agent.MAX_TOOL_CALLS
    assert all(call[3] == 0 for call in calls)
    search_calls = [
        (json.loads(call[2]), call[4])
        for call in calls
        if call[1] == "search_code"
    ]
    assert any(
        KNOWN_STRING in arguments.get("query", "") and "notes.txt" in summary
        for arguments, summary in search_calls
    )

    report_calls = [
        json.loads(call[2]).get("summary", "")
        for call in calls
        if call[1] == "report"
    ]
    assert any(
        KNOWN_STRING in summary and "notes.txt" in summary
        for summary in report_calls
    )
    api_verification = verify_session_via_api(test_db, session_id)
    assert api_verification["agent"]["agent_id"] == gemini_agent.AGENT_ID
    assert [call["tool_name"] for call in api_verification["activity"]] == [
        "search_code",
        "report",
    ]
    assert _sha256(production_db) == production_db_hash
