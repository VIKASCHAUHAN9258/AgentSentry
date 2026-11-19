from __future__ import annotations

import hashlib
import sqlite3
from pathlib import Path

from agent import gemini_agent
from core.telemetry import TelemetryStore
from scripts.verify_gemini_dashboard import verify_session_via_api


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_gemini_session_is_verified_from_existing_dashboard_api(tmp_path: Path) -> None:
    database = tmp_path / "dashboard-verification.db"
    store = TelemetryStore(gemini_agent.AGENT_ID, db_path=database)
    report_text = "The literal 'TODO' was found in the matching file path: notes.txt."
    store.log_call(
        "search_code",
        {"query": "TODO"},
        duration_ms=1.5,
        is_error=False,
        result_summary="Matches:\nnotes.txt",
    )
    store.log_call(
        "report",
        {"summary": report_text},
        duration_ms=0.5,
        is_error=False,
        result_summary=f"Report recorded ({len(report_text)} chars).",
    )
    store.end_session()
    before_api_reads = _sha256(database)

    verification = verify_session_via_api(database, store.session_id)

    assert verification["health"] == {"status": "ok", "database": "connected"}
    assert verification["agent"]["agent_id"] == gemini_agent.AGENT_ID
    assert verification["session"]["session_id"] == store.session_id
    assert verification["overview"]["sessions_total"] == 1
    assert verification["overview"]["tool_calls_total"] == 2
    assert verification["session_detail"]["calls"][0]["arguments"] == {"query": "TODO"}
    assert [item["tool_name"] for item in verification["activity"]] == [
        "search_code",
        "report",
    ]
    assert _sha256(database) == before_api_reads

    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
        assert connection.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0] == 2
