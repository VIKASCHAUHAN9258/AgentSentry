"""Opt-in live verification of Gemini telemetry through the dashboard API.

Run from the repository root with:
    python scripts/verify_gemini_dashboard.py --run-live --confirm-production-write

The command appends one Gemini session to the existing production telemetry
database. It never seeds, updates, or deletes existing telemetry.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sqlite3
import sys
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from api.app import create_app
from agent import gemini_agent
from core.telemetry import DB_PATH
from dotenv import load_dotenv

EXPECTED_TOOLS = ("search_code", "report")
SEARCH_QUERY = "TODO"
LIVE_TASK_TIMEOUT_SECONDS = 300


def verify_session_via_api(
    database: Path,
    session_id: str,
) -> dict[str, Any]:
    """Verify one persisted session and dashboard metrics through Flask routes."""
    client = create_app(
        {"TESTING": True, "DATABASE": str(database.resolve())}
    ).test_client()

    health_response = client.get("/api/health")
    assert health_response.status_code == 200, health_response.get_json()
    health = health_response.get_json()
    assert health == {"status": "ok", "database": "connected"}

    agents_response = client.get("/api/agents")
    assert agents_response.status_code == 200, agents_response.get_json()
    agents = agents_response.get_json()
    agent = next(
        (item for item in agents if item["agent_id"] == gemini_agent.AGENT_ID),
        None,
    )
    assert agent is not None, "Gemini agent is absent from persisted agent telemetry"
    assert agent["tool_call_count"] >= len(EXPECTED_TOOLS)

    sessions_response = client.get(
        f"/api/sessions?agent_id={gemini_agent.AGENT_ID}&limit=200"
    )
    assert sessions_response.status_code == 200, sessions_response.get_json()
    session = next(
        (item for item in sessions_response.get_json() if item["session_id"] == session_id),
        None,
    )
    assert session is not None, "Gemini session is absent from the sessions API"
    assert session["agent_id"] == gemini_agent.AGENT_ID
    assert session["ended_at"] is not None
    assert session["call_count"] == len(EXPECTED_TOOLS)

    detail_response = client.get(f"/api/sessions/{session_id}")
    assert detail_response.status_code == 200, detail_response.get_json()
    detail = detail_response.get_json()
    assert detail["session"]["session_id"] == session_id
    assert detail["session"]["ended_at"] is not None
    detail_calls = sorted(detail["calls"], key=lambda item: item["sequence_num"])
    detail_tools = [item["tool_name"] for item in detail_calls]
    assert detail_tools == list(EXPECTED_TOOLS), (
        f"Expected session detail tools {list(EXPECTED_TOOLS)!r}, received {detail_tools!r}"
    )
    assert all(item["is_error"] == 0 for item in detail_calls)

    overview_response = client.get("/api/dashboard/overview")
    assert overview_response.status_code == 200, overview_response.get_json()
    overview = overview_response.get_json()
    assert overview["metrics_note"] == "Counts are derived from persisted SQLite telemetry."
    with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True) as connection:
        persisted_counts = {
            "sessions_total": connection.execute(
                "SELECT COUNT(*) FROM sessions"
            ).fetchone()[0],
            "tool_calls_total": connection.execute(
                "SELECT COUNT(*) FROM tool_calls"
            ).fetchone()[0],
            "agents_total": connection.execute(
                "SELECT COUNT(DISTINCT agent_id) FROM sessions"
            ).fetchone()[0],
            "active_sessions": connection.execute(
                "SELECT COUNT(*) FROM sessions WHERE ended_at IS NULL"
            ).fetchone()[0],
            "tool_definition_changes": connection.execute(
                "SELECT COUNT(*) FROM tool_definition_events"
            ).fetchone()[0],
        }
    assert {key: overview[key] for key in persisted_counts} == persisted_counts

    activity_response = client.get("/api/dashboard/activity?limit=200")
    assert activity_response.status_code == 200, activity_response.get_json()
    activity = activity_response.get_json()
    session_calls = [
        item
        for item in activity
        if item["event_type"] == "tool_call" and item["session_id"] == session_id
    ]
    session_calls.sort(key=lambda item: item["sequence_num"])
    actual_tools = [item["tool_name"] for item in session_calls]
    assert actual_tools == list(EXPECTED_TOOLS), (
        f"Expected tool sequence {list(EXPECTED_TOOLS)!r}, received {actual_tools!r}"
    )
    assert all(item["is_error"] == 0 for item in session_calls)

    search_call = session_calls[0]
    report_call = session_calls[1]
    search_detail, report_detail = detail_calls

    assert search_detail["arguments"] == {"query": SEARCH_QUERY}
    search_results = search_call["result_summary"].splitlines()
    assert search_results and search_results[0] == "Matches:"
    assert "notes.txt" in search_results[1:], (
        "Sandbox search result did not report notes.txt as a match"
    )

    report_text = report_detail["arguments"].get("summary")
    assert isinstance(report_text, str) and report_text.strip()
    assert SEARCH_QUERY in report_text and "notes.txt" in report_text
    report_match = re.fullmatch(
        r"Report recorded \((\d+) chars\)\.", report_call["result_summary"]
    )
    assert report_match is not None, "Report tool did not return its persisted success summary"
    assert int(report_match.group(1)) == len(report_text), (
        "Report tool summary length does not match the recorded report argument"
    )

    return {
        "health": health,
        "agent": agent,
        "session": session,
        "session_detail": detail,
        "overview": overview,
        "activity": session_calls,
    }


def _run_live_verification() -> dict[str, Any]:
    database = DB_PATH.resolve()
    if not database.is_file():
        raise RuntimeError(
            f"Production telemetry database does not exist: {database}. "
            "Refusing to initialize or create it."
        )

    load_dotenv(gemini_agent.ROOT / ".env")
    if not os.getenv("GEMINI_API_KEY"):
        raise RuntimeError("GEMINI_API_KEY is unavailable; no live request was made.")

    initial = create_app(
        {"TESTING": True, "DATABASE": str(database)}
    ).test_client().get("/api/health")
    if initial.status_code != 200:
        raise RuntimeError(
            f"Production telemetry API health check failed: {initial.get_json()}"
        )
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        previous_session_ids = {
            row[0]
            for row in connection.execute(
                "SELECT session_id FROM sessions WHERE agent_id = ?",
                (gemini_agent.AGENT_ID,),
            )
        }

    task = (
        "Use search_code to search the sandbox for the exact literal "
        f"{SEARCH_QUERY!r}. After the search result, call report with a concise "
        "summary stating whether it was found and, if found, the matching file "
        "path. Use exactly these two tools, in this order: search_code, report. "
        "Do not use read_file or any other tool."
    )
    result = asyncio.run(
        asyncio.wait_for(
            gemini_agent.run_task(
                task,
                db_path=str(database),
                required_tool_sequence=EXPECTED_TOOLS,
            ),
            timeout=LIVE_TASK_TIMEOUT_SECONDS,
        )
    )
    if result["status"] != "completed" or result["tool_calls"] != len(EXPECTED_TOOLS):
        raise RuntimeError(f"Gemini did not complete the required two-tool task: {result}")

    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        new_sessions = connection.execute(
            """SELECT session_id FROM sessions
               WHERE agent_id = ? ORDER BY started_at DESC""",
            (gemini_agent.AGENT_ID,),
        ).fetchall()
    created_session_ids = [
        row[0] for row in new_sessions if row[0] not in previous_session_ids
    ]
    if len(created_session_ids) != 1:
        raise RuntimeError(
            "Expected exactly one newly appended Gemini session, found "
            f"{len(created_session_ids)}."
        )

    verification = verify_session_via_api(database, created_session_ids[0])
    return {
        "result": result,
        "verification": verification,
        "database": str(database),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Append one controlled Gemini session and verify its live dashboard API telemetry."
    )
    parser.add_argument(
        "--run-live",
        action="store_true",
        help="Make one real Gemini API request through the AgentSentry proxy.",
    )
    parser.add_argument(
        "--confirm-production-write",
        action="store_true",
        help="Confirm that this run appends one new session to the production telemetry database.",
    )
    args = parser.parse_args()
    if not args.run_live or not args.confirm_production_write:
        parser.error(
            "both --run-live and --confirm-production-write are required; "
            "this command appends a live Gemini session to production telemetry"
        )

    output = _run_live_verification()
    print(json.dumps(output, indent=2, ensure_ascii=False, default=str))
    print(
        "\nAPI verification passed. Open the dashboard and refresh Incident "
        "Management; find gemini-code-agent in Agent sessions and inspect its "
        "search_code and report activity."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
