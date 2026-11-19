"""
Phase 9 audit (Member 3) — can attacker-controlled strings hurt the telemetry store?

Agent IDs, tool names, arguments and result text come from systems an attacker can influence
(a prompt-injected agent, a malicious MCP server). They must be stored as inert data.
"""

import sqlite3

import pytest

from core.telemetry import TelemetryStore, get_session_calls

PAYLOADS = [
    "x'); DROP TABLE tool_calls;--",
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "unicode-\u202e-rtl-\u0000-test",
]


@pytest.mark.parametrize("payload", PAYLOADS)
def test_hostile_strings_are_stored_literally(tmp_path, payload):
    db = tmp_path / "audit.db"
    store = TelemetryStore(agent_id=payload, db_path=db)
    store.log_call(tool_name=payload, arguments={"k": payload}, duration_ms=1.0,
                   is_error=False, result_summary=payload)
    store.end_session()

    conn = sqlite3.connect(db)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"sessions", "tool_calls"} <= tables, "injection altered the schema"
    assert conn.execute("SELECT agent_id FROM sessions").fetchone()[0] == payload
    assert get_session_calls(store.session_id, db_path=db)[0]["tool_name"] == payload
    assert conn.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0] == 1
