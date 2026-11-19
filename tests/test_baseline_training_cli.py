import sqlite3
from pathlib import Path

import pytest

from scripts.train_baseline import load_reviewed_sessions
from core.telemetry import init_db
from core.session_review import review_session


def make_db(path: Path):
    init_db(path)
    with sqlite3.connect(path) as conn:
        conn.execute("INSERT INTO sessions VALUES ('done', 'agent-a', 100.0, 123.0)")
        conn.execute("INSERT INTO sessions VALUES ('active', 'agent-a', 100.0, NULL)")
        conn.execute("INSERT INTO sessions VALUES ('other', 'agent-b', 100.0, 123.0)")
        conn.execute("INSERT INTO tool_calls (session_id, sequence_num, tool_name, arguments_json, called_at, duration_ms, is_error) VALUES ('done', 1, 'read_file', '{}', 101.0, 1.0, 0)")
    review_session(path, 'done', 'approved', 'test-operator', confirm_reviewed=True)


def test_loads_only_explicit_completed_sessions(tmp_path):
    db = tmp_path / 'telemetry.db'
    make_db(db)
    result = load_reviewed_sessions(db, 'agent-a', ['done'])
    assert len(result) == 1
    assert result[0][0] == 'done'
    assert len(result[0][1]) == 1


@pytest.mark.parametrize(('agent', 'session', 'message'), [
    ('agent-a', 'active', 'still active'),
    ('agent-a', 'missing', 'not found'),
    ('agent-a', 'other', 'different agent'),
])
def test_rejects_invalid_training_sessions(tmp_path, agent, session, message):
    db = tmp_path / 'telemetry.db'
    make_db(db)
    with pytest.raises(ValueError, match=message):
        load_reviewed_sessions(db, agent, [session])


def test_rejects_duplicate_ids(tmp_path):
    db = tmp_path / 'telemetry.db'
    make_db(db)
    with pytest.raises(ValueError, match='Duplicate'):
        load_reviewed_sessions(db, 'agent-a', ['done', 'done'])
