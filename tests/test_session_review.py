import sqlite3
from pathlib import Path
import pytest
from core.telemetry import init_db
from core.session_review import review_session, get_review_status
from scripts.train_baseline import load_reviewed_sessions


def seeded_db(path: Path):
    init_db(path)
    with sqlite3.connect(path) as con:
        con.execute("INSERT INTO sessions VALUES ('s-1','agent-a',100.0,110.0)")
        con.execute("INSERT INTO tool_calls (session_id,sequence_num,tool_name,arguments_json,called_at,duration_ms,is_error,result_summary) VALUES ('s-1',1,'read_file','{}',101,2,0,'clean')")


def test_unreviewed_session_cannot_train(tmp_path):
    db=tmp_path/'telemetry.db'; seeded_db(db)
    with pytest.raises(ValueError, match='not been explicitly approved'):
        load_reviewed_sessions(db,'agent-a',['s-1'])


def test_review_requires_explicit_confirmation_and_completed_session(tmp_path):
    db=tmp_path/'telemetry.db'; seeded_db(db)
    with pytest.raises(ValueError, match='confirmation'):
        review_session(db,'s-1','approved','operator')
    with pytest.raises(ValueError, match='Active sessions'):
        with sqlite3.connect(db) as con: con.execute("UPDATE sessions SET ended_at=NULL WHERE session_id='s-1'")
        review_session(db,'s-1','approved','operator',confirm_reviewed=True)


def test_approval_unlocks_only_unchanged_session(tmp_path):
    db=tmp_path/'telemetry.db'; seeded_db(db)
    review_session(db,'s-1','approved','operator','Reviewed manually',True)
    loaded=load_reviewed_sessions(db,'agent-a',['s-1'])
    assert len(loaded)==1 and loaded[0][0]=='s-1'
    with sqlite3.connect(db) as con:
        con.execute("UPDATE tool_calls SET result_summary='changed' WHERE session_id='s-1'")
    with pytest.raises(ValueError, match='changed after review'):
        load_reviewed_sessions(db,'agent-a',['s-1'])


def test_rejection_and_reapproval_are_audited(tmp_path):
    db=tmp_path/'telemetry.db'; seeded_db(db)
    review_session(db,'s-1','rejected','operator','Suspicious',True)
    with sqlite3.connect(db) as con:
        assert con.execute("SELECT COUNT(*) FROM session_review_events").fetchone()[0]==1
    with pytest.raises(ValueError, match='not been explicitly approved'):
        load_reviewed_sessions(db,'agent-a',['s-1'])
    review_session(db,'s-1','approved','second-reviewer','Rechecked',True)
    with sqlite3.connect(db) as con:
        assert con.execute("SELECT COUNT(*) FROM session_review_events").fetchone()[0]==2


def test_approval_is_agent_specific_and_session_must_have_calls(tmp_path):
    db=tmp_path/'telemetry.db'; seeded_db(db)
    review_session(db,'s-1','approved','operator',confirm_reviewed=True)
    with pytest.raises(ValueError, match='different agent'):
        load_reviewed_sessions(db,'agent-b',['s-1'])
    with sqlite3.connect(db) as con:
        con.execute("INSERT INTO sessions VALUES ('empty','agent-a',100,110)")
    with pytest.raises(ValueError, match='without tool-call telemetry'):
        review_session(db,'empty','approved','operator',confirm_reviewed=True)

@pytest.mark.parametrize('bad', [None, 7, [], {}])
def test_rejects_malformed_review_fields(tmp_path, bad):
    db=tmp_path/'telemetry.db'; seeded_db(db)
    with pytest.raises(ValueError):
        review_session(db,'s-1',bad,'operator',confirm_reviewed=True)
    with pytest.raises(ValueError):
        review_session(db,'s-1','approved',bad,confirm_reviewed=True)
    with pytest.raises(ValueError):
        review_session(db,'s-1','approved','operator',bad,True)
