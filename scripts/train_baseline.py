"""Explicitly train one AgentSentry baseline from operator-reviewed benign sessions.

This command never guesses that a session is benign. The operator must supply
session IDs and explicitly confirm that they were reviewed as benign.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.detector import (  # noqa: E402
    MIN_TRAINING_SESSIONS,
    BehaviorAnomalyDetector,
)
from core.features import extract_session_features  # noqa: E402
from core.session_review import evidence_digest, session_evidence  # noqa: E402
from core.chain_detector import detect_chains  # noqa: E402
from core.policy import evaluate_policy, get_policy  # noqa: E402


def load_reviewed_sessions(db_path: Path, agent_id: str, session_ids: list[str]):
    if len(set(session_ids)) != len(session_ids):
        raise ValueError("Duplicate session IDs are not allowed.")
    if not session_ids:
        raise ValueError("Provide explicit --session-id values; automatic session selection is disabled.")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN")  # consistent read snapshot during approval/fingerprint validation
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        selected = []
        for session_id in session_ids:
            session = conn.execute(
                "SELECT session_id, agent_id, ended_at FROM sessions WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if session is None:
                raise ValueError(f"Session not found: {session_id}")
            if session["agent_id"] != agent_id:
                raise ValueError(f"Session {session_id} belongs to a different agent.")
            if session["ended_at"] is None:
                raise ValueError(f"Session {session_id} is still active; only completed sessions can train a baseline.")
            calls = conn.execute(
                "SELECT sequence_num, tool_name, arguments_json, called_at, duration_ms, is_error "
                "FROM tool_calls WHERE session_id = ? ORDER BY sequence_num ASC",
                (session_id,),
            ).fetchall()
            if not calls:
                raise ValueError(f"Session {session_id} has no tool-call telemetry.")
            if "session_reviews" not in tables:
                raise ValueError("Session review schema is missing; initialize the database and review sessions first.")
            review = conn.execute(
                "SELECT decision, evidence_sha256 FROM session_reviews WHERE session_id = ?",
                (session_id,),
            ).fetchone()
            if review is None or review["decision"] != "approved":
                raise ValueError(f"Session {session_id} has not been explicitly approved by a human reviewer.")
            evidence_session, evidence_calls, evidence_events = session_evidence(conn, session_id)
            if evidence_digest(evidence_session, evidence_calls, evidence_events) != review["evidence_sha256"]:
                raise ValueError(f"Session {session_id} telemetry changed after review; review it again.")
            if evidence_events:
                raise ValueError(f"Session {session_id} contains tool-definition changes and is not eligible for a benign baseline.")
            features = extract_session_features(session_id, calls)
            violations = evaluate_policy(features, get_policy(agent_id))
            if violations:
                raise ValueError(f"Session {session_id} violates the agent policy and cannot enter a benign baseline.")
            chains = detect_chains([dict(row) for row in calls])
            if chains:
                raise ValueError(f"Session {session_id} contains an attack-chain finding and cannot enter a benign baseline.")
            selected.append((session_id, calls))
        return selected
    finally:
        conn.close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Train an agent-specific baseline from explicitly reviewed benign MCP sessions.")
    parser.add_argument("--agent-id", required=True, help="Exact agent ID recorded in telemetry")
    parser.add_argument("--db", required=True, type=Path, help="Telemetry SQLite database path")
    parser.add_argument("--model-dir", required=True, type=Path, help="Trusted model directory")
    parser.add_argument("--session-id", action="append", default=[], help="Reviewed benign session ID; repeat at least 10 times")
    parser.add_argument("--i-confirm-benign", action="store_true", help="Confirm every supplied session was manually reviewed as benign")
    parser.add_argument("--dry-run", action="store_true", help="Validate and summarize data without training or writing model files")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.i_confirm_benign:
        print("Refusing to train: review every session and pass --i-confirm-benign.", file=sys.stderr)
        return 2
    if not args.db.is_file():
        print(f"Telemetry database does not exist: {args.db}", file=sys.stderr)
        return 2
    try:
        sessions = load_reviewed_sessions(args.db, args.agent_id, args.session_id)
        if len(sessions) < MIN_TRAINING_SESSIONS:
            raise ValueError(f"Need at least {MIN_TRAINING_SESSIONS} reviewed benign sessions; got {len(sessions)}.")
        vectors = [extract_session_features(session_id, rows).to_vector() for session_id, rows in sessions]
        if args.dry_run:
            print(json.dumps({"agent_id": args.agent_id, "sessions": len(vectors), "calls": sum(len(rows) for _, rows in sessions), "status": "VALIDATED_NO_MODEL_WRITTEN"}, indent=2))
            return 0
        detector = BehaviorAnomalyDetector(args.agent_id, args.model_dir)
        detector.fit(vectors)
        model_path = detector.save()
        print(json.dumps({"agent_id": args.agent_id, "training_sessions": len(vectors), "tool_calls": sum(len(rows) for _, rows in sessions), "model_path": str(model_path), "lifecycle": BehaviorAnomalyDetector.status(args.agent_id, args.model_dir)}, indent=2))
        return 0
    except (ValueError, OSError, sqlite3.Error) as exc:
        print(f"Baseline training refused: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
