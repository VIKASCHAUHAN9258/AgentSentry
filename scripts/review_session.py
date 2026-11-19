"""Explicitly approve or reject a completed AgentSentry session for baseline use."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from core.session_review import review_session
from core.telemetry import DB_PATH

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, default=DB_PATH)
    parser.add_argument('--session-id', required=True)
    parser.add_argument('--decision', choices=('approved', 'rejected'), required=True)
    parser.add_argument('--reviewer', required=True, help='Operator identifier; not an authentication identity')
    parser.add_argument('--note', default='')
    parser.add_argument('--i-reviewed-evidence', action='store_true', required=True,
                        help='Explicitly confirm you inspected the session evidence')
    args = parser.parse_args(argv)
    try:
        result = review_session(args.db, args.session_id, args.decision, args.reviewer,
                                args.note, args.i_reviewed_evidence)
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError) as exc:
        print(f'Review refused: {exc}', file=sys.stderr)
        return 2

if __name__ == '__main__':
    raise SystemExit(main())
