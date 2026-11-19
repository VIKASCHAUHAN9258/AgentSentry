"""
Live demo for the presentation (Member 1).

Trains a per-agent detector on SYNTHETIC benign sessions, then scores the
scenarios in lab/scenarios. Nothing is written to disk (no model files, no DB).

    python scripts/demo_risk_assessment.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.detector import BehaviorAnomalyDetector
from core.features import extract_session_features
from core.policy import get_policy
from core.risk_engine import assess_session
from lab.scenario_loader import load_scenarios, steps_to_rows
from lab.synthetic import benign_sessions


def main() -> None:
    tmp = Path(tempfile.mkdtemp())
    detectors = {}
    for s in load_scenarios():
        agent = s["agent_id"]
        if agent not in detectors:
            det = BehaviorAnomalyDetector(agent_id=agent, model_dir=tmp)
            det.fit([extract_session_features(f"train-{i}", r).to_vector()
                     for i, r in enumerate(benign_sessions(agent, 40))])
            detectors[agent] = det

    print("NOTE: baselines trained on synthetic benign sessions (demo only).\n")
    for s in load_scenarios():
        rows = steps_to_rows(s, seed=7)
        feats = extract_session_features(s["id"], rows)
        a = assess_session(s["id"], feats, detectors[s["agent_id"]], get_policy(s["agent_id"]))
        print(f"=== {s['id']}  [{s['type'].upper()}]  agent={s['agent_id']}")
        print(f"    risk: {a.risk_level} ({a.final_risk_score:.1f})   ml={a.ml_risk_score:.1f}   "
              f"policy_violations={len(a.policy_violations)}")
        for line in a.why_flagged(top_n=3):
            print("    -", line)
        print()


if __name__ == "__main__":
    main()
