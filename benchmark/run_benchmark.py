"""
Phase 10 benchmark harness (Member 3).

    python benchmark/run_benchmark.py

Compares detection methods on a LABELLED SYNTHETIC dataset:
  policy_only    deterministic rules only
  ml_only        Isolation Forest score >= 50
  hybrid         core.risk_engine level HIGH/CRITICAL   (the shipped design)
  hybrid+chains  hybrid OR chain detector fired          (n/a until Member 2's Phase 5 is merged)

Data: per agent, 40 benign training sessions (seeds 0-39), 60 held-out benign sessions (seeds 10000+),
and 30 variants of every attack scenario for that agent (random timing, 0-2 benign calls in front).

READ THIS BEFORE QUOTING NUMBERS
- Everything is synthetic. Benign and attack data come from the same author's assumptions, so this
  measures "does the machinery work and where does it break", NOT real-world accuracy.
- Always print the dataset sizes next to any number you show.
- Phase 10 final version should add: real lab replays (Member 2's run_scenario.py) and a static-scanner
  baseline (Cisco mcp-scanner / Snyk agent-scan: read their README, do not assume CLI flags).
"""

from __future__ import annotations

import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.detector import BehaviorAnomalyDetector
from core.features import extract_session_features
from core.policy import get_policy
from core.risk_engine import assess_session
from lab.scenario_loader import load_scenarios, steps_to_rows
from lab.synthetic import benign_sessions

TRAIN_N, TEST_BENIGN_N, ATTACK_VARIANTS = 40, 60, 30
POSITIVE_LEVELS = {"HIGH", "CRITICAL"}
RESULT_DIR = Path(__file__).parent / "results"


def _chains_available():
    try:
        from core.chain_detector import detect_chains
        detect_chains([{"tool_name": "read_file", "arguments_json": "{}", "called_at": 0.0,
                        "sequence_num": 1, "is_error": 0, "duration_ms": 1.0}])
        return detect_chains
    except Exception:  # stub raises NotImplementedError; missing module raises ImportError
        return None


def _metrics(tp, fp, tn, fn):
    div = lambda a, b: (a / b) if b else None
    precision, recall = div(tp, tp + fp), div(tp, tp + fn)
    f1 = div(2 * precision * recall, precision + recall) if precision and recall else None
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn, "precision": precision,
            "recall": recall, "f1": f1, "fpr": div(fp, fp + tn)}


def _fmt(x):
    return "n/a" if x is None else f"{x:.2f}"


def main() -> None:
    scenarios = [s for s in load_scenarios()]
    attacks = [s for s in scenarios if s["type"] == "attack"]
    detect_chains = _chains_available()
    model_dir = Path(tempfile.mkdtemp())

    samples = []  # (label, scenario_id, agent, rows)
    detectors = {}
    for agent in sorted({s["agent_id"] for s in scenarios}):
        det = BehaviorAnomalyDetector(agent_id=agent, model_dir=model_dir)
        det.fit([extract_session_features(f"train-{i}", r).to_vector()
                 for i, r in enumerate(benign_sessions(agent, TRAIN_N, 0))])
        detectors[agent] = det
        for i, rows in enumerate(benign_sessions(agent, TEST_BENIGN_N, 10_000)):
            samples.append((0, f"benign-{agent}", agent, rows))
    for s in attacks:
        for seed in range(ATTACK_VARIANTS):
            samples.append((1, s["id"], s["agent_id"], steps_to_rows(s, seed=seed, benign_prefix=True)))

    methods = ["policy_only", "ml_only", "hybrid"] + (["hybrid+chains"] if detect_chains else [])
    counts = {m: [0, 0, 0, 0] for m in methods}   # tp, fp, tn, fn
    per_scenario = {}
    latencies = []

    for label, sid, agent, rows in samples:
        t0 = time.perf_counter()
        feats = extract_session_features(sid, rows)
        a = assess_session(sid, feats, detectors[agent], get_policy(agent))
        latencies.append((time.perf_counter() - t0) * 1000)

        preds = {
            "policy_only": bool(a.policy_violations),
            "ml_only": a.ml_risk_score >= 50,
            "hybrid": a.risk_level in POSITIVE_LEVELS,
        }
        if detect_chains:
            preds["hybrid+chains"] = preds["hybrid"] or bool(detect_chains(rows))
        for m, p in preds.items():
            idx = {(1, True): 0, (0, True): 1, (0, False): 2, (1, False): 3}[(label, p)]
            counts[m][idx] += 1
        if label == 1:
            per_scenario.setdefault(sid, {m: 0 for m in methods})
            for m, p in preds.items():
                per_scenario[sid][m] += int(p)

    n_pos = sum(1 for s in samples if s[0] == 1)
    n_neg = len(samples) - n_pos
    results = {m: _metrics(*counts[m]) for m in methods}

    lines = [
        "# Benchmark results — SYNTHETIC DATA, not real-world accuracy",
        f"Dataset: {n_neg} benign test sessions, {n_pos} attack sessions "
        f"({len(attacks)} scenarios x {ATTACK_VARIANTS} variants); training: {TRAIN_N} benign sessions per agent.",
        f"Chain detector: {'included' if detect_chains else 'n/a (Phase 5 not merged yet)'}",
        "",
        "| Method | Precision | Recall | F1 | FPR | TP | FP | TN | FN |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for m in methods:
        r = results[m]
        lines.append(f"| {m} | {_fmt(r['precision'])} | {_fmt(r['recall'])} | {_fmt(r['f1'])} | {_fmt(r['fpr'])} "
                     f"| {r['tp']} | {r['fp']} | {r['tn']} | {r['fn']} |")
    lines += ["", f"Scoring latency per session (features + assessment): median {statistics.median(latencies):.2f} ms, "
                  f"max {max(latencies):.2f} ms (this machine, includes sklearn predict).", "",
              "## Detection rate per attack scenario (fraction of variants flagged)", "",
              "| Scenario | " + " | ".join(methods) + " |", "|---|" + "---|" * len(methods)]
    for sid, d in sorted(per_scenario.items()):
        lines.append(f"| {sid} | " + " | ".join(f"{d[m]}/{ATTACK_VARIANTS}" for m in methods) + " |")

    text = "\n".join(lines)
    print(text)
    RESULT_DIR.mkdir(exist_ok=True)
    (RESULT_DIR / "latest.md").write_text(text + "\n", encoding="utf-8")
    (RESULT_DIR / "latest.json").write_text(json.dumps(
        {"results": results, "per_scenario": per_scenario, "n_benign_test": n_neg, "n_attack": n_pos}, indent=2),
        encoding="utf-8")


if __name__ == "__main__":
    main()
