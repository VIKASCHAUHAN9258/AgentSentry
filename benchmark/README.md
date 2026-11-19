# Benchmark (Phase 10, Member 3)

```
python benchmark/run_benchmark.py       # writes benchmark/results/latest.md + latest.json
```

Works today on synthetic data (shared with Member 2 via `lab/synthetic.py` and `lab/scenarios/`).
The `hybrid+chains` column appears automatically once `core/chain_detector.py` is implemented.

First run (Phase 1-4 code, 120 benign + 120 attack synthetic sessions): hybrid precision 0.71, recall 0.66, FPR 0.28;
A3 caught 7/30, A4 12/30. Re-run after Phase 4.1 (calibration) and Phase 5 (chains) — before/after is the story.

TODO for the final version
1. Real lab replays (Member 2's `run_scenario.py`) as a second dataset, reported separately from synthetic.
2. Static-scanner baseline: install Cisco `mcp-scanner` or Snyk `agent-scan` (open source), read their README, run on the lab server config. Compare honestly — static scanners answer a different question; show where each one wins.
3. Throughput / resource numbers: coordinate with Member 2's `test_throughput.py`; don't measure twice.
4. Always print dataset sizes and "synthetic" next to numbers.
