# AgentSentry — Testing (DRAFT, Member 3 maintains)

Run: `pytest tests/ -q` (pytest.ini + conftest.py put the project root on sys.path).

| Area | Files | What it proves |
|---|---|---|
| Phase 1 | `tests/test_mcp_connection.py` | MCP plumbing works; path traversal blocked |
| Phase 2 | `tests/test_proxy.py` | Proxy is transparent; every call logged, no drops; errors logged; session end recorded |
| Phase 3 | `tests/test_features.py` | Entropy, escalation distance (max jump), bigrams, unknown-tool default |
| Phase 4 | `tests/test_detector.py`, `test_policy.py`, `test_risk_engine.py` | Per-agent model, policy rules, policy-overrides-ML |
| Contract | `tests/test_scenarios_schema.py` | Scenario JSONs agree with the real policy engine |
| Security | `tests/security/` | Hostile strings, oversized payloads; dashboard XSS (skipped until API exists) |
| Benchmark | `benchmark/run_benchmark.py` | Precision/recall/F1/FPR on synthetic labelled data (not a pytest test) |

## Bugs found while building (honest list)
| Phase | Bug | How found | Fix |
|---|---|---|---|
| 2 | Test DB path monkeypatch never reached the proxy subprocess | Running tests | Env var `AGENTSENTRY_DB_PATH` |
| 3 | Entropy test blob had lower entropy than plain text | Running the test | base64 of random bytes |
| 4 | z-scores exploded on zero-variance features | Running on real telemetry | Clip to +/-50 |
| team pkg | ML score calibration weak (Known Issue #1) | Measuring 200 held-out benign sessions + benchmark | Phase 4.1 (Member 1), open |

## NOT TESTED yet
Docker lab, real LLM-driven agents, concurrent sessions, large-scale throughput, evasion (Member 2 Phase 8).

## Phase 10.4 — baseline model lifecycle

The detector persists a versioned JSON metadata sidecar alongside each Joblib
model. Tests cover lifecycle state, schema/integrity rejection, finite training
inputs, path-safe agent identifiers, and save/load score parity. Run:

```powershell
python -m pytest tests/test_detector.py tests/test_session_assessment.py -q
```
