# Member 2 — Phases 5-8: Attack Chains, Attack Lab, API + Dashboard, Testing

Base (Phases 1-4) is already working: `pytest tests/ -q` should show **38 passed** before you touch anything,
plus xfailed/skipped tests that are YOUR to-do list. Read `TEAM_PLAN.md` first (ownership, git workflow, safety rules).

```powershell
python -m venv venv ; venv\Scripts\activate
pip install -r requirements.txt -r requirements-member2.txt
pytest tests/ -q
python scripts/demo_risk_assessment.py     # see what the engine does today (and what it misses: scenario A3)
```

Read first (30 min): `core/features.py`, `core/policy.py`, `core/risk_engine.py`, `lab/scenario_schema.md`.

---

## Phase 5 — Attack-chain correlation  (`core/chain_detector.py`) — IMPLEMENTED

**Goal:** flag a *sequence* of individually-allowed calls. Scenario A3 is the proof: policy says nothing, ML says MEDIUM.

Implemented: `is_sensitive_path()`, data-driven `ChainDefinition` matching, `sensitive_read_to_network`, `read_to_execute`, backward-compatible risk-engine integration, and the `research-assistant` NETWORK policy. Active tests cover all A1/A2/A3 chains, B1 benign behavior, 20 benign-prefix seeds, bounded gaps, and risk escalation.

Tasks (completed)
1. Implement `is_sensitive_path()` (unit-tested; decide patterns, document false-positive risk).
2. Implement chains as data (`ChainDefinition`) + one small engine: `sensitive_read_to_network`, `read_to_execute`.
3. Integrate in `core/risk_engine.py` **backward-compatibly**: add `attack_chains: list = field(default_factory=list)` to `RiskAssessment`; add optional `rows=None` to `assess_session()`. If a CRITICAL chain: final score >= 90 and level CRITICAL; HIGH chain: >= 70 and level at least HIGH. Add `ATTACK CHAIN: ...` lines to `why_flagged()`.
4. Register a policy for `research-assistant` in `core/policy.py` (ceiling NETWORK, no denied tools) — coordinate with Member 1 (his file). Scenario A3 depends on it being network-allowed.
5. Remove the `xfail` marks in `tests/test_chain_detector.py` as each test starts passing.

Acceptance: A1/A2/A3 each report their `expect_chain`; B1 reports none; attack-with-benign-prefix test passes for 20 seeds; original 36 tests untouched and green; MITRE ATT&CK technique IDs in `mitre_hint` looked up on attack.mitre.org (no guessing).
Learn: dataclasses, sliding-window sequence matching, MITRE ATT&CK basics. Difficulty: medium.

## Phase 6 — Attack lab (`mcp_lab/vulnerable_server.py`, `scripts/run_scenario.py`, `lab/docker*`) — IMPLEMENTED (simulation scope)

**Goal:** execute five repeatable MCP scenarios through the real AgentSentry stdio proxy against an intentionally vulnerable *simulated* MCP server.

Implemented:
- A1 indirect prompt injection: visible untrusted instruction in `lab_files/notes.txt`, fake credentials in `lab_files/.env`, sensitive-read-to-network chain.
- A2 privilege escalation: `shell_execute` and `sudo_command` are canned simulated tools; no shell is invoked.
- A3 exfiltration chain: `.env` read, local encoding, and a simulated outbound request written to `lab_files/outbox.log`; no socket is opened.
- A4 rug-pull event: runner records an explicit tool-definition-change marker through the real proxy telemetry path after the configured mutation step. The current lab models the event and detection contract; it does **not** yet implement a genuine MCP `notifications/tools/list_changed` exchange or mutate the server's advertised tool schema. That remains a known limitation requiring proxy/server notification support.
- B1 benign code review: normal read/search/report sequence.
- `scripts/run_scenario.py` runs selected scenarios or `--all`, routes calls through `core.proxy`, reads persisted telemetry, trains an ephemeral per-run benign baseline, evaluates policy + chain detection, and compares results with scenario expectations.
- Docker image runs as a non-root user; Compose disables networking, drops Linux capabilities, enables no-new-privileges, limits memory/PIDs, and uses a read-only root filesystem.

Safety boundary: the lab never connects to the internet, executes operating-system commands, or deletes real files. `delete_file` is simulation-only. Docker is an additional isolation layer, not a substitute for running only trusted code.

Run:
```powershell
python scripts/run_scenario.py --all
python -m pytest tests/test_phase6_lab.py tests/test_scenarios_schema.py -q
docker compose -f lab/docker-compose.yml build
```

## Phase 7 — API + dashboard  (`api/app.py`, `dashboard/`)

**Goal:** an analyst opens a flagged session and understands in 10 seconds what happened and why.

Tasks
1. Implement the endpoints exactly as specified in `api/app.py` docstring (shapes are a contract with Member 3).
2. Dashboard pages per `dashboard/README.md`. The **session replay** view (timeline + highlighted calls + WHY FLAGGED + chain steps) is the feature that sells the project — spend the time there.
3. Security requirements in the `api/app.py` docstring are mandatory (escape untrusted tool arguments, CSP + headers, localhost bind, no stack traces). Member 3 will attack it.
4. Set `IMPLEMENTED = True` only when the API starts and `/api/health` works.
5. API tests (Flask test client): normal, missing session, malformed ids, large payload, special characters in tool arguments.

Acceptance: demo flow works end-to-end on scenario data; API tests pass; Member 3's XSS test (`tests/security/test_dashboard_xss.py`) runs (not skipped) and you've fixed whatever it finds.
Learn: Flask (you may already know it), Jinja autoescaping, basic security headers. Difficulty: medium.

## Phase 8 — Testing  (`tests/test_false_positives.py`, `test_evasion.py`, `test_throughput.py`)

**Goal:** honest numbers, including bad ones.

Tasks: false-positive rate on >=100 new benign sessions (expect a bad result until Member 1's Phase 4.1 — Known Issue #1); evasion variants of A3 (many benign calls, slow timing, tiny payload, unregistered tool name) — record detected/missed; proxy overhead + scoring latency with hardware/Python version noted.

Acceptance: each file has real tests/measurements; misses and bad numbers are written in README "Limitations" (they are results, not failures); no threshold tuned just to hide a number.
Learn: precision/recall/FPR definitions, timing with `time.perf_counter`, pytest parametrization. Difficulty: medium.

---

## Handoffs

- To Member 3: scenario JSONs (keep schema stable), `api.app.IMPLEMENTED`, chain detector API (`detect_chains`) so the benchmark gets a "hybrid + chains" column.
- From Member 1: telemetry/features/detector questions; PR review.
- Ask early: tool-list-hash logging in the proxy (Phase 6), `research-assistant` policy (Phase 5).
