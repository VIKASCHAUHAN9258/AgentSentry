# Member 1 — Phases 1-4 (Core Engine) — COMPLETE

Everything here is built and tested: **36 / 36 tests passing** (`pytest tests/ -q`).

## What you own

| Phase | What | Key files |
|---|---|---|
| 1 Foundation | Lab MCP server (`read_file`, `search_code`, `report`) with path-traversal protection; scripted agent | `mcp_lab/file_tools_server.py`, `agent/demo_agent.py` |
| 2 Interception proxy | Transparent MCP proxy; every call logged to SQLite *before* the result is returned | `core/proxy.py`, `core/telemetry.py` |
| 3 Feature engineering | Privilege registry; session features (bigrams, entropy, escalation distance, timing) | `core/privilege.py`, `core/features.py` |
| 4 Hybrid detection | Per-agent Isolation Forest + deterministic policy; policy violation forces CRITICAL | `core/detector.py`, `core/policy.py`, `core/risk_engine.py` |

## Your job now (integrator + reviewer)

1. Create the GitHub repo, push this zip's contents to `main` (first commit).
2. Protect `main`: PR + your review required.
3. Review Member 2 / Member 3 PRs: run `pytest tests/ -q`, check they only touched files they own (see `TEAM_PLAN.md` section 4).
4. Answer interface questions about telemetry / features / detector (you are the only one who knows them in depth).
5. Own the final presentation story and live demo.

## Run it

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
pytest tests/ -q                           # expect 38 passed (36 core + 2 scenario contract tests)
python agent/demo_agent.py --proxy         # monitored session, logs to agentsentry.db
python scripts/demo_risk_assessment.py     # benign vs attack scoring, with "why flagged"
```

## Demo script (5 minutes)

1. Show architecture figure (`docs/AgentSentry_Project_Report.docx`, Figure 1).
2. Run `python agent/demo_agent.py --proxy` — agent sees normal results; point at what got logged.
3. Run `python scripts/demo_risk_assessment.py`. Expected (checked): A1/A2 = CRITICAL via policy; A3 (exfil chain by an agent that IS allowed network) = only MEDIUM, no policy violation — **this is the gap Phase 5 closes, say it out loud**; B1 benign = MEDIUM (~48) — **this is Known Issue #1 below, do not hide it**.
4. Show the bug table (report page 15): real bugs found by actually running tests.

## KNOWN ISSUE #1 — ML score calibration (your Phase 4.1 task)

Found while building the team package, measured, NOT yet fixed:

- On 200 held-out *synthetic benign* sessions per agent, ML risk score >= 50 for ~33% of sessions
  (demo-code-reviewer 66/200, research-assistant 67/200); median 31-40; p90 ~80-85.
- Cause (from reading `core/detector.py`): risk = 100 * (train_max - raw) / span, with min/max taken
  from the 1st/99th percentile of the **training** scores. Held-out normal data scores worse than
  data the forest was fit on, so normal sessions spread across the whole 0-100 range.
- The report's claim "held-out real benign session scored LOW" is true but anecdotal (1 session). Do not
  quote it as a false-positive rate.
- Fix idea (verify, don't assume): split benign data into train / calibration; set the score scale or
  threshold from the calibration set's score distribution (e.g. 99th percentile of benign = ~50 risk);
  re-measure with `benchmark/run_benchmark.py` (Member 3 owns it) before/after.
- Acceptance: documented before/after FPR on the synthetic benchmark; all existing tests still pass.

## Known limitations (be upfront about these in Q&A)

- Baselines are built from each agent's own traffic (min 10 sessions); there is no public dataset of agent-hijack sessions.
- Feature "why flagged" = z-scores (heuristic), not SHAP.
- `is_error` alone misses failures the lab server reports as plain text.
- Evasion (low-and-slow attacks mimicking normal behaviour) not tested yet — Phase 8.
- Detection quality on real agents is untested; all attack data so far is simulated.
