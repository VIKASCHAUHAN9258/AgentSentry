# Member 3 — Phases 9-12: Security Audit, Benchmarking, Documentation, Final Validation

Read `TEAM_PLAN.md` first (section 2 explains why you start NOW and not after Member 2 finishes).

```powershell
python -m venv venv ; venv\Scripts\activate
pip install -r requirements.txt
pytest tests/ -q                       # expect 46 passed, 1 skipped (the skip = dashboard XSS test, waiting for the API)
python benchmark/run_benchmark.py      # first real numbers (synthetic)
```

What is ALREADY done for you in this package (so you can verify, extend, own it): working security tests for the core,
a working benchmark harness, filled-in doc drafts, a tested bash validation script. What is NOT done is listed per phase.

---

## Phase 9 — Security audit of AgentSentry itself

Files: `security/AUDIT_CHECKLIST.md` (your tracker), `security/VULN_REPORT_TEMPLATE.md`, `tests/security/`.

Done: SQL-injection + oversized-payload tests on the telemetry store (pass — no vulnerability found there).
To do now (core): path traversal variants on the lab server (URL-encoded, symlinks), proxy malformed JSON-RPC / downstream crash,
joblib-model-loading risk, secrets scan of repo + git history, `pip-audit`.
To do later (after Member 2): lab simulations are really simulated, Docker hardening, **dashboard stored XSS**, security headers,
input validation, error leakage (`tests/security/test_dashboard_xss.py` has the to-do list; remove its placeholder failure when you write real tests).
Process for every finding: reproduce -> confirm -> report (template) -> owner fixes -> you retest -> regression test.
Acceptance: checklist fully ticked or marked NOT TESTED with a reason; every finding has a report + regression test; no CRITICAL/HIGH open.
Learn: OWASP Top 10 (relevant ones), Flask/Jinja XSS, security headers, pip-audit. Difficulty: medium.

## Phase 10 — Benchmarking

Files: `benchmark/run_benchmark.py`, `benchmark/README.md`, `benchmark/results/` (generated).

Done: harness with policy-only / ML-only / hybrid (and hybrid+chains automatically after Phase 5) on labelled synthetic data.
First run (Phase 1-4): hybrid precision 0.71, recall 0.66, **FPR 0.28**; A3 caught 7/30, A4 12/30 — the baseline "before" numbers.
To do: re-run after Phase 4.1 (Member 1 calibration) and Phase 5 (Member 2 chains) -> before/after table; add real lab replays as a separate dataset;
add a static-scanner baseline (Cisco mcp-scanner or Snyk agent-scan: read their README, don't assume flags) and say honestly where static scanning wins;
ask Member 2 for throughput numbers instead of measuring twice.
Acceptance: results table with dataset sizes + "synthetic" label; before/after for each improvement; no cherry-picked seeds.
Learn: precision/recall/F1/FPR meaning, why synthetic != real, how to read a confusion matrix. Difficulty: medium.

## Phase 11 — Documentation

Files: `docs/ARCHITECTURE.md`, `SECURITY.md`, `THREAT_MODEL.md`, `TESTING.md` (drafts already contain the Phase 1-4 facts, checked against the code).
To do: add sections as 5-8 merge (chain detector, lab topology, API endpoints, dashboard), architecture diagram update (the figure style is in Member 1's report),
MITRE mappings only after Member 2 verifies IDs, final README polish (install, run, limitations, ethical-use statement), keep the bug table in `TESTING.md` current.
Acceptance: a new person can clone, install, run tests and the demo from the README alone; every claim in docs is backed by a test or a benchmark row.
Learn: Mermaid/diagram tools (optional), technical writing. Difficulty: easy-medium.

## Phase 12 — Final validation

Files: `scripts/final_validation.sh` (tested here: passes in a fresh venv), `scripts/final_validation.ps1` (NOT TESTED — no Windows in the build environment; run it once and fix).
To do: run it after every merge into `main`; final run from a fresh `git clone`; if Docker lab exists, test from a clean machine/VM; check `requirements.txt` has every dependency (the script catches missing ones); record results in the final report.
Acceptance: fresh clone -> install -> `pytest` green -> demo runs -> benchmark runs, on a machine that never had the project.
Learn: venv/pip basics, shell/PowerShell scripting. Difficulty: easy.

---

## Handoffs
- From Member 2: scenario JSONs, `api.app.IMPLEMENTED`, `detect_chains`, `run_scenario.py`.
- From Member 1: answers on detector/telemetry; Phase 4.1 calibration fix (re-benchmark when it lands).
- To everyone: audit findings (reports), benchmark before/after tables, validation results.
