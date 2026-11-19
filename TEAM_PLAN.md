# AgentSentry — Team Plan (3 members, 12 phases)

AgentSentry = runtime behavioral security monitor for AI agent (MCP) tool-call sessions.
Phases 1-4 are DONE and tested (36/36). This plan splits the 12 phases 4-4-4.

## 1. Who owns what

| Member | Phases | Theme | Status |
|---|---|---|---|
| **Member 1** | 1, 2, 3, 4 | Core engine: MCP lab, proxy + telemetry, features, hybrid detection | DONE (36 tests passing). Now also integrator + reviewer |
| **Member 2** | 5, 6, 7, 8 | Attack-chain detection, attack lab, API + dashboard, testing | TO DO |
| **Member 3** | 9, 10, 11, 12 | Security audit, benchmarking, documentation, final validation | TO DO (starts in parallel — see section 2) |

## 2. Dependency problem (read this, Member 3)

Phases 9-12 *audit, measure, document and validate* things that Phases 5-8 create. If Member 3
waits for Member 2 to finish, they sit idle. So Member 3's zip is built to work NOW:

| Member 3 task | Can start immediately on... | Plugs into Member 2's work later |
|---|---|---|
| Phase 9 audit | Phase 1-4 code (SQL injection, oversized payloads, path traversal) | API/dashboard XSS + authz tests (skipped until `api.app.IMPLEMENTED = True`) |
| Phase 10 benchmark | `lab/scenarios` + synthetic benign sessions | Real chain-detector column + real lab replay |
| Phase 11 docs | Drafts already filled with Phase 1-4 facts | Add sections for 5-8 as they land |
| Phase 12 validation | `scripts/final_validation.*` against the current repo | Re-run after every merge |

## 2b. Known Issue #1 (found while preparing this package)

ML risk score is poorly calibrated: ~33% of held-out *synthetic benign* sessions score >= 50
(details + fix idea in MEMBER_1 file, "Phase 4.1"). Consequences for the team:
- Member 1: fixes it (Phase 4.1) — owner of `core/detector.py`.
- Member 2: Phase 8 false-positive tests must measure it; do not tune thresholds inside tests to hide it.
- Member 3: benchmark reports it honestly (FPR column); never present synthetic numbers as real-world accuracy.

## 3. Shared contracts (change only after telling everyone)

1. **Scenario JSON** — `lab/scenario_schema.md`, loader `lab/scenario_loader.py`. Owner: Member 2. Used by Member 3's benchmark.
2. **RiskAssessment** (`core/risk_engine.py`) — Member 2 adds an `attack_chains` field and an optional `rows` argument to `assess_session()`. Must stay backward compatible: the existing 36 tests must keep passing.
3. **API JSON shapes** — defined in MEMBER_2 file, section Phase 7. Member 3 audits against them.
4. **Telemetry schema** (`core/telemetry.py`) — Owner: Member 1. If someone needs a new column, ask Member 1.

## 4. File ownership (only the owner edits; others open a PR / ask)

| Path | Owner |
|---|---|
| `core/telemetry.py`, `core/features.py`, `core/privilege.py`, `core/detector.py`, `core/policy.py`, `core/proxy.py`, `mcp_lab/file_tools_server.py`, `agent/` | Member 1 |
| `core/chain_detector.py`, `core/risk_engine.py` (chain integration only), `lab/`, `api/`, `dashboard/`, `scripts/run_scenario.py`, Phase 8 tests | Member 2 |
| `security/`, `tests/security/`, `benchmark/`, `docs/ARCHITECTURE.md SECURITY.md THREAT_MODEL.md TESTING.md`, `scripts/final_validation.*` | Member 3 |
| `README.md`, `requirements.txt` | Shared — small edits only, always via PR, Member 1 merges |

Security findings that need a code change in someone else's file: Member 3 writes it up using
`security/VULN_REPORT_TEMPLATE.md`, the file's owner fixes it, Member 3 re-tests.

## 5. Git workflow

1. Member 1 creates the GitHub repo and pushes the current base to `main` (first commit = contents of Member 1's zip).
2. Members 2 and 3 clone it, then **copy only their own files** from their zip into the repo (their zip also contains the base so they can run things standalone — do not commit duplicate base files over `main`).
3. Branches: `member2/phase-5-chains`, `member2/phase-6-lab`, ... `member3/phase-9-audit`, ...
4. Before every PR: `pytest tests/ -q` must pass. PR description = phase, what changed, what you tested, what you did NOT test.
5. Member 1 reviews and merges. Nobody pushes straight to `main`.
6. Commit style: `phase5: add sensitive_read_to_network chain` (phase prefix + imperative).

## 6. Definition of done (per phase)

- Tests written AND actually run; paste the pass count in the PR.
- README section added (what exists / what does not).
- Bugs you hit are written down (what, how found, how fixed) — this table goes into the final report.
- Anything not tested is listed as `NOT TESTED — reason`.
- No fake numbers: synthetic data results are labelled synthetic.

## 7. Safety rules (non-negotiable)

- Lab tools are **simulations**: no real network calls, no real shell commands. `http_request` writes to a local outbox file; `shell_execute` returns canned text.
- Attack scenarios run only against the local lab / Docker network.
- No real secrets in the repo. `.env` files in `lab_files/` contain fake values only.

## 8. Suggested timeline

| Week | Member 1 | Member 2 | Member 3 |
|---|---|---|---|
| 1 | Push base repo, review setup, demo script | Phase 5 (chains) | Phase 9 audit on core + Phase 10 harness |
| 2 | Review PRs | Phase 6 (lab + scenarios replay) | Phase 11 doc drafts |
| 3 | Review PRs, integration | Phase 7 (API + dashboard) | Audit API/dashboard (Phase 9 part 2) |
| 4 | Presentation slides | Phase 8 (testing) | Phase 10 final benchmark, Phase 12 validation |

## 9. Presentation split (suggested)

Member 1: problem, novelty, architecture, live demo of detection. Member 2: attack lab + dashboard demo. Member 3: security audit findings, benchmark, what we would do next.
