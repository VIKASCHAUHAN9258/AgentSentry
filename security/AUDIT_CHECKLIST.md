# Phase 9 — Security audit checklist (AgentSentry itself)

Rule: authorized testing only — this repo, local lab, test accounts. Cycle for every finding:
**reproduce -> confirm -> root cause -> fix (owner) -> retest -> regression test.** Never mark "safe" without a test.

Status key: [ ] not done  [x] done, no issue  [!] finding (link report)  [~] partial / NOT TESTED (say why)

## A. Core (Phases 1-4) — can start now
- [x] SQL injection via agent_id / tool_name / arguments / result (`tests/security/test_telemetry_injection.py`) — passes, parameterised queries
- [x] Oversized payloads truncated; truncated-JSON does not crash features (`test_oversized_payloads.py`)
- [ ] Path traversal / symlink escape in `mcp_lab/file_tools_server.py` (relative, absolute, URL-encoded, symlink inside lab_files)
- [ ] Proxy: malformed JSON-RPC, missing params, huge messages, downstream server crash mid-call
- [ ] Proxy: `AGENTSENTRY_DB_PATH` env var — what if it points somewhere unexpected?
- [ ] Model files (`models/*.joblib`): joblib/pickle loads arbitrary code — who can write that directory? Document the risk, restrict permissions
- [ ] Feature evasion: unregistered tool names default to NETWORK (intended) — try to abuse (e.g. tool named `read_file ` with trailing space, unicode lookalikes)
- [ ] Secrets: grep repo + git history for keys/tokens; `.env` only has fake values
- [ ] Dependencies: `pip list --outdated`, `pip-audit` (install it, read its README)

## B. Lab + chains (Phases 5-6, after Member 2 merges)
- [ ] Lab tools truly simulated: no real network, no real command execution, no real file deletion
- [ ] Docker: `network_mode: none`, non-root user, no host mounts except lab files
- [ ] Chain detector: ReDoS / pathological input (very long path strings, 10k-call sessions)

## C. API + dashboard (Phase 7, after `api.app.IMPLEMENTED = True`)
- [ ] Stored XSS via tool arguments / result summary (`tests/security/test_dashboard_xss.py`)
- [ ] Security headers (CSP, nosniff, frame-options); CORS not `*`
- [ ] Input validation: session_id, limit, agent_id; error bodies leak no stack trace / path
- [ ] AuthN/AuthZ: is there any? If read-only localhost-only, document the assumption explicitly
- [ ] Rate limiting / large-response DoS (limit param)
- [ ] Debug mode off by default; binds 127.0.0.1

## D. Detection-logic abuse (feeds Phase 8/10)
- [ ] Low-and-slow evasion (see Member 2's `test_evasion.py` results)
- [ ] Baseline poisoning: attacker behaves "normally" during training window so malicious behaviour becomes the baseline — document, propose mitigation (policy layer is the mitigation: it does not learn)
- [ ] Alert flooding: can an attacker create thousands of sessions to hide a real one?
