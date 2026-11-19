# AgentSentry — Architecture (DRAFT, Member 3 maintains)

Status: Phases 1-4 documented from the actual code. Add sections for chains, lab, API/dashboard as they merge.

## Purpose
Runtime behavioral security monitor for AI agent tool-call sessions over MCP. Existing MCP security tools
(Snyk Agent Scan, Cisco MCP Scanner, mcp-audit) scan tool definitions before deployment; AgentSentry watches what
an agent actually does during a live session.

## Data flow
```
AI agent --MCP--> core/proxy.py (transparent) --MCP--> real MCP server(s)
                      |
                      v  (logged BEFORE the result is returned)
              core/telemetry.py  -> SQLite: sessions, tool_calls
                      |
                      v
              core/features.py   -> numeric feature vector per session
                      |
          +-----------+-----------+
          v                       v
   core/detector.py         core/policy.py
   Isolation Forest         privilege ceiling + denied tools
   (per-agent baseline)     (deterministic)
          \                       /
           +-----> core/risk_engine.py <-----+
                  policy violation => CRITICAL (>=95), else ML level
                  output: RiskAssessment + why_flagged()
```

## Modules (Phases 1-4)
| Module | Responsibility |
|---|---|
| `mcp_lab/file_tools_server.py` | Lab MCP server (`read_file`, `search_code`, `report`), confined to `lab_files/` |
| `core/proxy.py` | Transparent MCP proxy built on low-level Server hooks; forwards any tool set |
| `core/telemetry.py` | SQLite store; truncates arguments (4000 chars) and results (2000 chars) |
| `core/privilege.py` | Tool -> level (READ 1, TRANSFORM 2, NETWORK 3, EXECUTE 4); unknown tools default to NETWORK |
| `core/features.py` | Bigrams, escalation distance, Shannon entropy of argument values, timing, error rate |
| `core/detector.py` | Per-agent Isolation Forest, >=10 benign sessions; z-score "why flagged" (heuristic, not SHAP) |
| `core/policy.py` | Per-agent privilege ceiling + denied tools; conservative default for unknown agents |
| `core/risk_engine.py` | Combines ML + policy; thresholds LOW <25, MEDIUM <50, HIGH <75, CRITICAL >=75 |

## Key design decisions
1. Log before return — no monitoring blind spot if a call crashes.
2. Hybrid, not pure ML — policy is not overridable by a model score.
3. Unknown tool => elevated privilege — evasion by unregistered tool name is harder.
4. Per-agent baselines — "normal" differs per agent.

## TODO (Member 3, as phases merge)
- Phase 5 chain detector section + diagram update
- Phase 6 lab topology (Docker)
- Phase 7 API endpoints + dashboard pages
