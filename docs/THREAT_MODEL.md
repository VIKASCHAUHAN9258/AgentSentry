# AgentSentry — Threat model (DRAFT, Member 3 maintains)

## Assets
- The agent's tools and what they can reach (files, network, shell)
- Secrets reachable by the agent (`.env`, keys)
- Integrity of AgentSentry's own telemetry, baselines and dashboard

## Actors
- Attacker controlling content the agent reads (web page, document, tool output) -> indirect prompt injection
- Malicious or compromised MCP server (tool poisoning, rug pull)
- Insider/attacker training the baseline with malicious "normal" behaviour

## Trust boundaries
1. Agent <-> AgentSentry proxy (agent may be hijacked)
2. Proxy <-> downstream MCP server (server may be malicious)
3. Telemetry -> dashboard (all stored strings are untrusted)

## Scenarios (lab/scenarios/*.json)
| ID | Scenario | Caught by (today) | Source of the pattern |
|---|---|---|---|
| A1 | Indirect prompt injection -> read .env -> outbound request | Policy (agent denied network) | OWASP agentic AI reporting; prompt-injection literature |
| A2 | Privilege escalation read-only -> shell | Policy | Same |
| A3 | Read -> encode -> network by an agent allowed network | Partly ML (7/30 in synthetic benchmark); Phase 5 targets it | Exfiltration chain |
| A4 | MCP rug pull (tool redefined mid-session) | Partly ML (12/30); needs tool-list-hash detection | Documented rug-pull research (Invariant Labs) |

Add MITRE ATT&CK mappings once Member 2 has verified technique IDs on attack.mitre.org (do not guess).

## Out of scope (state it)
Attacks on the host OS, the LLM itself, network-level interception, compromise of the machine running AgentSentry.
