# Scenario file schema (shared contract)

One JSON file per scenario in `lab/scenarios/`. Validated by `lab/scenario_loader.py`
and by `tests/test_scenarios_schema.py`.

```json
{
  "id": "A3-exfil-chain-allowed-network",
  "name": "Human readable name",
  "type": "attack",
  "agent_id": "research-assistant",
  "description": "What happens and why it matters",
  "expected": {
    "min_risk_level": "HIGH",
    "expect_policy_violation": false,
    "expect_chain": "sensitive_read_to_network"
  },
  "steps": [
    {"tool": "read_file", "arguments": {"path": ".env"}, "delay_sec": 0.5}
  ]
}
```

- `type`: `benign` or `attack` (this is the ground-truth label used by the benchmark).
- `expected.min_risk_level`: LOW / MEDIUM / HIGH / CRITICAL — lowest level the system must reach for attacks.
- `expected.expect_policy_violation`: true/false, checked against `core.policy` in tests.
- `expected.expect_chain`: optional `chain_id` Phase 5's chain detector must report.
- `steps[].delay_sec`: optional; random 0.3-2.0s if omitted.
- `lab_config.read_document_rug_pull_after_calls`: optional positive integer; the vulnerable lab server mutates
  `read_document` after that many normal calls and emits the MCP tools/list_changed notification.

SAFETY: scenarios are replayed ONLY against the local lab. `http_request` and `shell_execute`
in the lab server must be simulations (no real network, no real command execution).
