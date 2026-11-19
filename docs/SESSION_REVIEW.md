# Human session review and baseline eligibility

AgentSentry never infers that a session is benign from successful tool calls. Baseline training requires an explicit review record for every supplied session.

## Review a session

1. Open the session in the dashboard and inspect its complete tool-call arguments, result summaries, tool-definition events, risk assessment, policy findings, and attack-chain findings.
2. Enter an operator identifier and a short reason in **Human session review**.
3. Confirm that the evidence was inspected, then choose **Approve as benign** or **Reject session**.
4. The review is stored in `session_reviews`; every decision/re-decision is appended to `session_review_events`.

The reviewer string is an operator-entered audit label, not an authenticated identity. The review API only accepts loopback requests; keep the Flask API bound to `127.0.0.1` and do not expose it directly to an untrusted network.

CLI alternative:

```powershell
python scripts\review_session.py `
  --db agentsentry.db `
  --session-id YOUR_SESSION_ID `
  --decision approved `
  --reviewer operator-1 `
  --note "Inspected calls, arguments, results and findings" `
  --i-reviewed-evidence
```

Use `--decision rejected` to reject a session. A later re-review is allowed and is retained in the append-only review event history.

## Training gate

`scripts/train_baseline.py` accepts only explicitly supplied, completed sessions belonging to the same agent and having an `approved` review. The review contains a SHA-256 fingerprint of the session, tool calls and tool-definition events. If any recorded evidence changes after review, training refuses the session until it is reviewed again.

Training additionally refuses sessions containing tool-definition-change events, deterministic policy violations, or attack-chain findings. It still requires at least 10 distinct approved sessions for the same agent and the explicit `--i-confirm-benign` operator confirmation. Run `--dry-run` first. The SHA-256 value detects changes; it is not a digital signature and does not authenticate the reviewer.

```powershell
python scripts\train_baseline.py `
  --agent-id demo-code-reviewer `
  --db agentsentry.db `
  --model-dir models `
  --session-id SESSION_ID_1 `
  --session-id SESSION_ID_2 `
  --i-confirm-benign `
  --dry-run
```

Do not use attack-lab, prompt-injection, privilege-escalation, exfiltration, MCP rug-pull, or otherwise suspicious sessions as benign baseline data. Human approval is a deliberate operator assertion; it is not a substitute for reviewing the evidence.
