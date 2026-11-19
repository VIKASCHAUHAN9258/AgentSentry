# Configurable benign demo-agent update

The demo agent now accepts `--file`, `--query`, `--agent-id`, and `--db-path`.

Run a monitored benign lab session from the project root:

```powershell
python agent/demo_agent.py --proxy --agent-id demo-code-reviewer --file benign_review.txt --query "input validation"
```

This sends MCP calls through `core.proxy` and records telemetry in the configured AgentSentry database. It does not label the session benign. Review the session evidence and explicitly approve it under your own baseline-training process. Do not use `notes.txt` for benign baseline collection because it contains an A1 prompt-injection simulation.
