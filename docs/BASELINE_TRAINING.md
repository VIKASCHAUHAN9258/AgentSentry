# AgentSentry baseline training (Phase 10.4)

The baseline is agent-specific and must be trained only from completed sessions that an operator has reviewed and classified as benign. The current telemetry schema does not contain a trusted benign/attack label, so the command deliberately does not infer labels or automatically select sessions.

## 1. Review candidate sessions

Inspect sessions and their tool-call evidence through the existing read-only API/dashboard or a read-only SQLite viewer. Select at least 10 completed sessions belonging to the same agent. Exclude attack simulations, suspicious sessions, incomplete sessions, and sessions whose behavior is not understood. Do not use production data unless the operator has separately approved that use.

## 2. Dry run

From the project root with the project virtual environment active:

```powershell
python scripts/train_baseline.py --agent-id gemini-agent --db agentsentry.db --model-dir models --session-id SESSION_ID_1 --session-id SESSION_ID_2 --i-confirm-benign --dry-run
```

Repeat `--session-id` for each reviewed session. At least 10 are required.

## 3. Train and persist

After the dry run succeeds, repeat the command without `--dry-run`:

```powershell
python scripts/train_baseline.py --agent-id gemini-agent --db agentsentry.db --model-dir models --session-id SESSION_ID_1 --session-id SESSION_ID_2 --i-confirm-benign
```

The command writes the model and metadata using the detector's atomic persistence routine, then prints lifecycle status. Keep the model directory writable only by the trusted AgentSentry service account. Joblib/pickle model loading is unsafe for untrusted files; the SHA-256 metadata detects corruption, not a malicious replacement of both files.

## Guardrails and limitations

- Explicit session IDs are mandatory; no automatic session selection occurs.
- All selected sessions must exist, be completed, have tool-call telemetry, and belong to the requested agent.
- Duplicate IDs and fewer than 10 sessions are rejected.
- `--i-confirm-benign` is an operator attestation, not an automatic truth label. The command cannot independently prove a session is benign.
- `--dry-run` validates and summarizes but does not create model files.
- Training writes only to the supplied model directory; the telemetry database is opened for reads only.
- This workflow does not yet implement scheduled retraining, model staleness policy, dashboard controls, or approval workflow. Those remain follow-up work.
