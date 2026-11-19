# Model artifact security

AgentSentry persists per-agent Isolation Forest baselines with joblib.
Joblib deserialization uses pickle semantics and can execute code. A checksum,
metadata validation, or file-size/path check does **not** make an untrusted
pickle safe.

## Required handling

- Treat both `.joblib` models and their JSON metadata as executable,
  security-sensitive artifacts.
- Only load models created by a trusted AgentSentry process or obtained through
  another verified trusted channel.
- Keep the configured model directory writable only by the trusted service
  account and readable by the API process. Do not place it in an
  attacker-writable or shared upload directory.
- Restrict changes to `AGENTSENTRY_MODEL_DIR` and its parent directories.
- Do not accept model uploads or load artifacts supplied by monitored agents.
- Back up trusted models before maintenance and protect backups with equivalent
  access controls.

The default model directory is the project-local `models/`; set
`AGENTSENTRY_MODEL_DIR` to use another directory. The loader rejects
symbolic-link paths and Windows junctions (where the Python runtime supports
junction detection), artifacts outside the configured directory, artifacts
over 100 MiB, incompatible metadata, and corrupted payloads. These are
defense-in-depth checks, not a sandbox against malicious serialized objects.
The SHA-256 metadata detects accidental corruption or mismatched files; it is
not a signature because an attacker able to replace both files can recompute
the hash.

For deployments that need to consume models from another trust domain, use a
non-executable model format and a separately reviewed import/verification
pipeline before loading those models.
