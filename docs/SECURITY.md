# AgentSentry security

This document records the current security boundaries and known limitations.
AgentSentry is a local monitoring prototype with bearer-key API access; it is
not a multi-user identity system or a substitute for isolating the monitored
agent.

## Security controls

- The bundled file-tools server resolves paths inside its lab root and rejects
  traversal and symlink escapes.
- Telemetry uses parameterized SQL. Oversized tool arguments retain valid JSON
  truncation markers, malformed historical JSON is represented explicitly, and
  text redaction covers password, secret, token, credential, private-key, and
  API/access-key labels.
- Flask rejects oversized request bodies with a JSON 413 response and sends
  restrictive content/security headers.
- Flask requires a randomly generated bearer key of at least 32 characters
  outside tests, compares it in constant time, and applies an exact-origin
  CORS allowlist. The dashboard key is entered by the operator and held only
  in tab memory. This is not a production identity or authorization system;
  see [`API_AUTHENTICATION.md`](API_AUTHENTICATION.md).
- Deterministic policy violations override the statistical detector. Unknown
  tool names default to NETWORK privilege.
- The MCP proxy starts downstream commands using an executable and argument
  vector, not a shell. Downstream environment forwarding is allow-listed.
- The lab attack scenarios are simulations: the HTTP tool only appends local
  simulation records, shell tools do not start processes, and delete is a
  no-op.

## Dependency findings

### JavaScript: GHSA-fc5q-39xc-vjpf

The dashboard currently uses Vite `8.3.5`, `@vitejs/plugin-react` `6.2.1`,
`tinyglobby` `0.2.17`, `fdir` `6.5.0`, and `picomatch` `4.0.7`. `npm audit`
reports five HIGH findings, all arising from the same transitive
picomatch ReDoS advisory, GHSA-fc5q-39xc-vjpf / CVE-2026-112366 (CVSS 7.5).
The official GitHub advisory marks every picomatch version through `4.0.7`
affected and currently lists no first patched version. The configured registry
is `https://registry.npmjs.org/`; its published versions end at `4.0.7`, and
the direct `picomatch@4.0.8` query returns E404. The reported automatic fix
would downgrade Vite to `6.2.7`, so no forced downgrade or unverified override
was applied.

These are frontend development/build dependencies, not runtime dependencies
shipped by the Flask service. Exposure is primarily in development/build
environments and depends on attacker-controlled patterns reaching picomatch;
this repository has not established a remotely exploitable dashboard path.
Until a compatible fixed dependency is published:

- Do not expose the Vite development server to untrusted networks.
- Build and develop from trusted source trees and limit who can supply files
  processed by tooling.
- Recheck `npm audit` and the advisory before upgrading; do not suppress the
  audit or apply an unverified picomatch override.

### Python

The pinned MCP SDK was updated from `mcp==2.0.0` to `mcp==2.2.0` after
`pip-audit` identified four advisories in the earlier version. The current
requirements audit reports no known Python vulnerabilities. Continue auditing
the installed environment and lock/pin set when dependencies change.

## Application trust boundaries and limitations

- The bearer key is a shared local-operator credential; there are no individual
  identities, roles, or per-resource authorization rules. Bind Flask to
  loopback and do not expose it directly to a network. Review the
  [`API_AUTHENTICATION.md`](API_AUTHENTICATION.md) deployment boundary before
  changing that scope.
- A monitored MCP proxy records tool behavior; it does not sandbox arbitrary
  downstream MCP servers or make their tools safe. Use dedicated OS/container
  isolation for untrusted servers.
- Risk scores and attack-chain rules are heuristics. Baselines learned from an
  agent's own history can be poisoned, and synthetic lab results are not a
  real-agent accuracy claim. Policy rules remain independent of model output.
- No real-agent evaluation has established detection rates or false-positive
  rates for production workloads.
- Baseline models use joblib/pickle deserialization. Only load trusted model
  files from a write-restricted directory. Path, symlink/junction, size,
  metadata, and hash checks do not make a malicious pickle safe; the SHA-256
  sidecar is not a signature. See [`MODEL_SECURITY.md`](MODEL_SECURITY.md).
- Dashboard risk and attack-chain aggregation still computes findings across
  stored sessions, although API processing batches telemetry reads and caches
  models within a request. Large databases may increase API latency.
- The synthetic benchmark corpus contains four attack scenarios and one benign
  scenario. Its perfect scores are descriptive of this small simulation set,
  not estimates of real-world detection accuracy; see
  [`DETECTION_BENCHMARK.md`](DETECTION_BENCHMARK.md).

## Reporting

For an internal project, report suspected vulnerabilities to the maintainers
with reproduction details that do not include real credentials or sensitive
telemetry.
