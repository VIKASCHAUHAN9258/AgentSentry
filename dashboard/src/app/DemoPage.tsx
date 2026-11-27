import {
  Activity,
  AlertTriangle,
  Check,
  CircleDot,
  Database,
  Eye,
  Play,
  RotateCcw,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../api/client";
import type { DemoAlert, DemoSession, DemoScenarioInfo } from "../api/types";

function formatTimestamp(value: number): string {
  return new Date(value * 1000).toLocaleTimeString();
}

function riskClass(value: string): string {
  return `demo-risk-${value.toLowerCase().replace(/[^a-z0-9-]/g, "")}`;
}

function formatScore(value: number | null): string {
  return value === null ? "Not available" : value.toFixed(2);
}

export function DemoPage() {
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["demo"],
    queryFn: api.demo,
    retry: 0,
    refetchOnWindowFocus: false,
  });
  const data = query.data;

  const runAction = async (action: () => Promise<unknown>) => {
    setActionError("");
    setBusy(true);
    try {
      await action();
      await queryClient.invalidateQueries({ queryKey: ["demo"] });
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "The demo request failed.");
    } finally {
      setBusy(false);
    }
  };

  const review = (session: DemoSession, decision: "approved" | "rejected") => {
    const runId = data?.active_run?.run_id;
    if (!runId) return;
    void runAction(() =>
      api.reviewDemoSession(runId, session.session.session_id, {
        decision,
        reviewer: "Local SOC Demo Operator",
        note: "Reviewed the synthetic evidence in the SOC demonstration.",
        confirm_reviewed: true,
      }),
    );
  };

  return (
    <section className="demo-page">
      <header className="demo-heading">
        <div>
          <div className="demo-eyebrow">LOCAL SECURITY OPERATIONS EXERCISE</div>
          <h1>SOC Demo Mode</h1>
          <p>
            Synthetic sessions are ingested into an isolated demo database, then
            evaluated by AgentSentry&apos;s feature, policy, detector, and correlation code.
          </p>
        </div>
        <span className={`demo-mode-pill${data?.enabled ? " is-enabled" : ""}`}>
          <CircleDot size={13} aria-hidden="true" />
          {query.isLoading ? "Checking mode" : data?.enabled ? "Demo enabled" : "Demo disabled"}
        </span>
      </header>

      <div className="demo-simulated-banner" role="note">
        <ShieldAlert size={18} aria-hidden="true" />
        <div>
          <strong>SIMULATED DATA — NOT REAL-WORLD DETECTIONS</strong>
          <span>
            No files are read, commands are executed, or HTTP requests are sent.
            All displayed records are generated for demonstration.
          </span>
        </div>
      </div>

      <div className="demo-safety-note">
        <Database size={15} aria-hidden="true" />
        <span>
          Demo records live separately from user accounts and live telemetry.
          Load replaces only the previous demo run; reset deletes only the selected run.
        </span>
      </div>

      {query.isLoading ? (
        <div className="demo-state" role="status">Loading demo status…</div>
      ) : query.error ? (
        <div className="demo-state is-error" role="alert">
          <strong>Demo status unavailable</strong>
          <span>{query.error.message}</span>
        </div>
      ) : data ? (
        <>
          {!data.enabled && (
            <div className="demo-state">
              <strong>Demo Mode is disabled by the backend.</strong>
              <span>
                Enable it for local development with <code>AGENTSENTRY_DEMO_MODE=1</code>,
                then restart the API. Demo requests are restricted to localhost.
              </span>
            </div>
          )}

          <div className="demo-action-bar">
            <div>
              <strong>Scenario controls</strong>
              <span>
                Repeated loads replace the prior active demo run; your telemetry and accounts are untouched.
              </span>
            </div>
            <div className="demo-actions">
              <button
                className="demo-button is-primary"
                disabled={!data.enabled || busy}
                onClick={() => void runAction(() => api.loadDemo())}
                type="button"
              >
                <Play size={14} aria-hidden="true" />
                Load Demo Data
              </button>
              <button
                className="demo-button"
                disabled={!data.enabled || !data.active_run || busy}
                onClick={() => {
                  const runId = data.active_run?.run_id;
                  if (runId) void runAction(() => api.resetDemo(runId));
                }}
                type="button"
              >
                <RotateCcw size={14} aria-hidden="true" />
                Reset Demo Data
              </button>
              <button
                className="demo-button is-quiet"
                disabled={busy}
                onClick={() => void query.refetch()}
                type="button"
              >
                Refresh
              </button>
            </div>
          </div>

          {actionError && <div className="demo-state is-error" role="alert">{actionError}</div>}

          <div className="demo-scenario-grid">
            {data.scenarios.map((scenario) => (
              <ScenarioControl
                key={scenario.id}
                scenario={scenario}
                disabled={!data.enabled || busy}
                onLoad={() => void runAction(() => api.loadDemo({ scenario_id: scenario.id }))}
              />
            ))}
          </div>

          {data.active_run && (
            <>
              <section className="demo-section">
                <div className="demo-section-heading">
                  <div>
                    <div className="demo-eyebrow">ISOLATED BACKEND RESULTS</div>
                    <h2>Run {data.active_run.run_id}</h2>
                  </div>
                  <span className="demo-tag">SIMULATED</span>
                </div>
                <div className="demo-metrics">
                  <Metric label="Sessions" value={data.metrics.sessions_total} />
                  <Metric label="Tool calls" value={data.metrics.tool_calls_total} />
                  <Metric label="Agents" value={data.metrics.agents_total} />
                  <Metric label="Security alerts" value={data.metrics.alerts_total} />
                </div>
                <p className="demo-disclosure">{data.model_disclosure}</p>
              </section>

              <AlertQueue alerts={data.alerts} />

              <section className="demo-section">
                <div className="demo-section-heading">
                  <div>
                    <div className="demo-eyebrow">SESSION ACTIVITY AND DETECTION EVIDENCE</div>
                    <h2>Scenario investigations</h2>
                  </div>
                </div>
                <div className="demo-session-list">
                  {data.active_run.scenarios.map((session) => (
                    <SessionInvestigation
                      key={session.session.session_id}
                      session={session}
                      runId={data.active_run!.run_id}
                      busy={busy}
                      onReview={(decision) => review(session, decision)}
                    />
                  ))}
                </div>
              </section>
            </>
          )}

          {!data.active_run && data.enabled && (
            <div className="demo-empty-state">
              <Activity size={20} aria-hidden="true" />
              <strong>No demo run is loaded</strong>
              <span>Load all scenarios or choose one scenario above to generate backend telemetry.</span>
            </div>
          )}
        </>
      ) : null}
    </section>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="demo-metric">
      <span>{label}</span>
      <strong>{value.toLocaleString()}</strong>
    </div>
  );
}

function ScenarioControl({
  scenario,
  disabled,
  onLoad,
}: {
  scenario: DemoScenarioInfo;
  disabled: boolean;
  onLoad: () => void;
}) {
  return (
    <article className="demo-scenario-control">
      <span className="demo-tag">DEMO SCENARIO</span>
      <h3>{scenario.name}</h3>
      <code>{scenario.agent_id}</code>
      <p>{scenario.description}</p>
      <div className="demo-scenario-footer">
        <span>{scenario.event_count} synthetic tool events</span>
        <button className="demo-button is-quiet" disabled={disabled} onClick={onLoad} type="button">
          Load scenario
        </button>
      </div>
    </article>
  );
}

function AlertQueue({ alerts }: { alerts: DemoAlert[] }) {
  return (
    <section className="demo-section">
      <div className="demo-section-heading">
        <div>
          <div className="demo-eyebrow">GENERATED FROM BACKEND ASSESSMENTS</div>
          <h2>Security alert queue <span>{alerts.length}</span></h2>
        </div>
        <ShieldAlert size={18} aria-hidden="true" />
      </div>
      {alerts.length === 0 ? (
        <div className="demo-empty-state compact">
          No HIGH/CRITICAL assessment, policy violation, or supported chain was returned.
        </div>
      ) : (
        <div className="demo-alert-list">
          {alerts.map((alert) => (
            <article className="demo-alert" key={alert.alert_id}>
              <div className={`demo-alert-icon ${riskClass(alert.risk_level)}`}>
                <AlertTriangle size={16} aria-hidden="true" />
              </div>
              <div className="demo-alert-copy">
                <div className="demo-alert-title">
                  <strong>{alert.scenario_name}</strong>
                  <span className={`demo-risk-badge ${riskClass(alert.risk_level)}`}>
                    {alert.risk_level}
                  </span>
                  <span className="demo-tag">SIMULATED</span>
                </div>
                <code>{alert.agent_id} · {alert.session_id}</code>
                <p>
                  Calculated risk score: <strong>{formatScore(alert.risk_score)}</strong>
                </p>
                {alert.why_flagged.length > 0 && (
                  <ul>{alert.why_flagged.map((reason) => <li key={reason}>{reason}</li>)}</ul>
                )}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}

function SessionInvestigation({
  session,
  runId,
  busy,
  onReview,
}: {
  session: DemoSession;
  runId: string;
  busy: boolean;
  onReview: (decision: "approved" | "rejected") => void;
}) {
  const { assessment } = session;
  const score = assessment.final_risk_score;
  return (
    <article className="demo-investigation">
      <header className="demo-investigation-heading">
        <div>
          <span className="demo-tag">SIMULATED SESSION</span>
          <h3>{session.scenario_name}</h3>
          <code>{session.agent_id} · {session.session.session_id}</code>
        </div>
        <div className="demo-risk-summary">
          <span className={`demo-risk-badge ${riskClass(assessment.risk_level)}`}>
            {assessment.risk_level}
          </span>
          <strong>{formatScore(score)}</strong>
          <small>calculated final risk</small>
        </div>
      </header>

      <p className="demo-session-description">{session.description}</p>

      <div className="demo-detector-grid">
        <div><span>Assessment status</span><strong>{assessment.assessment_status}</strong></div>
        <div><span>Isolation Forest score</span><strong>{formatScore(assessment.ml_risk_score)}</strong></div>
        <div><span>Policy violations</span><strong>{assessment.policy_violations.length}</strong></div>
        <div><span>Correlated chains</span><strong>{assessment.attack_chains.length}</strong></div>
      </div>

      {assessment.attack_chains.length > 0 && (
        <div className="demo-chain-list">
          {assessment.attack_chains.map((chain) => (
            <div className="demo-chain" key={chain.chain_id}>
              <ShieldAlert size={14} aria-hidden="true" />
              <div>
                <strong>{chain.chain_id} · {chain.severity}</strong>
                <span>
                  {chain.call_indices
                    .map((index) => session.calls[index]?.tool_name ?? `event ${index + 1}`)
                    .join(" → ")}
                </span>
                <small>{chain.description}{chain.mitre_hint ? ` ${chain.mitre_hint}` : ""}</small>
              </div>
            </div>
          ))}
        </div>
      )}

      <details className="demo-details">
        <summary><Activity size={14} aria-hidden="true" /> Tool-call history and timeline ({session.calls.length})</summary>
        <ol className="demo-timeline">
          {session.calls.map((call) => (
            <li key={call.id}>
              <span className="demo-timeline-marker" />
              <time>{formatTimestamp(call.called_at)}</time>
              <div className="demo-event-copy">
                <strong>{call.sequence_num}. {call.tool_name}</strong>
                <span>{JSON.stringify(call.arguments)}</span>
                <small>{call.result_summary}</small>
              </div>
              <span className="demo-tag">DEMO</span>
            </li>
          ))}
        </ol>
      </details>

      <details className="demo-details">
        <summary><Eye size={14} aria-hidden="true" /> Detection output and investigation evidence</summary>
        <div className="demo-investigation-content">
          {assessment.why_flagged.length > 0 ? (
            <ul className="demo-reasons">
              {assessment.why_flagged.map((reason) => <li key={reason}>{reason}</li>)}
            </ul>
          ) : (
            <p className="demo-no-finding">The configured detector and rules returned no finding for this synthetic session.</p>
          )}
          {assessment.contributing_signals.map((signal, index) => (
            <div className="demo-signal" key={`${signal.signal}-${index}`}>
              <strong>{signal.type} · {signal.severity}</strong>
              <span>{signal.detail}</span>
              {signal.evidence.length > 0 && (
                <small>
                  Evidence: {signal.evidence.map((item) => `${item.sequence_num}. ${item.tool_name}`).join(", ")}
                </small>
              )}
            </div>
          ))}
          {assessment.feature_contributions.length > 0 && (
            <div className="demo-feature-table-wrap">
              <strong>Actual feature contributions (z-scores are heuristic baseline deviations)</strong>
              <table className="demo-feature-table">
                <thead><tr><th>Feature</th><th>Observed</th><th>Baseline mean</th><th>z-score</th></tr></thead>
                <tbody>
                  {assessment.feature_contributions.slice(0, 6).map((feature) => (
                    <tr key={feature.feature}>
                      <td>{feature.feature}</td>
                      <td>{feature.value.toFixed(3)}</td>
                      <td>{feature.baseline_mean.toFixed(3)}</td>
                      <td>{feature.z_score.toFixed(2)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </details>

      <div className="demo-review-bar">
        <div>
          <strong>Investigation review: {session.review.decision}</strong>
          <span>
            {session.review.reviewer
              ? `Recorded by ${session.review.reviewer}; evidence ${session.review.evidence_current ? "current" : "changed"}.`
              : "Review decisions are stored only in the isolated demo database."}
          </span>
        </div>
        <div className="demo-actions">
          <button
            className="demo-button is-quiet"
            disabled={busy || !runId}
            onClick={() => onReview("approved")}
            type="button"
          >
            <Check size={13} aria-hidden="true" /> Approve evidence
          </button>
          <button
            className="demo-button is-quiet"
            disabled={busy || !runId}
            onClick={() => onReview("rejected")}
            type="button"
          >
            <AlertTriangle size={13} aria-hidden="true" /> Reject evidence
          </button>
          {session.review.decision !== "unreviewed" && (
            <ShieldCheck size={15} aria-label="Evidence reviewed" />
          )}
        </div>
      </div>
    </article>
  );
}
