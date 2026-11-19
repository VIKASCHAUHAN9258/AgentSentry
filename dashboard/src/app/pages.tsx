import {
  Activity,
  AlertTriangle,
  Boxes,
  Clock3,
  Database,
  FileSearch,
  RadioTower,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  ShieldCheck,
  Users,
  Wrench,
} from "lucide-react";
import { lazy, Suspense, useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api/client";
import {
  useAttackChains,
  useDashboardActivity,
  useDashboardOverview,
  useHealth,
  useMcpServers,
  useRiskDistribution,
  useSession,
  useSessionAssessment,
  useSessions,
  useToolChanges,
} from "../api/queries";
import type {
  ActivityItem,
  AttackChainFinding,
  RiskLevel,
  SessionAssessment,
  SessionSummary,
  ToolCall,
  ToolDefinitionEvent,
} from "../api/types";
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from "../components/states/QueryStates";
import { RenderErrorBoundary } from "../components/states/RenderErrorBoundary";

const NetworkTopology = lazy(() =>
  import("../components/network/NetworkTopology").then(({ NetworkTopology }) => ({
    default: NetworkTopology,
  })),
);

const RISK_LEVELS: RiskLevel[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNASSESSED"];

function formatNumber(value: number | null | undefined): string {
  return typeof value === "number" && Number.isFinite(value)
    ? new Intl.NumberFormat().format(value)
    : "—";
}

function formatTimestamp(value: number | null | undefined): string {
  if (typeof value !== "number" || !Number.isFinite(value)) return "Time unavailable";
  return new Date(value * 1000).toLocaleString();
}

function riskClass(value: string): string {
  return `risk-${value.toLowerCase().replace(/[^a-z0-9-]/g, "")}`;
}

function ErrorWithRetry({ error, retry }: { error: unknown; retry: () => void }) {
  return (
    <div className="soc-error-wrap">
      <ErrorState error={error} />
      <button className="soc-button soc-button--quiet" onClick={retry} type="button">
        <RefreshCw size={14} aria-hidden="true" />
        Retry
      </button>
    </div>
  );
}

function PageHeading({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="soc-page-heading">
      <div>
        <div className="soc-eyebrow">{eyebrow}</div>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {action}
    </div>
  );
}

function Panel({
  eyebrow,
  title,
  icon,
  action,
  children,
  className = "",
}: {
  eyebrow: string;
  title: string;
  icon?: ReactNode;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`soc-panel ${className}`}>
      <div className="soc-panel-heading">
        <div>
          <div className="soc-eyebrow">{eyebrow}</div>
          <h2>{title}</h2>
        </div>
        {action ?? (icon && <span className="soc-panel-icon">{icon}</span>)}
      </div>
      {children}
    </section>
  );
}

function MetricCard({
  label,
  value,
  icon,
  accent = "cyan",
  detail,
}: {
  label: string;
  value: string;
  icon: ReactNode;
  accent?: "cyan" | "teal" | "purple" | "amber";
  detail?: string;
}) {
  return (
    <article className={`soc-metric soc-metric--${accent}`}>
      <span className="soc-metric-icon">{icon}</span>
      <div className="soc-metric-copy">
        <span>{label}</span>
        <strong>{value}</strong>
        {detail && <small>{detail}</small>}
      </div>
    </article>
  );
}

function RiskDistributionPanel() {
  const query = useRiskDistribution();
  const total = query.data?.total_sessions ?? 0;
  return (
    <Panel
      eyebrow="RISK POSTURE"
      title="Session risk distribution"
      icon={<ShieldCheck size={17} aria-hidden="true" />}
      className="soc-risk-panel"
    >
      {query.isLoading ? (
        <LoadingState />
      ) : query.error ? (
        <ErrorWithRetry error={query.error} retry={() => void query.refetch()} />
      ) : !query.data || total === 0 ? (
        <EmptyState title="No sessions assessed">
          Risk distribution will be shown when session telemetry is available.
        </EmptyState>
      ) : (
        <>
          <div className="soc-risk-total">
            <strong>{formatNumber(total)}</strong>
            <span>recorded sessions</span>
          </div>
          <div className="soc-risk-list">
            {RISK_LEVELS.map((level) => {
              const count = query.data?.distribution[level] ?? 0;
              const percent = total > 0 ? (count / total) * 100 : 0;
              return (
                <div className="soc-risk-row" key={level}>
                  <div className="soc-risk-label">
                    <span className={`soc-risk-dot ${riskClass(level)}`} />
                    <span>{level}</span>
                    <strong>{formatNumber(count)}</strong>
                  </div>
                  <div className="soc-progress-track" aria-hidden="true">
                    <span className={riskClass(level)} style={{ width: `${percent}%` }} />
                  </div>
                </div>
              );
            })}
          </div>
          <p className="soc-panel-note">Counts reflect backend session assessments.</p>
        </>
      )}
    </Panel>
  );
}

function ActivityPanel() {
  const query = useDashboardActivity(50);
  return (
    <Panel
      eyebrow="LATEST SIGNALS"
      title="Activity timeline"
      icon={<Activity size={17} aria-hidden="true" />}
      className="soc-activity-panel"
    >
      {query.isLoading ? (
        <LoadingState />
      ) : query.error ? (
        <ErrorWithRetry error={query.error} retry={() => void query.refetch()} />
      ) : !query.data?.length ? (
        <EmptyState title="No activity recorded">
          Start an agent through the monitored proxy to populate this timeline.
        </EmptyState>
      ) : (
        <div className="soc-timeline">
          {query.data.slice(0, 7).map((item) => (
            <ActivityRow item={item} key={`${item.event_type}-${item.id}`} />
          ))}
        </div>
      )}
    </Panel>
  );
}

function ActivityRow({ item }: { item: ActivityItem }) {
  const isCall = item.event_type === "tool_call";
  const label = isCall ? item.tool_name : item.event_type.replaceAll("_", " ");
  return (
    <div className="soc-activity-row">
      <span className={`soc-event-marker${isCall ? "" : " soc-event-marker--change"}`} />
      <div className="soc-activity-copy">
        <strong>{label}</strong>
        <span>
          {isCall ? `Session ${item.session_id}` : `Tool ${item.tool_name} · ${item.session_id}`}
        </span>
      </div>
      <time
        dateTime={
          Number.isFinite(item.called_at)
            ? new Date(item.called_at * 1000).toISOString()
            : undefined
        }
      >
        {formatTimestamp(item.called_at)}
      </time>
    </div>
  );
}

function FindingRow({ finding }: { finding: AttackChainFinding }) {
  return (
    <Link
      className="soc-finding-row"
      to={`/sessions/${encodeURIComponent(finding.session_id)}`}
      aria-label={`Inspect ${finding.severity} ${finding.chain_id} finding`}
    >
      <span className={`soc-finding-icon ${riskClass(finding.severity)}`}>
        <ShieldAlert size={15} aria-hidden="true" />
      </span>
      <span className="soc-finding-copy">
        <strong>{finding.description}</strong>
        <small>
          {finding.chain_id} · {finding.session_id}
          {finding.mitre_hint ? ` · ${finding.mitre_hint}` : ""}
        </small>
      </span>
      <span className={`soc-risk-badge ${riskClass(finding.severity)}`}>
        {finding.severity}
      </span>
    </Link>
  );
}

function FindingsPanel() {
  const query = useAttackChains();
  return (
    <Panel
      eyebrow="CORRELATED SIGNALS"
      title="Attack-chain findings"
      icon={<ShieldAlert size={17} aria-hidden="true" />}
      className="soc-findings-panel"
    >
      {query.isLoading ? (
        <LoadingState />
      ) : query.error ? (
        <ErrorWithRetry error={query.error} retry={() => void query.refetch()} />
      ) : !query.data?.length ? (
        <EmptyState title="No attack chains detected">
          No correlated findings are currently returned by the API.
        </EmptyState>
      ) : (
        <div className="soc-findings-list">
          {query.data.slice(0, 5).map((finding, index) => (
            <FindingRow
              finding={finding}
              key={`${finding.session_id}-${finding.chain_id}-${index}`}
            />
          ))}
        </div>
      )}
    </Panel>
  );
}

function OverviewPage() {
  const overview = useDashboardOverview();
  const sessions = useSessions({ limit: 50 });
  const findings = useAttackChains();
  const activity = useDashboardActivity(50);

  const refresh = () => {
    void overview.refetch();
    void sessions.refetch();
    void findings.refetch();
    void activity.refetch();
  };
  const metrics = overview.data;

  return (
    <section className="soc-page soc-page-enter as-overview-page">
      <PageHeading
        eyebrow="AGENT RUNTIME SECURITY OPERATIONS"
        title="Incident Management"
        description="Monitor agent sessions, tool activity, and correlated security findings in real time."
        action={
          <button className="soc-button soc-button--primary" onClick={refresh} type="button">
            <RefreshCw size={14} aria-hidden="true" />
            Refresh data
          </button>
        }
      />

      {metrics?.metrics_note && (
        <div className="soc-data-note">
          <Database size={15} aria-hidden="true" />
          <span>{metrics.metrics_note}</span>
        </div>
      )}

      {overview.isLoading ? (
        <LoadingState title="Loading persisted overview metrics" />
      ) : overview.error ? (
        <ErrorWithRetry error={overview.error} retry={() => void overview.refetch()} />
      ) : null}

      <div className="soc-overview-grid as-incident-grid">
        <RiskDistributionPanel />
        <Panel
          eyebrow="LIVE OBSERVED RELATIONSHIPS"
          title="Session network topology"
          icon={<RadioTower size={17} aria-hidden="true" />}
          className="soc-topology-panel"
        >
          {sessions.isLoading || findings.isLoading ? (
            <LoadingState title="Loading observed sessions and findings" />
          ) : sessions.error ? (
            <ErrorWithRetry error={sessions.error} retry={() => void sessions.refetch()} />
          ) : findings.error ? (
            <ErrorWithRetry error={findings.error} retry={() => void findings.refetch()} />
          ) : (
            <RenderErrorBoundary
              fallback={
                <div className="as-topology-message" role="alert">
                  Interactive topology could not be loaded. Reload the page to try again.
                </div>
              }
            >
              <Suspense fallback={<LoadingState title="Loading session topology" />}>
                <NetworkTopology sessions={sessions.data ?? []} findings={findings.data ?? []} />
              </Suspense>
            </RenderErrorBoundary>
          )}
          <div className="soc-topology-legend">
            <span><i className="soc-legend-dot soc-legend-dot--normal" />Recorded session</span>
            <span><i className="soc-legend-dot soc-legend-dot--finding" />Session with finding</span>
          </div>
          {metrics && (
            <div className="soc-metrics-grid as-topology-metrics">
              <MetricCard label="Active sessions" value={formatNumber(metrics.active_sessions)} icon={<RadioTower size={17} />} accent="teal" />
              <MetricCard label="Total tool calls" value={formatNumber(metrics.tool_calls_total)} icon={<Activity size={17} />} />
              <MetricCard label="Registered agents" value={formatNumber(metrics.agents_total)} icon={<Users size={17} />} accent="purple" />
              <MetricCard label="Tool definition changes" value={formatNumber(metrics.tool_definition_changes)} icon={<Wrench size={17} />} accent="amber" />
            </div>
          )}
        </Panel>
        <ActivityPanel />
        <FindingsPanel />
        <MonitoringSnapshot />
      </div>
    </section>
  );
}

function MonitoringSnapshot() {
  const health = useHealth();
  const overview = useDashboardOverview();
  const apiStatus =
    health.isLoading ? "Checking" :
      health.error ? "Unavailable" :
        health.data?.status === "ok" && health.data.database === "connected" ? "Connected" :
          "Unavailable";

  return (
    <Panel
      eyebrow="SYSTEM STATUS"
      title="Monitoring snapshot"
      icon={<Server size={17} aria-hidden="true" />}
      className="soc-snapshot-panel"
    >
      <div className="soc-snapshot-list">
        <div><span>Telemetry API</span><strong className={apiStatus === "Connected" ? "is-connected" : ""}>{apiStatus}</strong></div>
        {overview.data && (
          <>
            <div><span>Persisted sessions</span><strong>{formatNumber(overview.data.sessions_total)}</strong></div>
            <div><span>Active sessions</span><strong>{formatNumber(overview.data.active_sessions)}</strong></div>
          </>
        )}
        {health.error && <p className="soc-inline-note">API health could not be verified.</p>}
      </div>
      <p className="soc-panel-note">Status and counts reflect the latest API responses.</p>
    </Panel>
  );
}

function SessionsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [search, setSearch] = useState(() => searchParams.get("search") ?? "");
  const [riskFilter, setRiskFilter] = useState(() => searchParams.get("risk") ?? "ALL");
  const query = useSessions({ limit: 200 });
  useEffect(() => {
    setSearch(searchParams.get("search") ?? "");
    setRiskFilter(searchParams.get("risk") ?? "ALL");
  }, [searchParams]);
  const rows = useMemo(() => {
    const normalized = search.trim().toLowerCase();
    return (query.data ?? []).filter((session) => {
      const matchesText =
        !normalized ||
        `${session.session_id} ${session.agent_id}`.toLowerCase().includes(normalized);
      return matchesText && (riskFilter === "ALL" || session.risk_level === riskFilter);
    });
  }, [query.data, riskFilter, search]);

  return (
    <section className="soc-page soc-page-enter">
      <PageHeading
        eyebrow="TELEMETRY EXPLORER"
        title="Agent sessions"
        description="Search persisted session records and inspect session-level evidence."
      />
      <Panel eyebrow="RECORDED TELEMETRY" title="Session monitor" icon={<RadioTower size={17} aria-hidden="true" />}>
        {query.isLoading ? (
          <LoadingState />
        ) : query.error ? (
          <ErrorWithRetry error={query.error} retry={() => void query.refetch()} />
        ) : !query.data?.length ? (
          <EmptyState title="No session telemetry">
            Sessions will appear after the monitored proxy records activity.
          </EmptyState>
        ) : (
          <>
            <p className="soc-panel-note">
              Showing up to 200 sessions returned by the API; older historical sessions may not be included.
            </p>
            <div className="soc-table-toolbar">
              <label className="soc-search">
                <Search size={15} aria-hidden="true" />
                <span className="sr-only">Search sessions</span>
                <input
                  onChange={(event) => setSearch(event.currentTarget.value)}
                  placeholder="Search session or agent ID"
                  value={search}
                />
              </label>
              <label className="soc-filter">
                <span className="sr-only">Filter by risk level</span>
                <select
                  value={riskFilter}
                  onChange={(event) => {
                    const nextRisk = event.currentTarget.value;
                    setRiskFilter(nextRisk);
                    const nextParams = new URLSearchParams(searchParams);
                    if (nextRisk === "ALL") nextParams.delete("risk");
                    else nextParams.set("risk", nextRisk);
                    setSearchParams(nextParams, { replace: true });
                  }}
                >
                  <option value="ALL">All risk levels</option>
                  {RISK_LEVELS.map((level) => <option key={level} value={level}>{level}</option>)}
                </select>
              </label>
            </div>
            {rows.length ? (
              <div className="soc-table-scroll">
                <table className="soc-table">
                  <thead>
                    <tr><th>Session</th><th>Agent</th><th>Started</th><th>Calls</th><th>Risk</th><th>Assessment</th><th /></tr>
                  </thead>
                  <tbody>
                    {rows.map((session) => <SessionTableRow key={session.session_id} session={session} />)}
                  </tbody>
                </table>
              </div>
            ) : (
              <EmptyState title="No matching sessions">
                Change the search text or risk filter to see other recorded sessions.
              </EmptyState>
            )}
          </>
        )}
      </Panel>
    </section>
  );
}

function SessionTableRow({ session }: { session: SessionSummary }) {
  return (
    <tr>
      <td className="soc-mono">{session.session_id}</td>
      <td>{session.agent_id}</td>
      <td>{formatTimestamp(session.started_at)}</td>
      <td>{formatNumber(session.call_count)}</td>
      <td><span className={`soc-risk-badge ${riskClass(session.risk_level)}`}>{session.risk_level}</span></td>
      <td>{session.assessment_status.replaceAll("_", " ")}</td>
      <td><Link className="soc-table-link" to={`/sessions/${encodeURIComponent(session.session_id)}`}>Inspect</Link></td>
    </tr>
  );
}

function SessionDetailPage() {
  const { sessionId = "" } = useParams();
  const sessionQuery = useSession(sessionId);
  const assessmentQuery = useSessionAssessment(sessionId);

  return (
    <section className="soc-page soc-page-enter">
      <Link className="soc-back-link" to="/sessions">← Back to sessions</Link>
      {sessionQuery.isLoading ? (
        <LoadingState title="Loading session evidence" />
      ) : sessionQuery.error ? (
        <ErrorWithRetry error={sessionQuery.error} retry={() => void sessionQuery.refetch()} />
      ) : sessionQuery.data ? (
        <>
          <PageHeading
            eyebrow="SESSION INVESTIGATION"
            title={sessionQuery.data.session.session_id}
            description="Persisted tool-call and tool-definition evidence for this session."
          />
          <div className="soc-detail-metrics">
            <MetricCard label="Agent" value={sessionQuery.data.session.agent_id} icon={<Users size={17} />} />
            <MetricCard label="Tool calls" value={formatNumber(sessionQuery.data.calls.length)} icon={<Activity size={17} />} accent="teal" />
            <MetricCard
              label="Risk level"
              value={assessmentQuery.isLoading ? "Loading" : assessmentQuery.data?.risk_level ?? "Unavailable"}
              icon={<ShieldCheck size={17} />}
              accent="purple"
            />
            <MetricCard
              label="Final risk score"
              value={typeof assessmentQuery.data?.final_risk_score === "number" ? formatNumber(assessmentQuery.data.final_risk_score) : "Not available"}
              icon={<AlertTriangle size={17} />}
              accent="amber"
            />
          </div>
          <SessionReviewPanel
            sessionId={sessionQuery.data.session.session_id}
            review={sessionQuery.data.review}
            refresh={() => void sessionQuery.refetch()}
          />
          {assessmentQuery.isLoading && <LoadingState title="Loading risk assessment" />}
          {assessmentQuery.error && <ErrorWithRetry error={assessmentQuery.error} retry={() => void assessmentQuery.refetch()} />}
          {assessmentQuery.data && <AssessmentPanel assessment={assessmentQuery.data} />}
          <SessionEvidence
            calls={sessionQuery.data.calls}
            events={sessionQuery.data.tool_definition_events}
          />
        </>
      ) : null}
    </section>
  );
}


function SessionReviewPanel({
  sessionId,
  review,
  refresh,
}: {
  sessionId: string;
  review?: { decision: string; reviewer: string | null; reviewed_at: number | null; review_note: string; evidence_current: boolean };
  refresh: () => void;
}) {
  const [reviewer, setReviewer] = useState("");
  const [note, setNote] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [failure, setFailure] = useState(false);
  const decision = review?.decision ?? "unreviewed";

  async function submit(next: "approved" | "rejected") {
    if (!reviewer.trim() || !confirmed) {
      setFailure(true);
      setMessage("Enter your reviewer ID and confirm that you inspected the full session evidence.");
      return;
    }
    setBusy(true);
    setMessage("");
    try {
      await api.reviewSession(sessionId, {
        decision: next,
        reviewer: reviewer.trim(),
        note,
        confirm_reviewed: true,
      });
      setFailure(false);
      setMessage(`Session ${next}. Review decision and evidence fingerprint recorded.`);
      setConfirmed(false);
      refresh();
    } catch (error) {
      setFailure(true);
      setMessage(error instanceof Error ? error.message : "Unable to record review.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel eyebrow="BASELINE ELIGIBILITY" title="Human session review" icon={<ShieldCheck size={17} aria-hidden="true" />}>
      <div className="soc-assessment-status">
        <span>Review decision</span>
        <strong>{decision.toUpperCase()}{review?.evidence_current === false && decision !== "unreviewed" ? " · STALE EVIDENCE" : ""}</strong>
        {review?.reviewer && <span className="soc-availability-note">Reviewed by {review.reviewer} · {formatTimestamp(review.reviewed_at)}</span>}
        {review?.review_note && <span className="soc-availability-note">{review.review_note}</span>}
      </div>
      <p className="soc-panel-note">Approval is a human assertion, not proof of benign behavior. Training also rejects stale evidence, policy violations, attack-chain findings, and tool-definition changes.</p>
      <div className="soc-table-toolbar">
        <label className="soc-search"><span className="sr-only">Reviewer identifier</span><input value={reviewer} onChange={(event) => setReviewer(event.currentTarget.value)} placeholder="Reviewer identifier" maxLength={120} /></label>
        <label className="soc-search"><span className="sr-only">Review note</span><input value={note} onChange={(event) => setNote(event.currentTarget.value)} placeholder="Review note (optional)" maxLength={2000} /></label>
      </div>
      <label className="soc-panel-note" style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <input type="checkbox" checked={confirmed} onChange={(event) => setConfirmed(event.currentTarget.checked)} />
        I inspected the session calls, arguments, results, and security findings.
      </label>
      <div className="soc-table-toolbar">
        <button className="soc-button soc-button--primary" disabled={busy || !sessionId} onClick={() => void submit("approved")} type="button">{busy ? "Saving…" : "Approve as benign"}</button>
        <button className="soc-button soc-button--quiet" disabled={busy || !sessionId} onClick={() => void submit("rejected")} type="button">Reject session</button>
      </div>
      {message && <p role="status" className="soc-panel-note" style={{ color: failure ? "#ff8b8b" : "#7de0c3" }}>{message}</p>}
    </Panel>
  );
}

function AssessmentPanel({ assessment }: { assessment: SessionAssessment }) {
  return (
    <Panel eyebrow="ASSESSMENT" title="Session risk assessment" icon={<ShieldAlert size={17} aria-hidden="true" />}>
      <div className="soc-assessment-status">
        <span>Status</span><strong>{assessment.assessment_status.replaceAll("_", " ")}</strong>
        {!assessment.availability.ml_assessment && (
          <span className="soc-availability-note">
            {assessment.availability.reason ?? "ML assessment unavailable."}
          </span>
        )}
      </div>
      {assessment.why_flagged.length ? (
        <ul className="soc-reason-list">
          {assessment.why_flagged.map((reason, index) => <li key={`${index}-${reason}`}>{reason}</li>)}
        </ul>
      ) : !assessment.contributing_signals.length ? (
        <EmptyState title={assessment.risk_level === "UNASSESSED" ? "Insufficient assessment data" : "No assessment findings"}>
          {assessment.risk_level === "UNASSESSED"
            ? "No risk score is available. The session has no trained baseline or deterministic findings."
            : "No contributing signals were returned for this session."}
        </EmptyState>
      ) : null}
      {!!assessment.contributing_signals.length && (
        <div className="soc-subsection">
          <h3>Contributing signals</h3>
          {assessment.contributing_signals.map((signal, index) => (
            <div className="soc-evidence-row" key={`${signal.type}-${signal.signal}-${index}`}>
              <span className={`soc-risk-badge ${riskClass(signal.severity)}`}>{signal.severity}</span>
              <div>
                <strong>{signal.signal.replaceAll("_", " ")}</strong>
                <span>{signal.detail}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      {!!assessment.policy_violations.length && (
        <div className="soc-subsection">
          <h3>Policy violations</h3>
          {assessment.policy_violations.map((violation, index) => (
            <div className="soc-evidence-row" key={`${violation.rule}-${index}`}>
              <span className={`soc-risk-badge ${riskClass(violation.severity)}`}>{violation.severity}</span>
              <div><strong>{violation.rule}</strong><span>{violation.detail}</span></div>
            </div>
          ))}
        </div>
      )}
      {!!assessment.attack_chains.length && (
        <div className="soc-subsection">
          <h3>Attack chains</h3>
          {assessment.attack_chains.map((chain, index) => (
            <div className="soc-evidence-row" key={`${chain.chain_id}-${index}`}>
              <span className={`soc-risk-badge ${riskClass(chain.severity)}`}>{chain.severity}</span>
              <div><strong>{chain.chain_id}</strong><span>{chain.description}{chain.mitre_hint ? ` · ${chain.mitre_hint}` : ""}</span></div>
            </div>
          ))}
        </div>
      )}
      {!!assessment.feature_contributions.length && (
        <div className="soc-subsection">
          <h3>Behavior baseline contributions</h3>
          <div className="soc-table-scroll">
            <table className="soc-table">
              <thead>
                <tr><th>Feature</th><th>Observed</th><th>Baseline</th><th>Deviation</th></tr>
              </thead>
              <tbody>
                {assessment.feature_contributions.slice(0, 5).map((item) => (
                  <tr key={item.feature}>
                    <td>{item.feature.replaceAll("_", " ")}</td>
                    <td>{formatNumber(item.value)}</td>
                    <td>{formatNumber(item.baseline_mean)}</td>
                    <td>{formatNumber(item.z_score)} σ</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="soc-panel-note">Standardized deviations are heuristic explanations, not causal attributions.</p>
        </div>
      )}
      {!!assessment.evidence.length && (
        <div className="soc-subsection">
          <h3>Observed evidence</h3>
          {assessment.evidence.map((item) => (
            <div className="soc-evidence-row" key={`${item.kind}-${item.index}`}>
              <span className="soc-risk-badge risk-unassessed">{item.kind.replaceAll("_", " ")}</span>
              <div>
                <strong>
                  {item.kind === "tool_call" ? "Call" : "Tool event"}{" "}
                  {formatNumber(item.sequence_num)} · {item.tool_name}
                </strong>
                <span>{formatTimestamp(item.called_at)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </Panel>
  );
}

function SessionEvidence({
  calls,
  events,
}: {
  calls: ToolCall[];
  events: ToolDefinitionEvent[];
}) {
  const timeline = useMemo(
    () => [
      ...calls.map((call) => ({ kind: "call" as const, sequence: call.sequence_num, item: call })),
      ...events.map((event) => ({ kind: "change" as const, sequence: event.sequence_num, item: event })),
    ].sort((a, b) => a.sequence - b.sequence),
    [calls, events],
  );

  return (
    <Panel eyebrow="SESSION EVIDENCE" title="Observed event timeline" icon={<Clock3 size={17} aria-hidden="true" />}>
      {timeline.length ? (
        <div className="soc-evidence-timeline">
          {timeline.map((entry, index) => entry.kind === "call" ? (
            <div className="soc-evidence-event" key={`call-${entry.item.id}`}>
              <span className={`soc-event-marker${entry.item.is_error ? " soc-event-marker--error" : ""}`} />
              <div className="soc-evidence-event__content">
                <div className="soc-evidence-event__heading">
                  <strong>{entry.item.tool_name}</strong>
                  <time>{formatTimestamp(entry.item.called_at)}</time>
                </div>
                <span>Tool call · sequence {entry.item.sequence_num}{entry.item.is_error ? " · error" : ""}</span>
                {entry.item.arguments !== null && entry.item.arguments !== undefined && (
                  <details>
                    <summary>Arguments</summary>
                    <pre>{JSON.stringify(entry.item.arguments, null, 2)}</pre>
                  </details>
                )}
                {entry.item.result_summary && <p>{entry.item.result_summary}</p>}
              </div>
            </div>
          ) : (
            <DefinitionEventRow event={entry.item} key={`change-${entry.item.id}-${index}`} />
          ))}
        </div>
      ) : (
        <EmptyState title="No session events recorded">
          This session currently has no tool calls or tool-definition events.
        </EmptyState>
      )}
    </Panel>
  );
}

function DefinitionEventRow({ event }: { event: ToolDefinitionEvent }) {
  return (
    <div className="soc-evidence-event">
      <span className="soc-event-marker soc-event-marker--change" />
      <div className="soc-evidence-event__content">
        <div className="soc-evidence-event__heading">
          <strong>Tool definition changed · {event.tool_name}</strong>
          <time>{formatTimestamp(event.called_at ?? event.recorded_at)}</time>
        </div>
        <span>{event.notification_method} · sequence {event.sequence_num}</span>
        <details>
          <summary>Definition details</summary>
          <pre>{JSON.stringify({ before: event.before_definition, after: event.after_definition }, null, 2)}</pre>
        </details>
      </div>
    </div>
  );
}

function InvestigationsPage() {
  const query = useAttackChains();
  return (
    <section className="soc-page soc-page-enter">
      <PageHeading
        eyebrow="DETECTION & RESPONSE"
        title="Attack-chain investigations"
        description="Correlated findings returned by the AgentSentry chain detector."
      />
      <Panel eyebrow="BACKEND FINDINGS" title="Correlated attack chains" icon={<FileSearch size={17} aria-hidden="true" />}>
        {query.isLoading ? (
          <LoadingState />
        ) : query.error ? (
          <ErrorWithRetry error={query.error} retry={() => void query.refetch()} />
        ) : !query.data?.length ? (
          <EmptyState title="No attack-chain findings">
            The API has not returned any correlated attack chains.
          </EmptyState>
        ) : (
          <div className="soc-findings-list">
            {query.data.map((finding, index) => (
              <FindingRow
                finding={finding}
                key={`${finding.session_id}-${finding.chain_id}-${index}`}
              />
            ))}
          </div>
        )}
      </Panel>
    </section>
  );
}

function McpPage() {
  const servers = useMcpServers();
  const changes = useToolChanges();

  return (
    <section className="soc-page soc-page-enter">
      <PageHeading
        eyebrow="MODEL CONTEXT PROTOCOL"
        title="MCP security"
        description="Inspect MCP servers and tool-definition changes observed by the AgentSentry proxy."
      />
      {servers.isLoading ? (
        <LoadingState title="Checking MCP inventory availability" />
      ) : servers.error ? (
        <ErrorWithRetry error={servers.error} retry={() => void servers.refetch()} />
      ) : servers.data?.status === "unavailable" ? (
        <div className="soc-unavailable-banner">
          <Server size={17} aria-hidden="true" />
          <div>
            <strong>MCP server inventory unavailable</strong>
            <span>{servers.data.reason ?? "Persistent proxy inventory is unavailable."}</span>
          </div>
        </div>
      ) : null}
      {!servers.isLoading && !servers.error && servers.data?.status === "empty" && (
        <Panel eyebrow="BACKEND INVENTORY" title="MCP server inventory" icon={<Server size={17} aria-hidden="true" />}>
          <EmptyState title="No proxy-observed MCP servers">
            {servers.data.reason ?? "Server inventory will appear after a downstream MCP connection is observed."}
          </EmptyState>
        </Panel>
      )}
      {!servers.isLoading && !servers.error && servers.data?.status === "available" && (
        <Panel
          eyebrow="BACKEND INVENTORY"
          title="MCP server inventory"
          icon={<Server size={17} aria-hidden="true" />}
        >
          <div className="soc-table-scroll">
            <table className="soc-table">
              <thead>
                <tr>
                  <th>Server</th>
                  <th>Transport</th>
                  <th>Status</th>
                  <th>Connections</th>
                  <th>First seen</th>
                  <th>Last seen</th>
                  <th>Associated agent sessions</th>
                </tr>
              </thead>
              <tbody>
                {servers.data.servers.map((server) => (
                  <tr key={server.server_id}>
                    <td>
                      <strong>{server.server_name}</strong>
                      <small className="soc-mcp-server-id">{server.server_id}</small>
                    </td>
                    <td>{server.transport}</td>
                    <td>
                      <span className={`soc-mcp-status soc-mcp-status--${server.connection_status}`}>
                        {server.connection_status}
                      </span>
                    </td>
                    <td>{formatNumber(server.connection_count)}</td>
                    <td>{formatTimestamp(server.first_seen)}</td>
                    <td>{formatTimestamp(server.last_seen)}</td>
                    <td>
                      <details>
                        <summary>{server.agents.map((agent) => agent.agent_id).join(", ")}</summary>
                        <ul className="soc-mcp-session-list">
                          {server.sessions.map((session) => (
                            <li key={session.session_id}>
                              <Link
                                className="soc-table-link"
                                to={`/sessions/${encodeURIComponent(session.session_id)}`}
                              >
                                {session.agent_id} · {session.session_id}
                              </Link>
                              <span>
                                {session.connection_status} · connected {formatTimestamp(session.connected_at)}
                                {session.disconnected_at !== null
                                  ? ` · disconnected ${formatTimestamp(session.disconnected_at)}`
                                  : ""}
                              </span>
                            </li>
                          ))}
                        </ul>
                      </details>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}
      <div className="soc-detail-metrics soc-detail-metrics--two">
        <MetricCard
          label="MCP inventory"
          value={servers.data ? (
            servers.data.status === "available" ? "Available" :
              servers.data.status === "empty" ? "Empty" : "Unavailable"
          ) : "Checking"}
          icon={<Server size={17} />}
          accent={servers.data?.status === "available" ? "teal" : "amber"}
        />
        <MetricCard
          label="Returned tool changes"
          value={changes.data ? formatNumber(changes.data.length) : "—"}
          icon={<Wrench size={17} />}
          accent="purple"
        />
      </div>
      <Panel eyebrow="INTEGRITY MONITOR" title="Tool-definition change log" icon={<Boxes size={17} aria-hidden="true" />}>
        {changes.isLoading ? (
          <LoadingState />
        ) : changes.error ? (
          <ErrorWithRetry error={changes.error} retry={() => void changes.refetch()} />
        ) : !changes.data?.length ? (
          <EmptyState title="No tool-definition changes recorded">
            Changes observed by the proxy will appear here when available.
          </EmptyState>
        ) : (
          <div className="soc-table-scroll">
            <table className="soc-table">
              <thead><tr><th>Recorded</th><th>Tool</th><th>Session</th><th>Notification</th><th>Schema update</th></tr></thead>
              <tbody>
                {changes.data.map((event) => (
                  <tr key={event.id}>
                    <td>{formatTimestamp(event.recorded_at)}</td>
                    <td>{event.tool_name}</td>
                    <td><Link className="soc-table-link" to={`/sessions/${encodeURIComponent(event.session_id)}`}>{event.session_id}</Link></td>
                    <td>{event.notification_method}</td>
                    <td><details><summary>View definitions</summary><pre>{JSON.stringify({ before: event.before_schema, after: event.after_schema }, null, 2)}</pre></details></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </section>
  );
}

export { OverviewPage, SessionsPage, SessionDetailPage, InvestigationsPage, McpPage };
