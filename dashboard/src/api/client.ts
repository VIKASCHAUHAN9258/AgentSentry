import type {
  ActivityItem,
  AgentSummary,
  AuthResult,
  AuthStatusResponse,
  AttackChainFinding,
  DemoAlert,
  DemoData,
  DemoReviewResult,
  DemoScenarioInfo,
  DemoSession,
  DashboardOverview,
  HealthResponse,
  McpServerInventoryItem,
  McpServersResponse,
  RiskDistribution,
  SessionAssessment,
  SessionDetailResponse,
  SessionReviewStatus,
  SessionSummary,
  ToolCall,
  ToolDefinitionEvent,
} from "./types";

export class ApiError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

let csrfToken: string | null = null;

type PayloadGuard<T> = (payload: unknown) => payload is T;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

function isNullableNumber(value: unknown): value is number | null {
  return value === null || isFiniteNumber(value);
}

function isHealthResponse(value: unknown): value is HealthResponse {
  return isRecord(value) &&
    (value.status === "ok" || value.status === "unavailable") &&
    (value.database === "connected" ||
      value.database === "unavailable" ||
      value.database === "schema_unavailable");
}

function isAuthUser(value: unknown): value is { id: number; name: string; email: string } {
  return isRecord(value) &&
    isFiniteNumber(value.id) &&
    isString(value.name) &&
    isString(value.email);
}

function isAuthStatusResponse(value: unknown): value is AuthStatusResponse {
  return isRecord(value) &&
    typeof value.required === "boolean" &&
    typeof value.authenticated === "boolean" &&
    (value.user === null || isAuthUser(value.user)) &&
    isString(value.csrf_token);
}

function isAuthResult(value: unknown): value is AuthResult {
  return isRecord(value) &&
    value.authenticated === true &&
    isAuthUser(value.user) &&
    isString(value.csrf_token);
}

function isDemoScenarioInfo(value: unknown): value is DemoScenarioInfo {
  return isRecord(value) &&
    isString(value.id) &&
    isString(value.name) &&
    isString(value.agent_id) &&
    isString(value.description) &&
    isFiniteNumber(value.event_count) &&
    value.classification === "SIMULATED";
}

function isDemoReview(value: unknown): value is SessionReviewStatus {
  return isRecord(value) &&
    (value.decision === "unreviewed" || value.decision === "approved" || value.decision === "rejected") &&
    (value.reviewer === null || isString(value.reviewer)) &&
    isNullableNumber(value.reviewed_at) &&
    isString(value.review_note) &&
    typeof value.evidence_current === "boolean";
}

function isDemoSession(value: unknown): value is DemoSession {
  return isRecord(value) &&
    isString(value.scenario_id) &&
    isString(value.scenario_name) &&
    isString(value.description) &&
    isString(value.agent_id) &&
    isRecord(value.session) &&
    isString(value.session.session_id) &&
    isString(value.session.agent_id) &&
    isFiniteNumber(value.session.started_at) &&
    isNullableNumber(value.session.ended_at) &&
    Array.isArray(value.calls) &&
    value.calls.every(isToolCall) &&
    isSessionAssessment(value.assessment) &&
    isDemoReview(value.review) &&
    value.classification === "SIMULATED";
}

function isDemoAlert(value: unknown): value is DemoAlert {
  return isRecord(value) &&
    isString(value.alert_id) &&
    isString(value.run_id) &&
    isString(value.scenario_id) &&
    isString(value.scenario_name) &&
    isString(value.agent_id) &&
    isString(value.session_id) &&
    isString(value.risk_level) &&
    isNullableNumber(value.risk_score) &&
    Array.isArray(value.why_flagged) &&
    value.why_flagged.every(isString) &&
    Array.isArray(value.contributing_signals) &&
    value.contributing_signals.every(isContributingSignal) &&
    value.classification === "SIMULATED";
}

function isDemoData(value: unknown): value is DemoData {
  if (!isRecord(value) || typeof value.enabled !== "boolean" ||
      value.classification !== "SIMULATED" || !isString(value.model_disclosure) ||
      !Array.isArray(value.scenarios) || !value.scenarios.every(isDemoScenarioInfo) ||
      !isRecord(value.metrics) || !isFiniteNumber(value.metrics.sessions_total) ||
      !isFiniteNumber(value.metrics.tool_calls_total) ||
      !isFiniteNumber(value.metrics.agents_total) ||
      !isFiniteNumber(value.metrics.alerts_total) ||
      !Array.isArray(value.alerts) || !value.alerts.every(isDemoAlert)) {
    return false;
  }
  if (value.active_run === null) return true;
  return isRecord(value.active_run) &&
    isString(value.active_run.run_id) &&
    isFiniteNumber(value.active_run.created_at) &&
    Array.isArray(value.active_run.scenarios) &&
    value.active_run.scenarios.every(isDemoSession);
}

function isDemoReviewResult(value: unknown): value is DemoReviewResult {
  return isRecord(value) &&
    isString(value.session_id) &&
    isString(value.agent_id) &&
    (value.decision === "approved" || value.decision === "rejected") &&
    isString(value.reviewer) &&
    isFiniteNumber(value.reviewed_at) &&
    isString(value.evidence_sha256);
}

function isAgentSummary(value: unknown): value is AgentSummary {
  return isRecord(value) &&
    isString(value.agent_id) &&
    isFiniteNumber(value.session_count) &&
    isFiniteNumber(value.tool_call_count) &&
    isNullableNumber(value.last_seen);
}

function isSessionSummary(value: unknown): value is SessionSummary {
  return isRecord(value) &&
    isString(value.session_id) &&
    isString(value.agent_id) &&
    isFiniteNumber(value.started_at) &&
    isNullableNumber(value.ended_at) &&
    isFiniteNumber(value.call_count) &&
    isString(value.risk_level) &&
    isNullableNumber(value.risk_score) &&
    isString(value.assessment_status);
}

function isSessionList(value: unknown): value is SessionSummary[] {
  return Array.isArray(value) && value.every(isSessionSummary);
}

function isToolCall(value: unknown): value is ToolCall {
  return isRecord(value) &&
    isFiniteNumber(value.id) &&
    isString(value.session_id) &&
    isFiniteNumber(value.sequence_num) &&
    isString(value.tool_name) &&
    "arguments" in value &&
    isFiniteNumber(value.called_at) &&
    isNullableNumber(value.duration_ms) &&
    isFiniteNumber(value.is_error) &&
    (value.result_summary === null || isString(value.result_summary));
}

function isToolDefinitionEvent(value: unknown): value is ToolDefinitionEvent {
  return isRecord(value) &&
    isFiniteNumber(value.id) &&
    isString(value.session_id) &&
    isFiniteNumber(value.sequence_num) &&
    isString(value.event_type) &&
    isString(value.tool_name) &&
    isString(value.notification_method) &&
    "before_definition" in value &&
    "after_definition" in value &&
    "before_schema" in value &&
    "after_schema" in value &&
    isFiniteNumber(value.recorded_at) &&
    (value.called_at === undefined || isFiniteNumber(value.called_at));
}

function isSessionDetail(value: unknown): value is SessionDetailResponse {
  return isRecord(value) &&
    isRecord(value.session) &&
    isString(value.session.session_id) &&
    isString(value.session.agent_id) &&
    isFiniteNumber(value.session.started_at) &&
    isNullableNumber(value.session.ended_at) &&
    Array.isArray(value.calls) &&
    value.calls.every(isToolCall) &&
    Array.isArray(value.tool_definition_events) &&
    value.tool_definition_events.every(isToolDefinitionEvent);
}

function isPolicyViolation(value: unknown): value is SessionAssessment["policy_violations"][number] {
  return isRecord(value) &&
    isString(value.rule) &&
    isString(value.detail) &&
    isString(value.severity);
}

function isAssessmentChain(value: unknown): value is SessionAssessment["attack_chains"][number] {
  return isRecord(value) &&
    isString(value.chain_id) &&
    isString(value.severity) &&
    Array.isArray(value.call_indices) &&
    value.call_indices.every(isFiniteNumber) &&
    isString(value.description) &&
    isString(value.mitre_hint);
}

function isAssessmentEvidence(
  value: unknown,
): value is SessionAssessment["evidence"][number] {
  return isRecord(value) &&
    (value.kind === "tool_call" || value.kind === "tool_definition_change") &&
    isFiniteNumber(value.index) &&
    isFiniteNumber(value.sequence_num) &&
    isString(value.tool_name) &&
    isFiniteNumber(value.called_at);
}

function isContributingSignal(
  value: unknown,
): value is SessionAssessment["contributing_signals"][number] {
  return isRecord(value) &&
    (
      value.type === "policy_violation" ||
      value.type === "attack_chain" ||
      value.type === "baseline_deviation" ||
      value.type === "behavioral_anomaly"
    ) &&
    isString(value.signal) &&
    isString(value.severity) &&
    isString(value.detail) &&
    Array.isArray(value.evidence) &&
    value.evidence.every(isAssessmentEvidence);
}

function isFeatureContribution(
  value: unknown,
): value is SessionAssessment["feature_contributions"][number] {
  return isRecord(value) &&
    isString(value.feature) &&
    isFiniteNumber(value.value) &&
    isFiniteNumber(value.baseline_mean) &&
    isFiniteNumber(value.z_score);
}

function isSessionAssessment(value: unknown): value is SessionAssessment {
  return isRecord(value) &&
    isString(value.session_id) &&
    isString(value.agent_id) &&
    isString(value.assessment_status) &&
    isRecord(value.availability) &&
    typeof value.availability.ml_assessment === "boolean" &&
    (value.availability.reason === null || isString(value.availability.reason)) &&
    isString(value.risk_level) &&
    isNullableNumber(value.final_risk_score) &&
    isNullableNumber(value.ml_risk_score) &&
    Array.isArray(value.policy_violations) &&
    value.policy_violations.every(isPolicyViolation) &&
    Array.isArray(value.attack_chains) &&
    value.attack_chains.every(isAssessmentChain) &&
    Array.isArray(value.why_flagged) &&
    value.why_flagged.every(isString) &&
    Array.isArray(value.contributing_signals) &&
    value.contributing_signals.every(isContributingSignal) &&
    Array.isArray(value.evidence) &&
    value.evidence.every(isAssessmentEvidence) &&
    Array.isArray(value.feature_contributions) &&
    value.feature_contributions.every(isFeatureContribution);
}

function isDashboardOverview(value: unknown): value is DashboardOverview {
  return isRecord(value) &&
    isFiniteNumber(value.sessions_total) &&
    isFiniteNumber(value.tool_calls_total) &&
    isFiniteNumber(value.agents_total) &&
    isFiniteNumber(value.active_sessions) &&
    isFiniteNumber(value.tool_definition_changes) &&
    isString(value.metrics_note);
}

function isActivityList(value: unknown): value is ActivityItem[] {
  return Array.isArray(value) && value.every((item) =>
    isRecord(item) &&
    isString(item.event_type) &&
    isFiniteNumber(item.id) &&
    isString(item.session_id) &&
    isFiniteNumber(item.sequence_num) &&
    isString(item.tool_name) &&
    isFiniteNumber(item.called_at),
  );
}

function isRiskDistribution(value: unknown): value is RiskDistribution {
  const levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "UNASSESSED"];
  if (!isRecord(value) || !isFiniteNumber(value.total_sessions)) return false;
  const distribution = value.distribution;
  return isRecord(distribution) &&
    levels.every((level) => isFiniteNumber(distribution[level]));
}

function isAttackChainList(value: unknown): value is AttackChainFinding[] {
  return Array.isArray(value) && value.every((finding) =>
    isRecord(finding) &&
    isString(finding.session_id) &&
    isString(finding.agent_id) &&
    isString(finding.chain_id) &&
    isString(finding.severity) &&
    Array.isArray(finding.call_indices) &&
    finding.call_indices.every(isFiniteNumber) &&
    isString(finding.description) &&
    isString(finding.mitre_hint),
  );
}

function isMcpServersResponse(value: unknown): value is McpServersResponse {
  return isRecord(value) &&
    typeof value.available === "boolean" &&
    (value.status === "unavailable" || value.status === "empty" || value.status === "available") &&
    value.available === (value.status === "available") &&
    Array.isArray(value.servers) &&
    value.servers.every(isMcpServerInventoryItem) &&
    (value.status !== "available" || value.servers.length > 0) &&
    (value.status === "available" || value.servers.length === 0) &&
    (value.reason === undefined || isString(value.reason));
}

function isMcpServerInventoryItem(value: unknown): value is McpServerInventoryItem {
  return isRecord(value) &&
    isString(value.server_id) &&
    isString(value.server_name) &&
    isString(value.transport) &&
    isFiniteNumber(value.first_seen) &&
    isFiniteNumber(value.last_seen) &&
    isFiniteNumber(value.connection_count) &&
    (value.connection_status === "connected" || value.connection_status === "disconnected") &&
    Array.isArray(value.agents) &&
    value.agents.every((agent) =>
      isRecord(agent) && isString(agent.agent_id) && isFiniteNumber(agent.connection_count),
    ) &&
    Array.isArray(value.sessions) &&
    value.sessions.every((session) =>
      isRecord(session) &&
      isString(session.session_id) &&
      isString(session.agent_id) &&
      isFiniteNumber(session.connected_at) &&
      isNullableNumber(session.disconnected_at) &&
      (session.connection_status === "connected" || session.connection_status === "disconnected"),
    );
}

function isToolDefinitionEventList(value: unknown): value is ToolDefinitionEvent[] {
  return Array.isArray(value) && value.every(isToolDefinitionEvent);
}

async function getJson<T>(path: string, isPayload: PayloadGuard<T>): Promise<T> {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
    credentials: "include",
  });

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new ApiError("The API returned an invalid JSON response.", response.status);
  }

  if (!response.ok) {
    const message =
      typeof payload === "object" &&
      payload !== null &&
      "error" in payload &&
      typeof payload.error === "string"
        ? payload.error
        : `The API request failed with status ${response.status}.`;
    throw new ApiError(message, response.status);
  }

  if (!isPayload(payload)) {
    throw new ApiError("The API returned data in an unexpected format.", response.status);
  }
  return payload;
}

async function postJson<T>(
  path: string,
  body: Record<string, unknown>,
  isPayload: PayloadGuard<T>,
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
    "Content-Type": "application/json",
  };
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const response = await fetch(path, {
    method: "POST",
    credentials: "include",
    headers,
    body: JSON.stringify(body),
  });
  const payload: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const message = isRecord(payload) && isString(payload.error)
      ? payload.error
      : `The API request failed with status ${response.status}.`;
    throw new ApiError(message, response.status);
  }
  if (!isPayload(payload)) {
    throw new ApiError("The API returned data in an unexpected format.", response.status);
  }
  if (isRecord(payload) && isString(payload.csrf_token)) {
    csrfToken = payload.csrf_token;
  }
  return payload;
}

function withQuery(path: string, params: Record<string, string | number | undefined>): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined) query.set(key, String(value));
  }
  const search = query.toString();
  return search ? `${path}?${search}` : path;
}

export const api = {
  health: () => getJson<HealthResponse>("/api/health", isHealthResponse),
  authStatus: async () => {
    const status = await getJson<AuthStatusResponse>("/api/auth/status", isAuthStatusResponse);
    csrfToken = status.csrf_token;
    return status;
  },
  signup: (input: { name: string; email: string; password: string }) =>
    postJson<AuthResult>("/api/auth/signup", input, isAuthResult),
  login: (input: { email: string; password: string }) =>
    postJson<AuthResult>("/api/auth/login", input, isAuthResult),
  logout: async () => {
    await postJson<{ logged_out: boolean }>(
      "/api/auth/logout",
      {},
      (value): value is { logged_out: boolean } =>
        isRecord(value) && value.logged_out === true,
    );
    csrfToken = null;
  },
  verifyAuth: () =>
    getJson<{ authenticated: boolean; user?: unknown }>(
      "/api/auth/verify",
      (value): value is { authenticated: boolean; user?: unknown } =>
        isRecord(value) && value.authenticated === true,
    ),
  demo: () => getJson<DemoData>("/api/demo", isDemoData),
  loadDemo: (input: { scenario_id?: string } = {}) =>
    postJson<DemoData>("/api/demo/load", input, isDemoData),
  resetDemo: (runId: string) =>
    postJson<DemoData>("/api/demo/reset", { run_id: runId }, isDemoData),
  reviewDemoSession: (
    runId: string,
    sessionId: string,
    input: {
      decision: "approved" | "rejected";
      reviewer: string;
      note: string;
      confirm_reviewed: true;
    },
  ) =>
    postJson<DemoReviewResult>(
      `/api/demo/runs/${encodeURIComponent(runId)}/sessions/${encodeURIComponent(sessionId)}/review`,
      input,
      isDemoReviewResult,
    ),
  agents: () => getJson<AgentSummary[]>("/api/agents", (value): value is AgentSummary[] =>
    Array.isArray(value) && value.every(isAgentSummary),
  ),
  sessions: (options: { agentId?: string; limit?: number } = {}) =>
    getJson<SessionSummary[]>(
      withQuery("/api/sessions", {
        agent_id: options.agentId,
        limit: options.limit,
      }),
      isSessionList,
    ),
  session: (sessionId: string) =>
    getJson<SessionDetailResponse>(
      `/api/sessions/${encodeURIComponent(sessionId)}`,
      isSessionDetail,
    ),
  assessment: (sessionId: string) =>
    getJson<SessionAssessment>(
      `/api/sessions/${encodeURIComponent(sessionId)}/assessment`,
      isSessionAssessment,
    ),
  overview: () => getJson<DashboardOverview>("/api/dashboard/overview", isDashboardOverview),
  activity: (limit = 50) =>
    getJson<ActivityItem[]>(withQuery("/api/dashboard/activity", { limit }), isActivityList),
  riskDistribution: () =>
    getJson<RiskDistribution>("/api/dashboard/risk-distribution", isRiskDistribution),
  attackChains: () =>
    getJson<AttackChainFinding[]>("/api/dashboard/attack-chains", isAttackChainList),
  mcpServers: () => getJson<McpServersResponse>("/api/mcp/servers", isMcpServersResponse),
  toolChanges: () =>
    getJson<ToolDefinitionEvent[]>("/api/mcp/tool-changes", isToolDefinitionEventList),
  reviewSession: async (sessionId: string, input: { decision: "approved" | "rejected"; reviewer: string; note: string; confirm_reviewed: true }) => {
    const response = await fetch(`/api/sessions/${encodeURIComponent(sessionId)}/review`, {
      method: "POST",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
      },
      credentials: "include",
      body: JSON.stringify(input),
    });
    const payload: unknown = await response.json().catch(() => null);
    if (!response.ok) {
      const message = isRecord(payload) && isString(payload.error) ? payload.error : `Review failed (${response.status}).`;
      throw new ApiError(message, response.status);
    }
    return payload;
  },
};
