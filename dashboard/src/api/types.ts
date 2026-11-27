export type RiskLevel =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL"
  | "UNASSESSED";

export interface ApiErrorResponse {
  error: string;
}

export interface HealthResponse {
  status: "ok" | "unavailable";
  database: "connected" | "unavailable" | "schema_unavailable";
}

export interface AuthUser {
  id: number;
  name: string;
  email: string;
}

export interface AuthStatusResponse {
  required: boolean;
  authenticated: boolean;
  user: AuthUser | null;
  csrf_token: string;
}

export interface AuthResult {
  authenticated: true;
  user: AuthUser;
  csrf_token: string;
}

export interface DemoScenarioInfo {
  id: string;
  name: string;
  agent_id: string;
  description: string;
  event_count: number;
  classification: "SIMULATED";
}

export interface DemoSession {
  scenario_id: string;
  scenario_name: string;
  description: string;
  agent_id: string;
  session: SessionRecord;
  calls: ToolCall[];
  assessment: SessionAssessment;
  review: SessionReviewStatus;
  classification: "SIMULATED";
}

export interface DemoAlert {
  alert_id: string;
  run_id: string;
  scenario_id: string;
  scenario_name: string;
  agent_id: string;
  session_id: string;
  risk_level: string;
  risk_score: number | null;
  why_flagged: string[];
  contributing_signals: ContributingSignal[];
  classification: "SIMULATED";
}

export interface DemoMetrics {
  sessions_total: number;
  tool_calls_total: number;
  agents_total: number;
  alerts_total: number;
}

export interface DemoData {
  enabled: boolean;
  classification: "SIMULATED";
  model_disclosure: string;
  scenarios: DemoScenarioInfo[];
  active_run: {
    run_id: string;
    created_at: number;
    scenarios: DemoSession[];
  } | null;
  metrics: DemoMetrics;
  alerts: DemoAlert[];
}

export interface DemoReviewResult {
  session_id: string;
  agent_id: string;
  decision: "approved" | "rejected";
  reviewer: string;
  reviewed_at: number;
  evidence_sha256: string;
}

export interface AgentSummary {
  agent_id: string;
  session_count: number;
  tool_call_count: number;
  last_seen: number | null;
}

export interface SessionSummary {
  session_id: string;
  agent_id: string;
  started_at: number;
  ended_at: number | null;
  call_count: number;
  risk_level: RiskLevel | string;
  risk_score: number | null;
  assessment_status: string;
}

export interface SessionRecord {
  session_id: string;
  agent_id: string;
  started_at: number;
  ended_at: number | null;
}

export interface ToolCall {
  id: number;
  session_id: string;
  sequence_num: number;
  tool_name: string;
  arguments: unknown;
  called_at: number;
  duration_ms: number | null;
  is_error: number;
  result_summary: string | null;
}

export interface ToolDefinitionEvent {
  id: number;
  session_id: string;
  sequence_num: number;
  event_type: string;
  tool_name: string;
  notification_method: string;
  before_definition: unknown;
  after_definition: unknown;
  before_schema: unknown;
  after_schema: unknown;
  recorded_at: number;
  called_at?: number;
}

export interface SessionReviewStatus {
  decision: "unreviewed" | "approved" | "rejected";
  reviewer: string | null;
  reviewed_at: number | null;
  review_note: string;
  evidence_current: boolean;
}

export interface SessionDetailResponse {
  session: SessionRecord;
  calls: ToolCall[];
  tool_definition_events: ToolDefinitionEvent[];
  review?: SessionReviewStatus;
}

export interface PolicyViolation {
  rule: string;
  detail: string;
  severity: string;
}

export interface AttackChain {
  chain_id: string;
  severity: string;
  call_indices: number[];
  description: string;
  mitre_hint: string;
}

export interface AssessmentAvailability {
  ml_assessment: boolean;
  reason: string | null;
}

export interface SessionAssessmentEvidence {
  kind: "tool_call" | "tool_definition_change";
  index: number;
  sequence_num: number;
  tool_name: string;
  called_at: number;
}

export interface ContributingSignal {
  type:
    | "policy_violation"
    | "attack_chain"
    | "baseline_deviation"
    | "behavioral_anomaly";
  signal: string;
  severity: string;
  detail: string;
  evidence: SessionAssessmentEvidence[];
}

export interface FeatureContribution {
  feature: string;
  value: number;
  baseline_mean: number;
  z_score: number;
}

export interface SessionAssessment {
  session_id: string;
  agent_id: string;
  assessment_status: string;
  availability: AssessmentAvailability;
  risk_level: RiskLevel | string;
  final_risk_score: number | null;
  ml_risk_score: number | null;
  policy_violations: PolicyViolation[];
  attack_chains: AttackChain[];
  why_flagged: string[];
  contributing_signals: ContributingSignal[];
  evidence: SessionAssessmentEvidence[];
  feature_contributions: FeatureContribution[];
}

export interface DashboardOverview {
  sessions_total: number;
  tool_calls_total: number;
  agents_total: number;
  active_sessions: number;
  tool_definition_changes: number;
  metrics_note: string;
}

export interface ToolCallActivity {
  event_type: "tool_call";
  id: number;
  session_id: string;
  sequence_num: number;
  tool_name: string;
  called_at: number;
  duration_ms: number | null;
  is_error: number;
  result_summary: string | null;
}

export interface ToolDefinitionActivity extends ToolDefinitionEvent {
  called_at: number;
}

export type ActivityItem = ToolCallActivity | ToolDefinitionActivity;

export interface RiskDistribution {
  distribution: Record<RiskLevel, number>;
  total_sessions: number;
}

export interface AttackChainFinding extends AttackChain {
  session_id: string;
  agent_id: string;
}

export interface McpServerSession {
  session_id: string;
  agent_id: string;
  connected_at: number;
  disconnected_at: number | null;
  connection_status: "connected" | "disconnected";
}

export interface McpServerAgent {
  agent_id: string;
  connection_count: number;
}

export interface McpServerInventoryItem {
  server_id: string;
  server_name: string;
  transport: string;
  first_seen: number;
  last_seen: number;
  connection_count: number;
  connection_status: "connected" | "disconnected";
  agents: McpServerAgent[];
  sessions: McpServerSession[];
}

export interface McpServersResponse {
  available: boolean;
  status: "unavailable" | "empty" | "available";
  servers: McpServerInventoryItem[];
  reason?: string;
}
