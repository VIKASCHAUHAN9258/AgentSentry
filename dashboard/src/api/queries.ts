import { useQuery } from "@tanstack/react-query";
import { api } from "./client";

export const queryKeys = {
  health: ["health"] as const,
  agents: ["agents"] as const,
  sessions: (agentId?: string, limit?: number) =>
    ["sessions", { agentId, limit }] as const,
  session: (sessionId: string) => ["session", sessionId] as const,
  assessment: (sessionId: string) => ["assessment", sessionId] as const,
  overview: ["dashboard", "overview"] as const,
  activity: (limit: number) => ["dashboard", "activity", limit] as const,
  riskDistribution: ["dashboard", "risk-distribution"] as const,
  attackChains: ["dashboard", "attack-chains"] as const,
  mcpServers: ["mcp", "servers"] as const,
  toolChanges: ["mcp", "tool-changes"] as const,
};

export const useHealth = () =>
  useQuery({ queryKey: queryKeys.health, queryFn: api.health, retry: 0 });

export const useAgents = () =>
  useQuery({ queryKey: queryKeys.agents, queryFn: api.agents });

export const useSessions = (options: { agentId?: string; limit?: number } = {}) =>
  useQuery({
    queryKey: queryKeys.sessions(options.agentId, options.limit),
    queryFn: () => api.sessions(options),
  });

export const useSession = (sessionId: string) =>
  useQuery({
    queryKey: queryKeys.session(sessionId),
    queryFn: () => api.session(sessionId),
    enabled: sessionId.length > 0,
  });

export const useSessionAssessment = (sessionId: string) =>
  useQuery({
    queryKey: queryKeys.assessment(sessionId),
    queryFn: () => api.assessment(sessionId),
    enabled: sessionId.length > 0,
  });

export const useDashboardOverview = () =>
  useQuery({ queryKey: queryKeys.overview, queryFn: api.overview });

export const useDashboardActivity = (limit = 50) =>
  useQuery({
    queryKey: queryKeys.activity(limit),
    queryFn: () => api.activity(limit),
  });

export const useRiskDistribution = () =>
  useQuery({ queryKey: queryKeys.riskDistribution, queryFn: api.riskDistribution });

export const useAttackChains = () =>
  useQuery({ queryKey: queryKeys.attackChains, queryFn: api.attackChains });

export const useMcpServers = () =>
  useQuery({ queryKey: queryKeys.mcpServers, queryFn: api.mcpServers });

export const useToolChanges = () =>
  useQuery({ queryKey: queryKeys.toolChanges, queryFn: api.toolChanges });
