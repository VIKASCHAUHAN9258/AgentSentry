import { AlertTriangle, Orbit } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import type { AttackChainFinding, SessionSummary } from "../../api/types";
import type {
  NetworkTopologyController,
  NetworkTopologyNode,
} from "./NetworkTopologyScene";

interface NetworkTopologyProps {
  sessions: SessionSummary[];
  findings: AttackChainFinding[];
}

function nodePosition(index: number, count: number): [number, number, number] {
  const goldenAngle = Math.PI * (3 - Math.sqrt(5));
  const y = 1 - ((index + 0.5) / count) * 2;
  const radius = Math.sqrt(Math.max(0, 1 - y * y));
  const angle = goldenAngle * index;
  return [
    Math.cos(angle) * radius * 2.05,
    y * 1.5,
    Math.sin(angle) * radius * 2.05,
  ];
}

function displayTime(timestamp: number): string {
  if (!Number.isFinite(timestamp)) return "Time unavailable";
  return new Date(timestamp * 1000).toLocaleString();
}

export function NetworkTopology({ sessions, findings }: NetworkTopologyProps) {
  const hostRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const [hoveredSession, setHoveredSession] = useState<SessionSummary | null>(null);
  const [webglUnavailable, setWebglUnavailable] = useState(false);
  const [sceneLoading, setSceneLoading] = useState(true);

  const nodes = useMemo<NetworkTopologyNode[]>(() => {
    const mostSevereBySession = new Map<string, string>();
    for (const finding of findings) {
      const current = mostSevereBySession.get(finding.session_id);
      if (finding.severity === "CRITICAL" || (!current && finding.severity === "HIGH")) {
        mostSevereBySession.set(finding.session_id, finding.severity);
      }
    }

    return sessions.slice(0, 28).map((session, index, visibleSessions) => ({
      session,
      position: nodePosition(index, visibleSessions.length),
      severity: mostSevereBySession.get(session.session_id) ?? null,
    }));
  }, [findings, sessions]);
  const nodesRef = useRef(nodes);
  const controllerRef = useRef<NetworkTopologyController | null>(null);
  const handlersRef = useRef({
    onHover: setHoveredSession,
    onSelect: (session: SessionSummary) =>
      navigate(`/sessions/${encodeURIComponent(session.session_id)}`),
  });
  nodesRef.current = nodes;
  handlersRef.current = {
    onHover: setHoveredSession,
    onSelect: (session) =>
      navigate(`/sessions/${encodeURIComponent(session.session_id)}`),
  };

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;

    let cancelled = false;
    void import("./NetworkTopologyScene")
      .then(({ mountNetworkTopology }) => {
        if (cancelled) return;
        try {
          const controller = mountNetworkTopology(
            host,
            nodesRef.current,
            (session) => handlersRef.current.onHover(session),
            (session) => handlersRef.current.onSelect(session),
          );
          controllerRef.current = controller;
          setWebglUnavailable(false);
        } catch (error) {
          console.error("Failed to initialize the network topology scene.", error);
          setWebglUnavailable(true);
        } finally {
          setSceneLoading(false);
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          console.error("Failed to load the network topology scene.", error);
          setWebglUnavailable(true);
          setSceneLoading(false);
        }
      });

    return () => {
      cancelled = true;
      controllerRef.current?.dispose();
      controllerRef.current = null;
    };
  }, []);

  useEffect(() => {
    controllerRef.current?.updateNodes(nodes);
  }, [nodes]);

  return (
    <div className={`soc-topology as-topology${sessions.length === 0 ? " is-empty" : ""}`}>
      <div className="as-topology-canvas" ref={hostRef} />
      {sceneLoading && (
        <div className="as-topology-message" role="status">
          Loading interactive topology.
        </div>
      )}
      <div className="as-topology-core-label" aria-hidden="true">
        <span className="as-core-shield"><Orbit size={25} /></span>
        <strong>AgentSentry Core</strong>
        <small>RUNTIME SECURITY</small>
      </div>
      {webglUnavailable && (
        <div className="as-topology-message" role="status">
          <AlertTriangle size={15} aria-hidden="true" />
          3D rendering unavailable in this browser.
        </div>
      )}
      {sessions.length === 0 && !webglUnavailable && (
        <div className="as-topology-empty-note">
          <strong>No session telemetry</strong>
          <span>
            Observed agent and tool relationships will appear here when the monitored proxy records activity.
          </span>
        </div>
      )}
      {hoveredSession && (
        <div className="as-topology-tooltip" role="status">
          <strong>{hoveredSession.agent_id}</strong>
          <span>{hoveredSession.session_id}</span>
          <small>{hoveredSession.risk_level} · {displayTime(hoveredSession.started_at)}</small>
        </div>
      )}
      <div className="as-topology-hint">
        Drag to rotate <i /> Scroll to zoom <i /> Select a session node to investigate
      </div>
      {sessions.length > nodes.length && (
        <div className="as-topology-limit">
          Showing {nodes.length} of {sessions.length} returned sessions
        </div>
      )}
    </div>
  );
}
