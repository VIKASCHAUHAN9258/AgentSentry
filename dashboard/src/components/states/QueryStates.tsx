import { AlertCircle, LoaderCircle, RadioTower } from "lucide-react";
import type { ReactNode } from "react";
import { ApiError } from "../../api/client";

interface StatePanelProps {
  title: string;
  children?: ReactNode;
}

export function LoadingState({ title = "Loading data" }: { title?: string }) {
  return (
    <div className="state-panel" role="status" aria-live="polite">
      <LoaderCircle className="state-icon is-spinning" aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        <p>Retrieving current telemetry from AgentSentry.</p>
      </div>
    </div>
  );
}

export function ErrorState({ error }: { error: unknown }) {
  const message = error instanceof Error ? error.message : "An unexpected error occurred.";
  return (
    <div className="state-panel state-panel--error" role="alert">
      <AlertCircle className="state-icon" aria-hidden="true" />
      <div>
        <strong>Unable to load data</strong>
        <p>{message}</p>
      </div>
    </div>
  );
}

export function EmptyState({ title, children }: StatePanelProps) {
  return (
    <div className="state-panel">
      <RadioTower className="state-icon" aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        {children && <p>{children}</p>}
      </div>
    </div>
  );
}

export function UnavailableState({ error }: { error: unknown }) {
  const message =
    error instanceof ApiError && error.status === 503
      ? "The API reports that its database or schema is unavailable."
      : error instanceof Error
        ? error.message
        : "The backend did not report this capability as available.";
  return (
    <div className="state-panel state-panel--unavailable" role="status">
      <RadioTower className="state-icon" aria-hidden="true" />
      <div>
        <strong>Backend unavailable</strong>
        <p>{message}</p>
      </div>
    </div>
  );
}
