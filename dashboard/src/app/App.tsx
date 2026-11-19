import {
  Activity,
  Boxes,
  ChevronDown,
  Command,
  FileSearch,
  LayoutDashboard,
  Menu,
  RadioTower,
  RefreshCw,
  Search,
  ShieldCheck,
  LockKeyhole,
  X,
} from "lucide-react";
import { useState, type FormEvent, type ReactNode } from "react";
import { NavLink, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError, setApiKey } from "../api/client";
import { useHealth } from "../api/queries";
import { AppRoutes } from "./routes";

const navigation = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/sessions", label: "Agent sessions", icon: RadioTower },
  { to: "/investigations", label: "Investigations", icon: FileSearch },
  { to: "/mcp", label: "MCP security", icon: Boxes },
];

const pageTitles: Record<string, string> = {
  "/": "Incident Management",
  "/sessions": "Agent sessions",
  "/investigations": "Investigations",
  "/mcp": "MCP security",
};

function ApiStatus() {
  const query = useHealth();
  const connected = query.data?.status === "ok" && query.data.database === "connected";
  const label = query.isLoading
    ? "Checking API"
    : query.error
      ? "API unavailable"
      : connected
        ? "API connected"
        : "API unavailable";

  return (
    <span className={`as-status${connected ? " is-online" : ""}`} role="status" aria-live="polite">
      <i />
      {label}
    </span>
  );
}

function Brand({ children }: { children?: ReactNode }) {
  return (
    <div className="as-brand-row">
      <NavLink className="as-brand" to="/" aria-label="AgentSentry overview">
        <span className="as-brand-symbol"><ShieldCheck size={23} /></span>
        <span>
          <strong>AgentSentry</strong>
          <small>SECURITY OPERATIONS</small>
        </span>
      </NavLink>
      {children}
    </div>
  );
}

export function App() {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [commandSearch, setCommandSearch] = useState("");
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [authenticated, setAuthenticated] = useState(false);
  const [authError, setAuthError] = useState("");
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const queryClient = useQueryClient();
  const authStatus = useQuery({
    queryKey: ["auth", "status"],
    queryFn: api.authStatus,
    retry: 0,
  });
  const authRequired = authStatus.data?.required ?? true;
  const pageTitle =
    location.pathname.startsWith("/sessions/") && location.pathname !== "/sessions"
      ? "Session investigation"
      : pageTitles[location.pathname] ?? "Incident Management";

  const submitSearch = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const params = new URLSearchParams();
    if (commandSearch.trim()) params.set("search", commandSearch.trim());
    const query = params.toString();
    navigate(query ? `/sessions?${query}` : "/sessions");
  };

  const changeRiskFilter = (risk: string) => {
    const params = new URLSearchParams();
    if (risk !== "ALL") params.set("risk", risk);
    const query = params.toString();
    navigate(query ? `/sessions?${query}` : "/sessions");
  };

  const submitApiKey = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setAuthError("");
    setApiKey(apiKeyInput);
    try {
      await api.verifyAuth();
      setApiKeyInput("");
      setAuthenticated(true);
      queryClient.clear();
    } catch (error) {
      setApiKey(null);
      setAuthenticated(false);
      setAuthError(
        error instanceof ApiError && error.status === 401
          ? "The API key was not accepted."
          : error instanceof Error
            ? error.message
            : "Unable to verify API access.",
      );
    }
  };

  const lockDashboard = () => {
    setApiKey(null);
    setAuthenticated(false);
    setApiKeyInput("");
    queryClient.clear();
  };

  const showDashboard = !authRequired || authenticated;

  return (
    <div className="as-shell">
      {mobileOpen && (
        <button
          className="as-scrim"
          aria-label="Close navigation"
          onClick={() => setMobileOpen(false)}
          type="button"
        />
      )}
      <aside className={`as-sidebar${mobileOpen ? " is-open" : ""}`}>
        <Brand>
          <button
            className="as-mobile-close"
            aria-label="Close navigation"
            onClick={() => setMobileOpen(false)}
            type="button"
          >
            <X size={18} />
          </button>
        </Brand>
        <div className="as-workspace">
          <span><Command size={16} /></span>
          <div><strong>Local workspace</strong><small>Private environment</small></div>
          <ChevronDown size={14} aria-hidden="true" />
        </div>
        <div className="as-nav-label">WORKSPACE</div>
        <nav className="as-nav" aria-label="Primary navigation">
          {navigation.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              onClick={() => setMobileOpen(false)}
              className={({ isActive }) => `as-nav-link${isActive ? " active" : ""}`}
            >
              <Icon size={18} aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="as-sidebar-spacer" />
        <div className="as-system-card">
          <div>
            <span className="as-system-icon"><Activity size={15} /></span>
            <span><strong>Telemetry API</strong><small><ApiStatus /></small></span>
          </div>
          <div>
            <span className="as-system-icon"><Boxes size={15} /></span>
            <span><strong>Database status</strong><small>Reported by API health</small></span>
          </div>
        </div>
        <div className="as-sidebar-footer">AGENTSENTRY · READ-ONLY TELEMETRY</div>
      </aside>

      <main className="as-main">
        <header className="as-topbar">
          <button
            className="as-mobile-menu"
            aria-label="Open navigation"
            onClick={() => setMobileOpen(true)}
            type="button"
          >
            <Menu size={20} />
          </button>
          <div className="as-crumb">
            <span>AgentSentry</span>
            <b>/</b>
            <strong>{pageTitle}</strong>
          </div>
          <div className="as-commandbar">
            <form className="as-command-search" onSubmit={submitSearch} role="search">
              <Search size={14} aria-hidden="true" />
              <label className="sr-only" htmlFor="global-session-search">
                Search sessions or agents
              </label>
              <input
                id="global-session-search"
                onChange={(event) => setCommandSearch(event.currentTarget.value)}
                placeholder="Search sessions or agents"
                value={commandSearch}
              />
            </form>
            <label className="sr-only" htmlFor="global-risk-filter">Filter sessions by risk</label>
            <select
              id="global-risk-filter"
              className="as-command-filter"
              value={searchParams.get("risk") ?? "ALL"}
              onChange={(event) => changeRiskFilter(event.currentTarget.value)}
            >
              <option value="ALL">All risks</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
              <option value="UNASSESSED">Unassessed</option>
            </select>
            <button
              className="as-command-refresh"
              aria-label="Refresh dashboard data"
              onClick={() => void queryClient.invalidateQueries()}
              type="button"
            >
              <RefreshCw size={14} />
              <span>Refresh</span>
            </button>
            {authRequired && authenticated && (
              <button
                className="as-command-refresh"
                onClick={lockDashboard}
                type="button"
              >
                <LockKeyhole size={14} aria-hidden="true" />
                <span>Lock</span>
              </button>
            )}
          </div>
          <div className="as-topbar-right">
            <span className="as-console-label">LOCAL SECURITY CONSOLE</span>
            <ApiStatus />
          </div>
        </header>
        {authStatus.isPending ? (
          <section className="as-auth-gate" role="status">Checking API access…</section>
        ) : authStatus.error ? (
          <section className="as-auth-gate" role="alert">
            <h1>API unavailable</h1>
            <p>{authStatus.error.message}</p>
            <button type="button" onClick={() => void authStatus.refetch()}>Retry</button>
          </section>
        ) : showDashboard ? (
          <AppRoutes />
        ) : (
          <section className="as-auth-gate">
            <form className="as-auth-card" onSubmit={(event) => void submitApiKey(event)}>
              <LockKeyhole size={24} aria-hidden="true" />
              <h1>Authenticate to AgentSentry</h1>
              <p>Enter the API key configured for the local AgentSentry service.</p>
              <label htmlFor="agentsentry-api-key">API key</label>
              <input
                autoComplete="off"
                autoCapitalize="none"
                id="agentsentry-api-key"
                onChange={(event) => setApiKeyInput(event.currentTarget.value)}
                type="password"
                value={apiKeyInput}
                required
              />
              {authError && <p className="as-auth-error" role="alert">{authError}</p>}
              <button type="submit" disabled={!apiKeyInput}>Connect</button>
              <small>The key is held in tab memory only and is not stored in the browser.</small>
            </form>
          </section>
        )}
        <footer className="as-footer">
          AGENTSENTRY <span>·</span> SECURITY OPERATIONS <span>·</span> READ-ONLY TELEMETRY
        </footer>
      </main>
    </div>
  );
}
