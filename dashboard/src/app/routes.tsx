import { Navigate, Route, Routes } from "react-router-dom";
import {
  InvestigationsPage,
  McpPage,
  OverviewPage,
  SessionDetailPage,
  SessionsPage,
} from "./pages";

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<OverviewPage />} />
      <Route path="/sessions" element={<SessionsPage />} />
      <Route path="/sessions/:sessionId" element={<SessionDetailPage />} />
      <Route path="/investigations" element={<InvestigationsPage />} />
      <Route path="/mcp" element={<McpPage />} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  );
}
