import { Component, type ErrorInfo, type ReactNode } from "react";

interface RenderErrorBoundaryProps {
  children: ReactNode;
  fallback: ReactNode;
}

interface RenderErrorBoundaryState {
  hasError: boolean;
}

export class RenderErrorBoundary extends Component<
  RenderErrorBoundaryProps,
  RenderErrorBoundaryState
> {
  state: RenderErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): RenderErrorBoundaryState {
    return { hasError: true };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Dashboard component failed to render", error, info.componentStack);
  }

  render() {
    return this.state.hasError ? this.props.fallback : this.props.children;
  }
}
