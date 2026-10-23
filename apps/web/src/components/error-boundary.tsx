"use client";

import { Component, type ErrorInfo, type ReactNode } from "react";
import { Button } from "@nopass/ui";

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("[nopass] unhandled render error", {
      message: error.message,
      stack: error.stack,
      componentStack: info.componentStack,
    });
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        this.props.fallback ?? (
          <div className="flex min-h-screen items-center justify-center bg-bg p-6 text-fg">
            <div role="alert" className="w-full max-w-[400px]">
              <h1 className="text-h1 font-semibold text-fg">Something went wrong</h1>
              <p className="mt-2 text-body text-muted">
                This page hit an error. Try again, and reload the page if it keeps happening.
              </p>
              <p className="mt-4 break-words rounded border border-divider bg-surface-hover px-3 py-2 font-mono text-mono-sm text-muted">
                {this.state.error.message}
              </p>
              <Button className="mt-6" onClick={() => this.setState({ error: null })}>
                Try again
              </Button>
            </div>
          </div>
        )
      );
    }
    return this.props.children;
  }
}
