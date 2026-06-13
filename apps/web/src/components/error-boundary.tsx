"use client";

import { Component, type ErrorInfo, type ReactNode } from "react";

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
          <div className="min-h-screen bg-[#070706] flex items-center justify-center p-8">
            <div className="max-w-md w-full border border-[#2B2923] p-6">
              <p className="font-mono text-xs text-[#E8321A] uppercase tracking-widest mb-3">
                Something went wrong
              </p>
              <p className="text-sm text-[#9C988D] font-mono break-words">
                {this.state.error.message}
              </p>
              <button
                onClick={() => this.setState({ error: null })}
                className="mt-4 font-mono text-xs text-[#9C988D] border border-[#2B2923] px-3 py-1.5 hover:text-[#F4F1E8] hover:border-[#9C988D] transition-colors"
              >
                Try again
              </button>
            </div>
          </div>
        )
      );
    }
    return this.props.children;
  }
}
