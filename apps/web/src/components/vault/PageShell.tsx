"use client";

import type { ReactNode } from "react";
import { Menu } from "lucide-react";
import { IconButton } from "@nopass/ui";
import { useVault } from "./vault-context";

/** Single-column settings page: title, one sentence, then content (max 760px). */
export function PageShell({
  title,
  description,
  actions,
  children,
}: {
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  const { setDrawerOpen } = useVault();
  return (
    <div className="min-w-0 flex-1 overflow-y-auto">
      <div className="mx-auto w-full max-w-[760px] px-4 py-6 md:px-6 md:py-8">
        <div className="mb-6 flex items-start gap-3">
          <IconButton label="Open navigation" onClick={() => setDrawerOpen(true)} className="-ml-2 md:hidden">
            <Menu aria-hidden className="size-4" />
          </IconButton>
          <div className="min-w-0 flex-1">
            <h1 className="text-h1 font-semibold text-fg">{title}</h1>
            {description && <p className="mt-1 max-w-prose text-ui text-muted">{description}</p>}
          </div>
          {actions}
        </div>
        {children}
      </div>
    </div>
  );
}

/** Tailscale-style table shell: header row, 44px rows, divider lines. */
export function DataTable({ children, label }: { children: ReactNode; label: string }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-divider bg-surface">
      <table aria-label={label} className="w-full min-w-[560px] border-collapse text-left text-ui">
        {children}
      </table>
    </div>
  );
}

export const TH = "h-9 border-b border-divider px-4 text-meta font-medium text-muted";
export const TD = "h-11 border-b border-divider px-4 align-middle";
export const TBODY = "[&>tr:last-child>td]:border-b-0";

/** Relative time with the exact timestamp on hover. */
export function RelativeTime({ iso, fallback = "Never" }: { iso: string | null; fallback?: string }) {
  if (!iso) return <span className="text-muted">{fallback}</span>;
  return (
    <time dateTime={iso} title={new Date(iso).toLocaleString()} className="text-muted">
      {timeAgo(iso)}
    </time>
  );
}

export function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const minutes = Math.floor(diff / 60_000);
  const hours = Math.floor(diff / 3_600_000);
  const days = Math.floor(diff / 86_400_000);
  if (minutes < 1) return "Just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 30) return `${days}d ago`;
  return new Date(iso).toLocaleDateString();
}
