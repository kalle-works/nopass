"use client";

import { Clock, FileText, Globe, KeyRound, Search } from "lucide-react";
import { Badge, Kbd, SecretRow } from "@nopass/ui";
import { copySecret } from "@/components/auth/clipboard";

const ITEMS = [
  { icon: Globe, title: "GitHub", subtitle: "kalle@example.com", selected: true },
  { icon: KeyRound, title: "OpenAI API key", subtitle: "sk-proj-7f3a…" },
  { icon: Clock, title: "AWS root", subtitle: "root@example.com", badge: "TOTP" },
  { icon: KeyRound, title: "Postgres production", subtitle: "db.internal:5432" },
  { icon: FileText, title: "Deploy runbook", subtitle: "Note" },
];

/**
 * The vault as it looks after unlocking, built from the same primitives the app uses.
 * The data is made up.
 */
export function VaultMock() {
  return (
    <div
      role="group"
      aria-label="Example vault with sample data"
      className="grid overflow-hidden rounded-lg border border-border bg-surface sm:grid-cols-[216px_1fr]"
    >
      <div className="hidden border-r border-divider bg-bg-subtle sm:block">
        <div className="flex h-11 items-center gap-2 border-b border-divider px-3 text-meta text-faint">
          <Search aria-hidden className="size-4 text-icon" />
          <span className="flex-1">Search</span>
          <Kbd>/</Kbd>
        </div>
        <ul>
          {ITEMS.map(({ icon: Icon, title, subtitle, selected, badge }) => (
            <li
              key={title}
              aria-current={selected || undefined}
              className={`relative flex h-[52px] items-center gap-2.5 px-3 ${selected ? "bg-accent-subtle" : ""}`}
            >
              {selected && <span aria-hidden className="absolute inset-y-0 left-0 w-0.5 bg-accent" />}
              <Icon aria-hidden className="size-4 shrink-0 text-icon" />
              <div className="min-w-0 flex-1">
                <p className="truncate text-ui font-medium text-fg">{title}</p>
                <p className="truncate text-meta text-muted">{subtitle}</p>
              </div>
              {badge && <Badge>{badge}</Badge>}
            </li>
          ))}
        </ul>
      </div>

      <div>
        <div className="flex h-11 items-center justify-between gap-2 border-b border-divider px-4">
          <div className="flex min-w-0 items-baseline gap-2">
            <h3 className="text-h3 font-semibold text-fg">GitHub</h3>
            <span className="truncate font-mono text-mono-sm text-muted">github.com</span>
          </div>
          <Badge>TOTP</Badge>
        </div>
        <SecretRow label="Username" value="kalle@example.com" copy={copySecret} />
        <SecretRow label="Password" value="Zq7!mR2#vL9x" concealed copy={copySecret} warning="Reused on 3 other items" />
        <SecretRow
          label="One-time code"
          value="482913"
          mono
          copy={copySecret}
          trailing={<span className="px-1 font-mono text-mono-sm text-muted">18s</span>}
        />
        <SecretRow label="Website" value="https://github.com/login" mono copy={copySecret} />
      </div>
    </div>
  );
}
