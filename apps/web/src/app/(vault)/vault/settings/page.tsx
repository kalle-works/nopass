"use client";

import { useEffect } from "react";
import { ChangePasswordForm, Kbd, useNopassStore } from "@nopass/ui";
import { PageShell, DataTable, TBODY, TD, TH } from "@/components/vault/PageShell";
import { api } from "@/lib/api";

const SHORTCUTS: Array<{ keys: string[]; action: string }> = [
  { keys: ["⌘", "K"], action: "Open the command palette" },
  { keys: ["⌘", "L"], action: "Lock the vault" },
  { keys: ["/"], action: "Search items" },
  { keys: ["N"], action: "New item" },
  { keys: ["↑", "↓"], action: "Move through the list" },
  { keys: ["↵"], action: "Open the selected item" },
  { keys: ["E"], action: "Edit the selected item" },
  { keys: ["C"], action: "Copy the main secret of the selected item" },
  { keys: ["U"], action: "Copy the username of the selected login" },
];

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mb-8">
      <h2 className="mb-3 text-h2 font-semibold text-fg">{title}</h2>
      {children}
    </section>
  );
}

export default function SettingsPage() {
  const { email } = useNopassStore();

  useEffect(() => {
    document.title = "Settings — nopwd";
  }, []);

  return (
    <PageShell title="Settings" description="Account details and keyboard shortcuts. The theme switch is at the bottom of the sidebar.">
      <Section title="Account">
        <dl className="divide-y divide-divider overflow-hidden rounded-lg border border-divider">
          <div className="flex min-h-11 items-center justify-between gap-4 px-4 py-2">
            <dt className="text-meta text-muted">Email</dt>
            <dd className="truncate font-mono text-mono-sm text-fg">{email}</dd>
          </div>
          <div className="flex min-h-11 items-center justify-between gap-4 px-4 py-2">
            <dt className="text-meta text-muted">Auto-lock</dt>
            <dd className="text-ui text-fg">After 15 minutes without activity</dd>
          </div>
          <div className="flex min-h-11 items-center justify-between gap-4 px-4 py-2">
            <dt className="text-meta text-muted">Clipboard</dt>
            <dd className="text-ui text-fg">Cleared 30 seconds after copying</dd>
          </div>
          <div className="flex min-h-11 items-center justify-between gap-4 px-4 py-2">
            <dt className="text-meta text-muted">Revealed secrets</dt>
            <dd className="text-ui text-fg">Hidden again after 30 seconds or when the window loses focus</dd>
          </div>
        </dl>
      </Section>

      <Section title="Master password">
        <ChangePasswordForm apiClient={api} />
      </Section>

      <Section title="Keyboard shortcuts">
        <DataTable label="Keyboard shortcuts">
          <thead>
            <tr>
              <th scope="col" className={TH}>Keys</th>
              <th scope="col" className={TH}>Action</th>
            </tr>
          </thead>
          <tbody className={TBODY}>
            {SHORTCUTS.map((s) => (
              <tr key={s.action}>
                <td className={TD}>
                  <span className="flex gap-1">
                    {s.keys.map((k) => (
                      <Kbd key={k}>{k}</Kbd>
                    ))}
                  </span>
                </td>
                <td className={`${TD} text-fg`}>{s.action}</td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      </Section>
    </PageShell>
  );
}
