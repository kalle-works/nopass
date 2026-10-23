"use client";

import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { Badge, Banner, EmptyState, IconButton, useNopassStore } from "@nopass/ui";
import type { ActivityEventInfo, DeviceInfo } from "@nopass/types";
import { api } from "@/lib/api";
import { DataTable, PageShell, RelativeTime, TBODY, TD, TH } from "@/components/vault/PageShell";

/** Plain verbs for each event; `review` events get a visible word, not only a color. */
const EVENT_LABELS: Record<string, { label: string; review?: boolean }> = {
  login_succeeded: { label: "Signed in" },
  login_failed: { label: "Failed sign-in attempt", review: true },
  login_upgraded: { label: "Upgraded sign-in protection" },
  password_changed: { label: "Changed master password", review: true },
  recovery_kit_created: { label: "Created recovery kit" },
  recovery_kit_disabled: { label: "Disabled recovery", review: true },
  recovery_initiated: { label: "Used recovery code", review: true },
  recovery_completed: { label: "Recovered account and rotated master password", review: true },
  share_created: { label: "Created share link" },
  share_viewed: { label: "Opened share link" },
  share_revoked: { label: "Revoked share link" },
  device_registered: { label: "Registered new device", review: true },
  device_revoked: { label: "Revoked device" },
  vault_created: { label: "Created vault" },
  vault_deleted: { label: "Deleted vault" },
};

export default function ActivityPage() {
  const { sessionToken } = useNopassStore();
  const [events, setEvents] = useState<ActivityEventInfo[]>([]);
  const [devices, setDevices] = useState<Map<string, DeviceInfo>>(new Map());
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    document.title = "Activity — nopwd";
  }, []);

  useEffect(() => {
    if (!sessionToken) return;
    let cancelled = false;
    (async () => {
      try {
        const [list, deviceList] = await Promise.all([
          api.activity.list(sessionToken),
          api.devices.list(sessionToken).catch(() => [] as DeviceInfo[]),
        ]);
        if (cancelled) return;
        setEvents(list);
        setDevices(new Map(deviceList.map((d) => [d.id, d])));
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load activity");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [sessionToken]);

  return (
    <PageShell
      title="Activity"
      description="Security events on your account from the last 90 days."
    >
      <Banner className="mb-4" title="What the server can't see">
        It records that an event happened, not what it touched: item contents, and which secret you copied, are never
        logged.
      </Banner>

      {error && (
        <Banner
          tone="danger"
          className="mb-4"
          action={
            <IconButton label="Dismiss error" onClick={() => setError(null)} className="-my-1 -mr-2">
              <X aria-hidden className="size-4" />
            </IconButton>
          }
        >
          {error}
        </Banner>
      )}

      {loading ? (
        <div aria-busy="true" aria-label="Loading activity" className="space-y-px overflow-hidden rounded-lg border border-divider">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-11 animate-pulse bg-surface-hover" />
          ))}
        </div>
      ) : events.length === 0 ? (
        <div className="rounded-lg border border-divider">
          <EmptyState title="No activity recorded yet." />
        </div>
      ) : (
        <DataTable label="Account activity">
          <thead>
            <tr>
              <th scope="col" className={TH}>Event</th>
              <th scope="col" className={TH}>Device</th>
              <th scope="col" className={TH}>Source</th>
              <th scope="col" className={TH}>Time</th>
            </tr>
          </thead>
          <tbody className={TBODY}>
            {events.map((event) => {
              const meta = EVENT_LABELS[event.eventType] ?? { label: event.eventType.replace(/_/g, " ") };
              const device = event.deviceId ? devices.get(event.deviceId) : undefined;
              return (
                <tr key={event.id}>
                  <td className={TD}>
                    <span className="flex items-center gap-2">
                      <span className="font-medium text-fg">{meta.label}</span>
                      {meta.review && <Badge tone="warning">Review</Badge>}
                    </span>
                  </td>
                  <td className={`${TD} text-muted`}>{device?.deviceName ?? "—"}</td>
                  <td className={`${TD} font-mono text-mono-sm text-muted`}>{event.ip ?? "unknown"}</td>
                  <td className={TD}>
                    <RelativeTime iso={event.createdAt} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </DataTable>
      )}
    </PageShell>
  );
}
