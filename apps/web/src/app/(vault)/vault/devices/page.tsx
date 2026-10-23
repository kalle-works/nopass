"use client";

import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { Badge, Banner, Button, Dialog, EmptyState, IconButton, useNopassStore } from "@nopass/ui";
import type { DeviceInfo } from "@nopass/types";
import { api } from "@/lib/api";
import { DataTable, PageShell, RelativeTime, TBODY, TD, TH } from "@/components/vault/PageShell";
import { RowMenu } from "@/components/vault/RowMenu";

const DEVICE_TYPE_LABELS: Record<string, string> = {
  desktop_mac: "Mac",
  desktop_linux: "Linux",
  desktop_windows: "Windows",
  android: "Android",
  web: "Web",
  extension: "Browser extension",
};

export default function DevicesPage() {
  const { sessionToken } = useNopassStore();
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toRevoke, setToRevoke] = useState<DeviceInfo | null>(null);
  const [revoking, setRevoking] = useState(false);
  const [confirmSignOutOthers, setConfirmSignOutOthers] = useState(false);
  const [signingOut, setSigningOut] = useState(false);

  useEffect(() => {
    document.title = "Devices — nopwd";
  }, []);

  useEffect(() => {
    if (!sessionToken) return;
    let cancelled = false;
    (async () => {
      try {
        const list = await api.devices.list(sessionToken);
        if (!cancelled) setDevices(list);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load devices");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [sessionToken]);

  async function handleRevoke() {
    if (!sessionToken || !toRevoke) return;
    setRevoking(true);
    try {
      await api.devices.remove(toRevoke.id, sessionToken);
      setDevices((d) => d.filter((dev) => dev.id !== toRevoke.id));
      setToRevoke(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke device");
      setToRevoke(null);
    } finally {
      setRevoking(false);
    }
  }

  async function handleSignOutOthers() {
    if (!sessionToken) return;
    setSigningOut(true);
    try {
      await api.devices.signOutOthers(sessionToken);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to sign out other devices");
    } finally {
      setConfirmSignOutOthers(false);
      setSigningOut(false);
    }
  }

  return (
    <PageShell
      title="Devices"
      description="Devices that have signed in as you. Revoke any you don't recognize; that signs out all of its active sessions."
      actions={
        <Button variant="ghost" onClick={() => setConfirmSignOutOthers(true)}>
          Sign out all other devices
        </Button>
      }
    >
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
        <div aria-busy="true" aria-label="Loading devices" className="space-y-px overflow-hidden rounded-lg border border-divider">
          {[...Array(3)].map((_, i) => (
            <div key={i} className="h-11 animate-pulse bg-surface-hover" />
          ))}
        </div>
      ) : devices.length === 0 ? (
        <div className="rounded-lg border border-divider">
          <EmptyState
            title="No trusted devices."
            description="Devices are registered when you sign in from the CLI or the desktop app."
            action={
              <a
                href="nopass://open"
                className="inline-flex h-9 items-center rounded border border-border bg-surface px-3.5 text-ui font-medium text-fg transition-colors duration-[120ms] hover:border-border-strong hover:bg-surface-hover"
              >
                Open desktop app
              </a>
            }
          />
        </div>
      ) : (
        <DataTable label="Devices">
          <thead>
            <tr>
              <th scope="col" className={TH}>Name</th>
              <th scope="col" className={TH}>Platform</th>
              <th scope="col" className={TH}>Last active</th>
              <th scope="col" className={TH}>Added</th>
              <th scope="col" className={`${TH} w-12`}>
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody className={TBODY}>
            {devices.map((device) => (
              <tr key={device.id}>
                <td className={TD}>
                  <span className="font-medium text-fg">{device.deviceName}</span>
                </td>
                <td className={TD}>
                  <Badge>{DEVICE_TYPE_LABELS[device.deviceType] ?? device.deviceType}</Badge>
                </td>
                <td className={TD}>
                  <RelativeTime iso={device.lastSeenAt} />
                </td>
                <td className={TD}>
                  <RelativeTime iso={device.createdAt} />
                </td>
                <td className={`${TD} text-right`}>
                  <RowMenu
                    label={`Actions for ${device.deviceName}`}
                    actions={[{ label: "Revoke…", onSelect: () => setToRevoke(device) }]}
                  />
                </td>
              </tr>
            ))}
          </tbody>
        </DataTable>
      )}

      <Dialog
        open={toRevoke !== null}
        onClose={() => setToRevoke(null)}
        title={`Revoke “${toRevoke?.deviceName ?? ""}”?`}
        description="Every active session on this device is signed out. It has to authenticate again to get back in."
        footer={
          <>
            <Button variant="ghost" onClick={() => setToRevoke(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleRevoke} pending={revoking} pendingLabel="Revoking…">
              Revoke device
            </Button>
          </>
        }
      />

      <Dialog
        open={confirmSignOutOthers}
        onClose={() => setConfirmSignOutOthers(false)}
        title="Sign out all other devices?"
        description="Every session except this one ends. Other devices stay registered but have to authenticate again."
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirmSignOutOthers(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleSignOutOthers} pending={signingOut} pendingLabel="Signing out…">
              Sign out others
            </Button>
          </>
        }
      />
    </PageShell>
  );
}
