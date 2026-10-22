"use client";

import { useEffect, useState } from "react";
import { X } from "lucide-react";
import { Banner, Button, Dialog, EmptyState, IconButton, useNopassStore } from "@nopass/ui";
import { decryptBytes } from "@nopass/crypto";
import type { ShareInfo } from "@nopass/types";
import { api } from "@/lib/api";
import { DataTable, PageShell, RelativeTime, TBODY, TD, TH } from "@/components/vault/PageShell";
import { RowMenu } from "@/components/vault/RowMenu";

interface ShareRow extends ShareInfo {
  label: string;
}

function timeLeft(expiresAt: string): string {
  const ms = new Date(expiresAt).getTime() - Date.now();
  if (ms <= 0) return "Expired";
  const hours = Math.floor(ms / 3_600_000);
  if (hours >= 24) return `${Math.floor(hours / 24)}d left`;
  if (hours >= 1) return `${hours}h left`;
  return `${Math.max(1, Math.floor(ms / 60_000))}m left`;
}

export default function SharesPage() {
  const { sessionToken, vaultEncKey } = useNopassStore();
  const [shares, setShares] = useState<ShareRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [toRevoke, setToRevoke] = useState<ShareRow | null>(null);
  const [revoking, setRevoking] = useState(false);

  useEffect(() => {
    document.title = "Shared links — nopwd";
  }, []);

  useEffect(() => {
    if (!sessionToken || !vaultEncKey) return;
    let cancelled = false;
    (async () => {
      try {
        const list = await api.shares.list(sessionToken);
        const rows = await Promise.all(
          list.map(async (s) => {
            let label = "(unreadable label)";
            try {
              const bytes = await decryptBytes({ blob: s.labelBlob, blobIv: s.labelIv, blobMac: "" }, vaultEncKey);
              label = new TextDecoder().decode(bytes);
            } catch {
              // label was encrypted under an older vault key (e.g. pre-recovery)
            }
            return { ...s, label };
          }),
        );
        if (!cancelled) setShares(rows);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load shares");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [sessionToken, vaultEncKey]);

  async function handleRevoke() {
    if (!sessionToken || !toRevoke) return;
    setRevoking(true);
    try {
      await api.shares.revoke(toRevoke.id, sessionToken);
      setShares((s) => s.filter((row) => row.id !== toRevoke.id));
      setToRevoke(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke share");
      setToRevoke(null);
    } finally {
      setRevoking(false);
    }
  }

  return (
    <PageShell
      title="Shared links"
      description="Links you have created. Revoking one disables it immediately."
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
        <div aria-busy="true" aria-label="Loading shared links" className="space-y-px overflow-hidden rounded-lg border border-divider">
          {[...Array(2)].map((_, i) => (
            <div key={i} className="h-11 animate-pulse bg-surface-hover" />
          ))}
        </div>
      ) : shares.length === 0 ? (
        <div className="rounded-lg border border-divider">
          <EmptyState
            title="No active shared links."
            description="Open an item and choose Share to create a link that expires."
          />
        </div>
      ) : (
        <DataTable label="Shared links">
          <thead>
            <tr>
              <th scope="col" className={TH}>Item</th>
              <th scope="col" className={TH}>Views</th>
              <th scope="col" className={TH}>Expires</th>
              <th scope="col" className={TH}>Created</th>
              <th scope="col" className={`${TH} w-12`}>
                <span className="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody className={TBODY}>
            {shares.map((share) => (
              <tr key={share.id}>
                <td className={TD}>
                  <span className="font-medium text-fg">{share.label}</span>
                </td>
                <td className={`${TD} font-mono text-mono-sm tabular-nums text-muted`}>
                  {share.viewCount}/{share.maxViews}
                </td>
                <td className={`${TD} text-muted`}>
                  <time dateTime={share.expiresAt} title={new Date(share.expiresAt).toLocaleString()}>
                    {timeLeft(share.expiresAt)}
                  </time>
                </td>
                <td className={TD}>
                  <RelativeTime iso={share.createdAt} />
                </td>
                <td className={`${TD} text-right`}>
                  <RowMenu
                    label={`Actions for ${share.label}`}
                    actions={[{ label: "Revoke…", onSelect: () => setToRevoke(share) }]}
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
        title={`Revoke the link to “${toRevoke?.label ?? ""}”?`}
        description="Anyone holding the link can no longer open it. This can't be undone."
        footer={
          <>
            <Button variant="ghost" onClick={() => setToRevoke(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleRevoke} pending={revoking} pendingLabel="Revoking…">
              Revoke link
            </Button>
          </>
        }
      />
    </PageShell>
  );
}
