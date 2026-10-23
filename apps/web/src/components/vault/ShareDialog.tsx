"use client";

import { useState } from "react";
import { Button, Dialog, cx, useNopassStore } from "@nopass/ui";
import { useVault, type DecryptedEntry } from "./vault-context";
import { api } from "@/lib/api";

const EXPIRY_OPTIONS = [
  { label: "1 hour", hours: 1 },
  { label: "24 hours", hours: 24 },
  { label: "7 days", hours: 168 },
];

const VIEW_OPTIONS = [1, 3, 10];

function Choice<T extends number>({
  legend,
  options,
  value,
  onChange,
}: {
  legend: string;
  options: Array<{ value: T; label: string }>;
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div role="radiogroup" aria-label={legend} className="flex flex-col gap-1.5">
      <span className="text-meta font-medium text-fg">{legend}</span>
      <div className="flex gap-2">
        {options.map((o) => (
          <button
            key={o.value}
            type="button"
            role="radio"
            aria-checked={value === o.value}
            onClick={() => onChange(o.value)}
            className={cx(
              "h-8 rounded border px-3 text-meta transition-colors duration-[120ms]",
              value === o.value
                ? "border-accent bg-accent-subtle font-medium text-accent-text"
                : "border-border bg-surface text-fg hover:border-border-strong hover:bg-surface-hover",
            )}
          >
            {o.label}
          </button>
        ))}
      </div>
    </div>
  );
}

export function ShareDialog({ entry, onClose }: { entry: DecryptedEntry; onClose: () => void }) {
  const { copy } = useVault();
  const [maxViews, setMaxViews] = useState(1);
  const [expiresInHours, setExpiresInHours] = useState(24);
  const [link, setLink] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleCreate() {
    const { sessionToken, vaultEncKey } = useNopassStore.getState();
    if (!sessionToken || !vaultEncKey) return;
    setCreating(true);
    setError(null);
    try {
      const { generateShareKey, encryptSharePayload, encryptBytes } = await import("@nopass/crypto");
      const { key, keyB64url } = await generateShareKey();
      const payload = await encryptSharePayload(entry.plaintext, key);
      const label = await encryptBytes(new TextEncoder().encode(entry.plaintext.name), vaultEncKey);
      const { shareId } = await api.shares.create(
        {
          blob: payload.blob,
          blobIv: payload.blobIv,
          labelBlob: label.blob,
          labelIv: label.blobIv,
          maxViews,
          expiresInHours,
        },
        sessionToken,
      );
      setLink(`${window.location.origin}/s/${shareId}#k=${keyB64url}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to create share");
    } finally {
      setCreating(false);
    }
  }

  async function handleCopy() {
    if (!link) return;
    if (await copy(link)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  }

  return (
    <Dialog
      open
      onClose={onClose}
      title={`Share “${entry.plaintext.name}”`}
      description={
        link
          ? "Send this link over a channel you trust. The decryption key sits after the # and never reaches our servers."
          : "Creates a link to a snapshot of this item, encrypted with a key that only exists in the link. You can revoke it from Shared links."
      }
      footer={
        link ? (
          <>
            <Button variant="ghost" onClick={onClose}>
              Done
            </Button>
            <Button variant="primary" onClick={handleCopy}>
              {copied ? "Copied" : "Copy link"}
            </Button>
          </>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleCreate} pending={creating} pendingLabel="Creating…">
              Create share link
            </Button>
          </>
        )
      }
    >
      {link ? (
        <div className="select-all break-all rounded border border-divider bg-bg-subtle p-3 font-mono text-mono-sm text-fg">
          {link}
        </div>
      ) : (
        <div className="space-y-4">
          <Choice
            legend="Expires after"
            options={EXPIRY_OPTIONS.map((o) => ({ value: o.hours, label: o.label }))}
            value={expiresInHours}
            onChange={setExpiresInHours}
          />
          <Choice
            legend="Views allowed"
            options={VIEW_OPTIONS.map((n) => ({ value: n, label: n === 1 ? "1 (one-time)" : String(n) }))}
            value={maxViews}
            onChange={setMaxViews}
          />
          {error && (
            <p role="alert" className="text-meta text-danger">
              {error}
            </p>
          )}
        </div>
      )}
    </Dialog>
  );
}
