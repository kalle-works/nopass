import { useEffect, useState } from "react";
import { ArrowLeft } from "lucide-react";
import { Button, IconButton, SecretRow, Spinner, useNopassStore } from "@nopass/ui";
import type { VaultEntry } from "./EntryRow";

interface EntryDetailProps {
  entry: VaultEntry;
  loadCredentials: (itemId: string) => Promise<{ username: string; password: string } | null>;
  onBack: () => void;
  onFill: (entry: VaultEntry) => void;
}

/** Clipboard writes clear after 30s via the shared copyWithAutoClear logic. */
const copy = (text: string) => useNopassStore.getState().copyWithAutoClear(text);

export function EntryDetail({ entry, loadCredentials, onBack, onFill }: EntryDetailProps) {
  const [credentials, setCredentials] = useState<{ username: string; password: string } | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    loadCredentials(entry.id).then((c) => {
      if (cancelled) return;
      if (c) setCredentials(c);
      else setFailed(true);
    });
    return () => {
      cancelled = true;
    };
  }, [entry.id, loadCredentials]);

  return (
    <section aria-label={entry.name} className="flex min-h-0 flex-1 flex-col">
      <div className="flex items-center gap-2 border-b border-divider px-3 py-2">
        <IconButton label="Back to list" onClick={onBack}>
          <ArrowLeft aria-hidden className="size-4" />
        </IconButton>
        <h2 className="min-w-0 flex-1 truncate text-h3 font-semibold text-fg">{entry.name}</h2>
        <Button size="sm" onClick={() => onFill(entry)}>
          Fill
        </Button>
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {failed ? (
          <p role="alert" className="px-4 py-6 text-ui text-danger">
            Couldn't decrypt this item.
          </p>
        ) : !credentials ? (
          <div className="flex items-center gap-2 px-4 py-6 text-ui text-muted">
            <Spinner /> Decrypting…
          </div>
        ) : (
          <>
            <SecretRow label="Username" value={credentials.username} copy={copy} />
            <SecretRow label="Password" value={credentials.password} concealed copy={copy} />
            {entry.urls.length > 0 && (
              <SecretRow label="Website" value={entry.urls[0]!} mono copy={copy} />
            )}
          </>
        )}
      </div>
    </section>
  );
}
