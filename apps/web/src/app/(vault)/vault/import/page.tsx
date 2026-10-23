"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { Banner, Button, Spinner, cx, useNopassStore } from "@nopass/ui";
import { PageShell } from "@/components/vault/PageShell";
import { TYPE_PLURAL } from "@/components/vault/vault-model";
import { encryptItemV2 } from "@nopass/crypto";
import type { VaultItemPlaintext, VaultItemType } from "@nopass/types";
import { api } from "@/lib/api";
import { parseOnePux, type ImportResult } from "@/lib/import/onepassword";

type Phase = "select" | "preview" | "importing" | "done" | "error";

function countByType(items: VaultItemPlaintext[]): Partial<Record<VaultItemType, number>> {
  const counts: Partial<Record<VaultItemType, number>> = {};
  for (const item of items) {
    const t = item.type as VaultItemType;
    counts[t] = (counts[t] ?? 0) + 1;
  }
  return counts;
}

export default function ImportPage() {
  const router = useRouter();
  const { sessionToken, defaultVaultId, vaultEncKey, upsertItem } =
    useNopassStore();

  const [phase, setPhase] = useState<Phase>("select");
  const [parsed, setParsed] = useState<ImportResult | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [progress, setProgress] = useState({ done: 0, failed: 0, total: 0 });
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    document.title = "Import — nopwd";
  }, []);

  const handleFile = useCallback(async (file: File) => {
    if (!file.name.endsWith(".1pux")) {
      setErrorMsg("Only .1pux files are supported. Export from 1Password → File → Export → 1PUX format.");
      setPhase("error");
      return;
    }
    try {
      const result = await parseOnePux(file);
      setParsed(result);
      setPhase("preview");
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : "Failed to parse file");
      setPhase("error");
    }
  }, []);

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  const handleFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  const handleImport = useCallback(async () => {
    if (!parsed || !sessionToken || !defaultVaultId || !vaultEncKey) return;

    setPhase("importing");
    setProgress({ done: 0, failed: 0, total: parsed.items.length });

    let done = 0;
    let failed = 0;
    for (const plaintext of parsed.items) {
      try {
        const id = crypto.randomUUID();
        const encrypted = await encryptItemV2(
          plaintext,
          { scope: { kind: "personal" }, itemId: id, itemType: plaintext.type },
          1,
          vaultEncKey,
        );
        const created = await api.vault.create(
          defaultVaultId,
          { id, itemType: plaintext.type, ...encrypted },
          sessionToken,
        );
        upsertItem(created);
        done++;
      } catch {
        failed++;
      }
      setProgress({ done, failed, total: parsed.items.length });
    }

    setPhase("done");
  }, [parsed, sessionToken, defaultVaultId, vaultEncKey, upsertItem]);

  const card = "rounded-lg border border-divider bg-surface p-6";

  return (
    <PageShell
      title="Import"
      description="Bring items in from another password manager. Files are read in this browser and encrypted before upload."
    >
      {phase === "select" && (
        <div className={card}>
          <h2 className="text-h2 font-semibold text-fg">Import from 1Password</h2>
          <p className="mb-5 mt-1 text-ui text-muted">
            Export your vault as a{" "}
            <code className="rounded-sm border border-divider bg-surface-hover px-1 font-mono text-mono-sm">.1pux</code>{" "}
            file from 1Password, then drop it here. All processing happens locally; the file never leaves your browser.
          </p>

          <div className="mb-5 rounded-lg border border-divider bg-bg-subtle p-4">
            <h3 className="mb-2 text-meta font-medium text-fg">How to export from 1Password</h3>
            <ol className="list-decimal space-y-1 pl-5 text-ui text-muted">
              <li>Open 1Password on your Mac or PC</li>
              <li>
                Go to <strong className="font-medium text-fg">File → Export → All Vaults…</strong>
              </li>
              <li>
                Choose <strong className="font-medium text-fg">1Password Unencrypted Export (.1pux)</strong>
              </li>
              <li>Save the file and drop it below</li>
            </ol>
          </div>

          <button
            type="button"
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            className={cx(
              "flex w-full flex-col items-center gap-1 rounded-lg border-2 border-dashed px-6 py-10 text-center transition-colors duration-[120ms]",
              dragOver ? "border-accent bg-accent-subtle" : "border-border hover:border-border-strong hover:bg-surface-hover",
            )}
          >
            <span className="text-ui font-medium text-fg">Drop your .1pux file here</span>
            <span className="text-meta text-muted">or click to browse</span>
          </button>
          <input ref={fileInputRef} type="file" accept=".1pux" className="hidden" onChange={handleFileInput} />
        </div>
      )}

      {phase === "preview" && parsed && (
        <div className={card}>
          <h2 className="text-h2 font-semibold text-fg">Ready to import</h2>
          <p className="mb-5 mt-1 text-ui text-muted">
            Found <strong className="font-medium text-fg">{parsed.items.length}</strong> items
            {parsed.vaultNames.length > 0 && (
              <>
                {" "}
                from{" "}
                {parsed.vaultNames.map((n, i) => (
                  <strong key={n} className="font-medium text-fg">
                    {i > 0 && ", "}
                    {n}
                  </strong>
                ))}
              </>
            )}
            .{parsed.skipped > 0 && <span className="text-warning"> {parsed.skipped} trashed items skipped.</span>}
          </p>

          <dl className="mb-5 divide-y divide-divider overflow-hidden rounded-lg border border-divider">
            {(Object.entries(countByType(parsed.items)) as [VaultItemType, number][]).map(([type, count]) => (
              <div key={type} className="flex min-h-11 items-center justify-between px-4 py-2">
                <dt className="text-ui text-muted">{TYPE_PLURAL[type]}</dt>
                <dd className="font-mono text-ui tabular-nums text-fg">{count}</dd>
              </div>
            ))}
          </dl>

          <div className="flex items-center gap-2">
            <Button variant="primary" onClick={handleImport}>
              Import {parsed.items.length} items
            </Button>
            <Button
              variant="ghost"
              onClick={() => {
                setParsed(null);
                setPhase("select");
              }}
            >
              Cancel
            </Button>
          </div>
        </div>
      )}

      {phase === "importing" && (
        <div className={card} role="status">
          <h2 className="flex items-center gap-2 text-h2 font-semibold text-fg">
            <Spinner /> Importing…
          </h2>
          <p className="mt-1 text-ui text-muted">
            {progress.done} / {progress.total} items encrypted and saved
          </p>
          <div
            role="progressbar"
            aria-label="Import progress"
            aria-valuemin={0}
            aria-valuemax={progress.total}
            aria-valuenow={progress.done}
            className="mt-4 h-1 overflow-hidden rounded-full bg-divider"
          >
            <div
              className="h-full bg-accent transition-[width] duration-300"
              style={{ width: `${progress.total > 0 ? (progress.done / progress.total) * 100 : 0}%` }}
            />
          </div>
        </div>
      )}

      {phase === "done" && (
        <div className={card}>
          <h2 className="text-h2 font-semibold text-fg">Import complete</h2>
          <p className="mb-5 mt-1 text-ui text-muted">
            {progress.done} items imported and encrypted in your vault.
            {progress.failed > 0 && <span className="text-warning"> {progress.failed} items could not be imported.</span>}
          </p>
          <Button variant="primary" onClick={() => router.push("/vault")}>
            Go to vault
          </Button>
        </div>
      )}

      {phase === "error" && (
        <div className="space-y-4">
          <Banner tone="danger" title="Import failed">
            {errorMsg}
          </Banner>
          <Button
            onClick={() => {
              setErrorMsg("");
              setPhase("select");
            }}
          >
            Try again
          </Button>
        </div>
      )}
    </PageShell>
  );
}
