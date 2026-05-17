"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { useNopassStore } from "@nopass/ui";
import { encryptItem } from "@nopass/crypto";
import type { VaultItemPlaintext, VaultItemType } from "@nopass/types";
import { api } from "@/lib/api";
import { parseOnePux, type ImportResult } from "@/lib/import/onepassword";

type Phase = "select" | "preview" | "importing" | "done" | "error";

const TYPE_LABELS: Record<VaultItemType, string> = {
  login: "Logins",
  note: "Notes",
  card: "Cards",
  identity: "Identities",
  ssh_key: "SSH Keys",
};

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
  const { isUnlocked, sessionToken, defaultVaultId, vaultEncKey, vaultMacKey, upsertItem } =
    useNopassStore();

  const [phase, setPhase] = useState<Phase>("select");
  const [parsed, setParsed] = useState<ImportResult | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  const [progress, setProgress] = useState({ done: 0, total: 0 });
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    document.title = "Import — nopass";
    if (!isUnlocked()) router.replace("/login");
  }, [isUnlocked, router]);

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
    if (!parsed || !sessionToken || !defaultVaultId || !vaultEncKey || !vaultMacKey) return;

    setPhase("importing");
    setProgress({ done: 0, total: parsed.items.length });

    let done = 0;
    for (const plaintext of parsed.items) {
      try {
        const encrypted = await encryptItem(plaintext, vaultEncKey, vaultMacKey);
        const created = await api.vault.create(
          defaultVaultId,
          { itemType: plaintext.type, ...encrypted },
          sessionToken,
        );
        upsertItem(created);
      } catch {
        // Skip items that fail to import
      }
      done++;
      setProgress({ done, total: parsed.items.length });
    }

    setPhase("done");
  }, [parsed, sessionToken, defaultVaultId, vaultEncKey, vaultMacKey, upsertItem]);

  if (!isUnlocked()) return null;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col">
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 px-6 py-4 flex items-center gap-4">
        <button
          onClick={() => router.push("/vault")}
          className="flex items-center gap-1.5 text-sm text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-200 transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          Back to vault
        </button>
        <h1 className="text-sm font-semibold text-gray-900 dark:text-white">Import from 1Password</h1>
      </header>

      <main className="flex-1 flex items-start justify-center pt-12 px-4">
        <div className="w-full max-w-lg">

          {phase === "select" && (
            <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm p-8">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">
                Import from 1Password
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
                Export your vault as a <code className="text-xs bg-gray-100 dark:bg-gray-700 px-1 py-0.5 rounded">.1pux</code> file from 1Password, then drop it here.
                All processing happens locally — the file never leaves your browser.
              </p>

              <div className="mb-6 p-4 bg-gray-50 dark:bg-gray-700/50 rounded-xl text-sm text-gray-600 dark:text-gray-300 space-y-1.5">
                <p className="font-medium text-gray-700 dark:text-gray-200 text-xs uppercase tracking-wide mb-2">How to export from 1Password</p>
                <p>1. Open 1Password on your Mac or PC</p>
                <p>2. Go to <strong>File → Export → All Vaults…</strong></p>
                <p>3. Choose <strong>1Password Unencrypted Export (.1pux)</strong></p>
                <p>4. Save the file and drop it below</p>
              </div>

              <div
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-10 flex flex-col items-center gap-3 cursor-pointer transition-colors ${
                  dragOver
                    ? "border-blue-500 bg-blue-50 dark:bg-blue-900/20"
                    : "border-gray-200 dark:border-gray-600 hover:border-gray-300 dark:hover:border-gray-500 hover:bg-gray-50 dark:hover:bg-gray-700/30"
                }`}
              >
                <svg className="w-10 h-10 text-gray-300 dark:text-gray-600" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                </svg>
                <div className="text-center">
                  <p className="text-sm font-medium text-gray-700 dark:text-gray-300">
                    Drop your .1pux file here
                  </p>
                  <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">or click to browse</p>
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".1pux"
                  className="hidden"
                  onChange={handleFileInput}
                />
              </div>
            </div>
          )}

          {phase === "preview" && parsed && (
            <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm p-8">
              <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-1">
                Ready to import
              </h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
                Found <strong>{parsed.items.length}</strong> items
                {parsed.vaultNames.length > 0 && (
                  <> from {parsed.vaultNames.map((n) => <strong key={n}> {n}</strong>)}</>
                )}.
                {parsed.skipped > 0 && (
                  <span className="text-amber-600 dark:text-amber-400"> {parsed.skipped} trashed items skipped.</span>
                )}
              </p>

              <div className="space-y-2 mb-6">
                {(Object.entries(countByType(parsed.items)) as [VaultItemType, number][]).map(
                  ([type, count]) => (
                    <div
                      key={type}
                      className="flex items-center justify-between px-3.5 py-2.5 bg-gray-50 dark:bg-gray-700/50 rounded-lg"
                    >
                      <span className="text-sm text-gray-700 dark:text-gray-300">{TYPE_LABELS[type]}</span>
                      <span className="text-sm font-medium text-gray-900 dark:text-white tabular-nums">{count}</span>
                    </div>
                  ),
                )}
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={handleImport}
                  className="flex-1 py-2.5 text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
                >
                  Import {parsed.items.length} items
                </button>
                <button
                  onClick={() => { setParsed(null); setPhase("select"); }}
                  className="px-4 py-2.5 text-sm text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {phase === "importing" && (
            <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm p-8 text-center">
              <div className="w-12 h-12 rounded-full border-4 border-blue-100 dark:border-blue-900/40 border-t-blue-600 dark:border-t-blue-400 animate-spin mx-auto mb-4" />
              <h2 className="text-base font-semibold text-gray-900 dark:text-white mb-1">Importing…</h2>
              <p className="text-sm text-gray-500 dark:text-gray-400">
                {progress.done} / {progress.total} items encrypted and saved
              </p>
              <div className="mt-4 h-1.5 bg-gray-100 dark:bg-gray-700 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-600 rounded-full transition-all duration-300"
                  style={{ width: `${progress.total > 0 ? (progress.done / progress.total) * 100 : 0}%` }}
                />
              </div>
            </div>
          )}

          {phase === "done" && (
            <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm p-8 text-center">
              <div className="w-12 h-12 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h2 className="text-base font-semibold text-gray-900 dark:text-white mb-1">Import complete</h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
                {progress.done} items imported and encrypted in your vault.
              </p>
              <button
                onClick={() => router.push("/vault")}
                className="px-6 py-2.5 text-sm font-medium bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
              >
                Go to vault
              </button>
            </div>
          )}

          {phase === "error" && (
            <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm p-8 text-center">
              <div className="w-12 h-12 rounded-full bg-red-100 dark:bg-red-900/30 flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-red-600 dark:text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <h2 className="text-base font-semibold text-gray-900 dark:text-white mb-1">Import failed</h2>
              <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">{errorMsg}</p>
              <button
                onClick={() => { setErrorMsg(""); setPhase("select"); }}
                className="px-6 py-2.5 text-sm font-medium bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 text-gray-700 dark:text-gray-300 rounded-lg transition-colors"
              >
                Try again
              </button>
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
