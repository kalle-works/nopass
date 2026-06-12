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
  const [progress, setProgress] = useState({ done: 0, failed: 0, total: 0 });
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    document.title = "Import — nopwd";
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
    setProgress({ done: 0, failed: 0, total: parsed.items.length });

    let done = 0;
    let failed = 0;
    for (const plaintext of parsed.items) {
      try {
        const encrypted = await encryptItem(plaintext, vaultEncKey, vaultMacKey);
        const created = await api.vault.create(
          defaultVaultId,
          { itemType: plaintext.type, ...encrypted },
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
  }, [parsed, sessionToken, defaultVaultId, vaultEncKey, vaultMacKey, upsertItem]);

  if (!isUnlocked()) return null;

  return (
    <div className="min-h-screen bg-[#070706] flex flex-col">
      {/* Header */}
      <header className="bg-[#11110F] border-b border-[#2B2923] px-6 py-4 flex items-center gap-4">
        <button
          onClick={() => router.push("/vault")}
          className="flex items-center gap-1.5 font-mono text-xs text-[#9C988D] hover:text-[#F4F1E8] transition-colors"
        >
          <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
            <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
          </svg>
          Back to vault
        </button>
        <h1 className="font-mono text-sm font-semibold text-[#F4F1E8]">Import from 1Password</h1>
      </header>

      <main className="flex-1 flex items-start justify-center pt-12 px-4">
        <div className="w-full max-w-lg">

          {phase === "select" && (
            <div className="bg-[#11110F] border border-[#2B2923] p-8">
              <h2 className="font-mono text-sm font-semibold text-[#F4F1E8] uppercase tracking-widest mb-1">
                Import from 1Password
              </h2>
              <p className="text-sm text-[#9C988D] mb-6">
                Export your vault as a <code className="font-mono text-xs bg-[#070706] border border-[#2B2923] px-1 py-0.5">.1pux</code> file from 1Password, then drop it here.
                All processing happens locally — the file never leaves your browser.
              </p>

              <div className="mb-6 p-4 bg-[#070706] border border-[#2B2923] text-sm text-[#9C988D] space-y-1.5">
                <p className="font-mono text-[10px] text-[#9C988D] uppercase tracking-widest mb-2">How to export from 1Password</p>
                <p>1. Open 1Password on your Mac or PC</p>
                <p>2. Go to <strong className="text-[#F4F1E8]">File → Export → All Vaults…</strong></p>
                <p>3. Choose <strong className="text-[#F4F1E8]">1Password Unencrypted Export (.1pux)</strong></p>
                <p>4. Save the file and drop it below</p>
              </div>

              <div
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
                onClick={() => fileInputRef.current?.click()}
                className={`border-2 border-dashed p-10 flex flex-col items-center gap-3 cursor-pointer transition-colors ${
                  dragOver
                    ? "border-[#D6FF3F] bg-[#D6FF3F]/10"
                    : "border-[#2B2923] hover:border-[#9C988D]/50 hover:bg-[#181713]"
                }`}
              >
                <svg className="w-10 h-10 text-[#2B2923]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
                </svg>
                <div className="text-center">
                  <p className="text-sm text-[#F4F1E8]">
                    Drop your .1pux file here
                  </p>
                  <p className="text-xs text-[#9C988D] mt-1">or click to browse</p>
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
            <div className="bg-[#11110F] border border-[#2B2923] p-8">
              <h2 className="font-mono text-sm font-semibold text-[#F4F1E8] uppercase tracking-widest mb-1">
                Ready to import
              </h2>
              <p className="text-sm text-[#9C988D] mb-6">
                Found <strong className="text-[#F4F1E8]">{parsed.items.length}</strong> items
                {parsed.vaultNames.length > 0 && (
                  <> from {parsed.vaultNames.map((n) => <strong key={n} className="text-[#F4F1E8]"> {n}</strong>)}</>
                )}.
                {parsed.skipped > 0 && (
                  <span className="text-[#D6FF3F]"> {parsed.skipped} trashed items skipped.</span>
                )}
              </p>

              <div className="space-y-px mb-6">
                {(Object.entries(countByType(parsed.items)) as [VaultItemType, number][]).map(
                  ([type, count]) => (
                    <div
                      key={type}
                      className="flex items-center justify-between px-3.5 py-2.5 bg-[#070706] border border-[#2B2923]"
                    >
                      <span className="font-mono text-xs text-[#9C988D] uppercase tracking-widest">{TYPE_LABELS[type]}</span>
                      <span className="font-mono text-sm font-medium text-[#F4F1E8] tabular-nums">{count}</span>
                    </div>
                  ),
                )}
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={handleImport}
                  className="flex-1 py-2.5 font-mono text-xs font-semibold bg-[#D6FF3F] hover:bg-[#C4EE30] text-[#070706] transition-colors"
                >
                  Import {parsed.items.length} items
                </button>
                <button
                  onClick={() => { setParsed(null); setPhase("select"); }}
                  className="px-4 py-2.5 font-mono text-xs text-[#9C988D] hover:bg-[#181713] hover:text-[#F4F1E8] transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {phase === "importing" && (
            <div className="bg-[#11110F] border border-[#2B2923] p-8 text-center">
              <div className="w-8 h-8 border-2 border-[#2B2923] border-t-[#D6FF3F] animate-spin mx-auto mb-4" />
              <h2 className="font-mono text-xs font-semibold text-[#F4F1E8] uppercase tracking-widest mb-1">Importing…</h2>
              <p className="text-sm text-[#9C988D]">
                {progress.done} / {progress.total} items encrypted and saved
              </p>
              <div className="mt-4 h-px bg-[#2B2923] overflow-hidden">
                <div
                  className="h-full bg-[#D6FF3F] transition-all duration-300"
                  style={{ width: `${progress.total > 0 ? (progress.done / progress.total) * 100 : 0}%` }}
                />
              </div>
            </div>
          )}

          {phase === "done" && (
            <div className="bg-[#11110F] border border-[#2B2923] p-8 text-center">
              <div className="w-12 h-12 bg-[#7CFF6B]/10 border border-[#7CFF6B]/30 flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-[#7CFF6B]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h2 className="font-mono text-xs font-semibold text-[#F4F1E8] uppercase tracking-widest mb-1">Import complete</h2>
              <p className="text-sm text-[#9C988D] mb-6">
                {progress.done} items imported and encrypted in your vault.
                {progress.failed > 0 && (
                  <span className="text-[#D6FF3F]"> {progress.failed} items could not be imported.</span>
                )}
              </p>
              <button
                onClick={() => router.push("/vault")}
                className="px-6 py-2.5 font-mono text-xs font-semibold bg-[#D6FF3F] hover:bg-[#C4EE30] text-[#070706] transition-colors"
              >
                Go to vault
              </button>
            </div>
          )}

          {phase === "error" && (
            <div className="bg-[#11110F] border border-[#E8321A]/30 p-8 text-center">
              <div className="w-12 h-12 bg-[#E8321A]/10 border border-[#E8321A]/30 flex items-center justify-center mx-auto mb-4">
                <svg className="w-6 h-6 text-[#E8321A]" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <h2 className="font-mono text-xs font-semibold text-[#F4F1E8] uppercase tracking-widest mb-1">Import failed</h2>
              <p className="text-sm text-[#9C988D] mb-6">{errorMsg}</p>
              <button
                onClick={() => { setErrorMsg(""); setPhase("select"); }}
                className="px-6 py-2.5 font-mono text-xs text-[#9C988D] border border-[#2B2923] hover:bg-[#181713] hover:text-[#F4F1E8] transition-colors"
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
