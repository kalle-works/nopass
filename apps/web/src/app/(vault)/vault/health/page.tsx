"use client";

import { useEffect, useMemo, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useNopassStore } from "@nopass/ui";
import { decryptItem } from "@nopass/crypto";
import type { EncryptedVaultItem, LoginItem, VaultItemPlaintext } from "@nopass/types";

interface HealthEntry {
  item: EncryptedVaultItem;
  plaintext: LoginItem;
}

interface HealthReport {
  weak: HealthEntry[];
  reused: Array<{ password: string; entries: HealthEntry[] }>;
  noPassword: HealthEntry[];
  breached: Array<{ entry: HealthEntry; count: number }>;
}

function passwordStrengthScore(pw: string): number {
  if (!pw) return 0;
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
  return score;
}

async function sha1Hex(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hash = await crypto.subtle.digest("SHA-1", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

async function checkHibp(password: string): Promise<number> {
  if (!password) return 0;
  try {
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);
    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "Add-Padding": "true" },
    });
    if (!res.ok) return 0;
    const text = await res.text();
    const line = text.split("\n").find((l) => l.startsWith(suffix));
    if (!line) return 0;
    return parseInt(line.split(":")[1] ?? "0", 10);
  } catch {
    return 0;
  }
}

function buildReport(entries: HealthEntry[]): Omit<HealthReport, "breached"> {
  const weak: HealthEntry[] = [];
  const noPassword: HealthEntry[] = [];
  const byPassword = new Map<string, HealthEntry[]>();

  for (const entry of entries) {
    const pw = entry.plaintext.password;
    if (!pw) {
      noPassword.push(entry);
      continue;
    }
    if (passwordStrengthScore(pw) <= 1) {
      weak.push(entry);
    }
    const group = byPassword.get(pw) ?? [];
    group.push(entry);
    byPassword.set(pw, group);
  }

  const reused = Array.from(byPassword.entries())
    .filter(([, group]) => group.length > 1)
    .map(([password, entries]) => ({ password, entries }))
    .sort((a, b) => b.entries.length - a.entries.length);

  return { weak, reused, noPassword };
}

function ScoreCard({ label, count, color, description }: { label: string; count: number; color: string; description: string }) {
  return (
    <div className={`rounded-xl border p-4 ${color}`}>
      <div className="text-2xl font-bold tabular-nums">{count}</div>
      <div className="text-sm font-medium mt-0.5">{label}</div>
      <div className="text-xs mt-1 opacity-70">{description}</div>
    </div>
  );
}

function EntryRow({ entry, onClick }: { entry: HealthEntry; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-700/50 transition-colors text-left"
    >
      <div className="w-8 h-8 rounded-lg bg-blue-100 dark:bg-blue-900/40 flex items-center justify-center shrink-0">
        <svg className="w-4 h-4 text-blue-600 dark:text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
          <rect x="3" y="11" width="18" height="11" rx="2" />
          <path d="M7 11V7a5 5 0 0 1 10 0v4" />
        </svg>
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-gray-900 dark:text-white truncate">{entry.plaintext.name}</p>
        {entry.plaintext.username && (
          <p className="text-xs text-gray-500 dark:text-gray-400 truncate">{entry.plaintext.username}</p>
        )}
      </div>
    </button>
  );
}

export default function HealthPage() {
  const router = useRouter();
  const { isUnlocked, items, vaultEncKey, vaultMacKey } = useNopassStore();

  const [entries, setEntries] = useState<HealthEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [hibpLoading, setHibpLoading] = useState(false);
  const [breached, setBreached] = useState<Array<{ entry: HealthEntry; count: number }>>([]);
  const [hibpChecked, setHibpChecked] = useState(false);
  const [hibpError, setHibpError] = useState<string | null>(null);

  useEffect(() => {
    document.title = "Security audit — nopwd";
    if (!isUnlocked()) {
      router.replace("/login");
      return;
    }
  }, [isUnlocked, router]);

  useEffect(() => {
    if (!vaultEncKey || !vaultMacKey) return;
    let cancelled = false;
    const enc = vaultEncKey;
    const mac = vaultMacKey;
    const loginItems = items.filter((i) => i.itemType === "login" && !i.deletedAt);

    Promise.all(
      loginItems.map(async (item) => {
        try {
          const plaintext = await decryptItem(item, enc, mac) as VaultItemPlaintext;
          if (plaintext.type === "login") return { item, plaintext } as HealthEntry;
        } catch {
          // skip items that fail to decrypt
        }
        return null;
      }),
    ).then((results) => {
      if (cancelled) return;
      setEntries(results.filter((r): r is HealthEntry => r !== null));
      setLoading(false);
    });

    return () => { cancelled = true; };
  }, [items, vaultEncKey, vaultMacKey]);

  const runHibpCheck = useCallback(async () => {
    if (hibpLoading || entries.length === 0) return;
    setHibpLoading(true);
    setHibpError(null);
    const results: Array<{ entry: HealthEntry; count: number }> = [];
    try {
      for (const entry of entries) {
        const pw = entry.plaintext.password;
        if (!pw) continue;
        const count = await checkHibp(pw);
        if (count > 0) results.push({ entry, count });
        // Small delay to be a good citizen to the HIBP API
        await new Promise((r) => setTimeout(r, 80));
      }
      setBreached(results);
      setHibpChecked(true);
    } catch {
      setHibpError("Breach check failed. Check your network and try again.");
    } finally {
      setHibpLoading(false);
    }
  }, [entries, hibpLoading]);

  const base = useMemo(() => buildReport(entries), [entries]);
  const report: HealthReport = { ...base, breached };

  const problematicIds = new Set([
    ...report.weak.map((e) => e.item.id),
    ...report.reused.flatMap((g) => g.entries.map((e) => e.item.id)),
    ...report.noPassword.map((e) => e.item.id),
    ...report.breached.map((b) => b.entry.item.id),
  ]);
  const score = entries.length === 0 ? 100 : Math.max(0, Math.round(100 - (problematicIds.size / entries.length) * 100));

  const scoreColor =
    score >= 90 ? "text-green-600 dark:text-green-400" :
    score >= 70 ? "text-blue-600 dark:text-blue-400" :
    score >= 50 ? "text-amber-500 dark:text-amber-400" :
    "text-red-600 dark:text-red-400";

  if (!isUnlocked()) return null;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex flex-col">
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
        <h1 className="text-sm font-semibold text-gray-900 dark:text-white">Security audit</h1>
      </header>

      <main className="flex-1 max-w-2xl mx-auto w-full px-4 py-8 space-y-8">
        {loading ? (
          <div className="flex flex-col items-center justify-center py-20 gap-4">
            <div className="w-10 h-10 rounded-full border-4 border-blue-100 dark:border-blue-900/40 border-t-blue-600 dark:border-t-blue-400 animate-spin" />
            <p className="text-sm text-gray-500 dark:text-gray-400">Analysing vault…</p>
          </div>
        ) : (
          <>
            {/* Score */}
            <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm p-6 flex items-center gap-6">
              <div className="text-center shrink-0">
                <div className={`text-5xl font-bold tabular-nums ${scoreColor}`}>{score}</div>
                <div className="text-xs text-gray-500 dark:text-gray-400 mt-1">Security score</div>
              </div>
              <div className="flex-1">
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  Analysed <strong className="text-gray-900 dark:text-white">{entries.length}</strong> login items.
                  {problematicIds.size === 0
                    ? " Everything looks great — no issues found."
                    : ` Found ${problematicIds.size} issue${problematicIds.size !== 1 ? "s" : ""} to review.`}
                </p>
              </div>
            </div>

            {/* Summary cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <ScoreCard
                label="Weak"
                count={report.weak.length}
                color={report.weak.length > 0 ? "border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300" : "border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300"}
                description="Too short or simple"
              />
              <ScoreCard
                label="Reused"
                count={report.reused.reduce((sum, g) => sum + g.entries.length, 0)}
                color={report.reused.length > 0 ? "border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-300" : "border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300"}
                description="Same password, multiple sites"
              />
              <ScoreCard
                label="Breached"
                count={report.breached.length}
                color={report.breached.length > 0 ? "border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300" : "border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300"}
                description={hibpChecked ? "Found in data breaches" : "Not checked yet"}
              />
              <ScoreCard
                label="No password"
                count={report.noPassword.length}
                color={report.noPassword.length > 0 ? "border-gray-300 dark:border-gray-600 bg-gray-100 dark:bg-gray-700/50 text-gray-600 dark:text-gray-400" : "border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300"}
                description="Empty password field"
              />
            </div>

            {/* HIBP check */}
            {!hibpChecked && (
              <div className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm p-5">
                <div className="flex items-start gap-4">
                  <div className="w-9 h-9 rounded-lg bg-orange-100 dark:bg-orange-900/30 flex items-center justify-center shrink-0">
                    <svg className="w-5 h-5 text-orange-600 dark:text-orange-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                    </svg>
                  </div>
                  <div className="flex-1">
                    <h3 className="text-sm font-semibold text-gray-900 dark:text-white">Check for data breaches</h3>
                    <p className="text-xs text-gray-500 dark:text-gray-400 mt-1">
                      Checks your passwords against the HaveIBeenPwned database using k-anonymity — your passwords never leave your device in cleartext.
                    </p>
                    {hibpError && (
                      <p className="text-xs text-red-600 dark:text-red-400 mt-2">{hibpError}</p>
                    )}
                  </div>
                  <button
                    onClick={runHibpCheck}
                    disabled={hibpLoading || entries.length === 0}
                    className="flex items-center gap-2 px-4 py-2 text-sm bg-orange-500 hover:bg-orange-600 disabled:opacity-60 text-white rounded-lg font-medium transition-colors shrink-0"
                  >
                    {hibpLoading ? (
                      <>
                        <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
                          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                        </svg>
                        Checking…
                      </>
                    ) : (
                      "Check now"
                    )}
                  </button>
                </div>
                {hibpLoading && (
                  <div className="mt-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg px-3 py-2">
                    <p className="text-xs text-gray-500 dark:text-gray-400">
                      Checking {entries.length} passwords via k-anonymity…
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Breached passwords */}
            {hibpChecked && report.breached.length > 0 && (
              <section className="bg-white dark:bg-gray-800 rounded-2xl border border-red-200 dark:border-red-800 shadow-sm overflow-hidden">
                <div className="px-4 py-3 border-b border-red-100 dark:border-red-800/50 flex items-center gap-2 bg-red-50 dark:bg-red-900/20">
                  <div className="w-2 h-2 rounded-full bg-red-500 shrink-0" />
                  <h2 className="text-sm font-semibold text-red-900 dark:text-red-200">Found in data breaches</h2>
                  <span className="ml-auto text-xs text-red-600 dark:text-red-400">{report.breached.length} item{report.breached.length !== 1 ? "s" : ""}</span>
                </div>
                <div className="divide-y divide-gray-100 dark:divide-gray-700">
                  {report.breached.map(({ entry, count }) => (
                    <div key={entry.item.id} className="flex items-center">
                      <div className="flex-1">
                        <EntryRow entry={entry} onClick={() => router.push(`/vault?item=${entry.item.id}`)} />
                      </div>
                      <div className="px-4 shrink-0">
                        <span className="text-xs font-mono font-bold text-red-600 dark:text-red-400">
                          {count.toLocaleString()}×
                        </span>
                        <span className="text-[10px] text-gray-400 ml-1">breaches</span>
                      </div>
                    </div>
                  ))}
                </div>
                <div className="px-4 py-3 bg-red-50 dark:bg-red-900/10 border-t border-red-100 dark:border-red-800/50">
                  <p className="text-xs text-red-700 dark:text-red-300">
                    Change these passwords immediately. Use the built-in generator to create strong unique replacements.
                  </p>
                </div>
              </section>
            )}

            {hibpChecked && report.breached.length === 0 && (
              <div className="bg-green-50 dark:bg-green-900/20 rounded-2xl border border-green-200 dark:border-green-800 p-4 flex items-center gap-3">
                <svg className="w-5 h-5 text-green-600 dark:text-green-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
                </svg>
                <p className="text-sm text-green-700 dark:text-green-300">
                  None of your passwords appear in known data breaches.
                </p>
              </div>
            )}

            {/* Weak passwords */}
            {report.weak.length > 0 && (
              <section className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-100 dark:border-gray-700 flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-red-500 shrink-0" />
                  <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Weak passwords</h2>
                  <span className="ml-auto text-xs text-gray-400 dark:text-gray-500">{report.weak.length} items</span>
                </div>
                <div className="divide-y divide-gray-100 dark:divide-gray-700">
                  {report.weak.map((entry) => (
                    <EntryRow key={entry.item.id} entry={entry} onClick={() => router.push(`/vault?item=${entry.item.id}`)} />
                  ))}
                </div>
              </section>
            )}

            {/* Reused passwords */}
            {report.reused.length > 0 && (
              <section className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-100 dark:border-gray-700 flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-amber-500 shrink-0" />
                  <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Reused passwords</h2>
                  <span className="ml-auto text-xs text-gray-400 dark:text-gray-500">{report.reused.length} groups</span>
                </div>
                <div className="divide-y divide-gray-100 dark:divide-gray-700">
                  {report.reused.map(({ password, entries: group }) => (
                    <div key={password}>
                      <div className="px-4 py-2 bg-amber-50 dark:bg-amber-900/10">
                        <span className="text-xs font-medium text-amber-700 dark:text-amber-400">
                          {group.length} sites share this password
                        </span>
                      </div>
                      {group.map((entry) => (
                        <EntryRow key={entry.item.id} entry={entry} onClick={() => router.push(`/vault?item=${entry.item.id}`)} />
                      ))}
                    </div>
                  ))}
                </div>
              </section>
            )}

            {/* No password */}
            {report.noPassword.length > 0 && (
              <section className="bg-white dark:bg-gray-800 rounded-2xl border border-gray-200 dark:border-gray-700 shadow-sm overflow-hidden">
                <div className="px-4 py-3 border-b border-gray-100 dark:border-gray-700 flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-gray-400 shrink-0" />
                  <h2 className="text-sm font-semibold text-gray-900 dark:text-white">No password stored</h2>
                  <span className="ml-auto text-xs text-gray-400 dark:text-gray-500">{report.noPassword.length} items</span>
                </div>
                <div className="divide-y divide-gray-100 dark:divide-gray-700">
                  {report.noPassword.map((entry) => (
                    <EntryRow key={entry.item.id} entry={entry} onClick={() => router.push(`/vault?item=${entry.item.id}`)} />
                  ))}
                </div>
              </section>
            )}

            {problematicIds.size === 0 && hibpChecked && (
              <div className="text-center py-12">
                <div className="w-14 h-14 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center mx-auto mb-4">
                  <svg className="w-7 h-7 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <p className="text-sm font-medium text-gray-700 dark:text-gray-300">All passwords look good</p>
                <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">No weak, reused, or breached passwords detected</p>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
