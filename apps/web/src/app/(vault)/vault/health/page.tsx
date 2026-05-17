"use client";

import { useEffect, useMemo, useState } from "react";
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

function buildReport(entries: HealthEntry[]): HealthReport {
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

function EntryRow({ entry, router }: { entry: HealthEntry; router: ReturnType<typeof useRouter> }) {
  return (
    <button
      onClick={() => router.push("/vault")}
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

  useEffect(() => {
    document.title = "Security audit — nopass";
    if (!isUnlocked()) {
      router.replace("/login");
      return;
    }
  }, [isUnlocked, router]);

  useEffect(() => {
    if (!vaultEncKey || !vaultMacKey) return;
    let cancelled = false;
    async function decrypt() {
      const result: HealthEntry[] = [];
      for (const item of items) {
        if (item.itemType !== "login" || item.deletedAt) continue;
        try {
          const plaintext = await decryptItem(item, vaultEncKey!, vaultMacKey!) as VaultItemPlaintext;
          if (plaintext.type === "login") {
            result.push({ item, plaintext });
          }
        } catch {
          // skip items that fail to decrypt
        }
      }
      if (!cancelled) {
        setEntries(result);
        setLoading(false);
      }
    }
    decrypt();
    return () => { cancelled = true; };
  }, [items, vaultEncKey, vaultMacKey]);

  const report = useMemo(() => buildReport(entries), [entries]);

  const totalIssues = report.weak.length + report.reused.reduce((sum, g) => sum + g.entries.length, 0) + report.noPassword.length;
  const score = entries.length === 0 ? 100 : Math.max(0, Math.round(100 - (totalIssues / entries.length) * 100));

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
                  {totalIssues === 0
                    ? " Everything looks great — no issues found."
                    : ` Found ${totalIssues} issue${totalIssues !== 1 ? "s" : ""} to review.`}
                </p>
              </div>
            </div>

            {/* Summary cards */}
            <div className="grid grid-cols-3 gap-3">
              <ScoreCard
                label="Weak passwords"
                count={report.weak.length}
                color={report.weak.length > 0 ? "border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-300" : "border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300"}
                description="Too short or too simple"
              />
              <ScoreCard
                label="Reused"
                count={report.reused.reduce((sum, g) => sum + g.entries.length, 0)}
                color={report.reused.length > 0 ? "border-amber-200 dark:border-amber-800 bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-300" : "border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300"}
                description="Same password in multiple sites"
              />
              <ScoreCard
                label="No password"
                count={report.noPassword.length}
                color={report.noPassword.length > 0 ? "border-gray-300 dark:border-gray-600 bg-gray-100 dark:bg-gray-700/50 text-gray-600 dark:text-gray-400" : "border-gray-200 dark:border-gray-700 bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300"}
                description="Login with empty password field"
              />
            </div>

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
                    <EntryRow key={entry.item.id} entry={entry} router={router} />
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
                        <EntryRow key={entry.item.id} entry={entry} router={router} />
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
                    <EntryRow key={entry.item.id} entry={entry} router={router} />
                  ))}
                </div>
              </section>
            )}

            {totalIssues === 0 && (
              <div className="text-center py-12">
                <div className="w-14 h-14 rounded-full bg-green-100 dark:bg-green-900/30 flex items-center justify-center mx-auto mb-4">
                  <svg className="w-7 h-7 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                </div>
                <p className="text-sm font-medium text-gray-700 dark:text-gray-300">All passwords look good</p>
                <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">No weak or reused passwords detected</p>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
