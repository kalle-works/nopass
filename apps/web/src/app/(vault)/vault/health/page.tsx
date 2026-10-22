"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Banner, Button, Spinner, estimateStrength, useNopassStore } from "@nopass/ui";
import type { EncryptedVaultItem, LoginItem } from "@nopass/types";
import { api } from "@/lib/api";
import { PageShell } from "@/components/vault/PageShell";
import { useVault } from "@/components/vault/vault-context";

interface HealthEntry {
  item: EncryptedVaultItem;
  plaintext: LoginItem;
}

async function sha1Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const hash = await crypto.subtle.digest("SHA-1", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/** Have I Been Pwned range query: only the first 5 hash characters leave the device. */
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

function buildReport(entries: HealthEntry[]) {
  const weak: HealthEntry[] = [];
  const noPassword: HealthEntry[] = [];
  const missing2fa: HealthEntry[] = [];
  const byPassword = new Map<string, HealthEntry[]>();

  for (const entry of entries) {
    const { password, totp, passkey } = entry.plaintext;
    if (!totp && !passkey) missing2fa.push(entry);
    if (!password) {
      noPassword.push(entry);
      continue;
    }
    // Level 1 is the "Weak" bucket of the strength estimator (zxcvbn score 0 or 1)
    if (estimateStrength(password).level <= 1) weak.push(entry);
    byPassword.set(password, [...(byPassword.get(password) ?? []), entry]);
  }

  const reused = [...byPassword.values()].filter((group) => group.length > 1).flat();
  return { weak, noPassword, missing2fa, reused };
}

function HealthCard({
  title,
  count,
  description,
  action,
}: {
  title: string;
  count: number | null;
  description: string;
  action: React.ReactNode;
}) {
  return (
    <section aria-label={title} className="flex flex-col rounded-lg border border-divider bg-surface p-4">
      <div className="flex items-baseline justify-between gap-3">
        <h2 className="text-h3 font-semibold text-fg">{title}</h2>
        <p className="text-h1 font-semibold tabular-nums text-fg">
          {count ?? "–"}
        </p>
      </div>
      <p className="mb-4 mt-1 flex-1 text-ui text-muted">{description}</p>
      <div>{action}</div>
    </section>
  );
}

export default function HealthPage() {
  const router = useRouter();
  const { sessionToken } = useNopassStore();
  const v = useVault();
  const { breaches, setBreaches, setReview } = v;

  const [hibpLoading, setHibpLoading] = useState(false);
  const [hibpChecked, setHibpChecked] = useState(breaches.size > 0);
  const [hibpError, setHibpError] = useState<string | null>(null);
  const [recoveryEnabled, setRecoveryEnabled] = useState<boolean | null>(null);

  useEffect(() => {
    document.title = "Health — nopwd";
  }, []);

  useEffect(() => {
    if (!sessionToken) return;
    let cancelled = false;
    api.recovery
      .status(sessionToken)
      .then((s) => {
        if (!cancelled) setRecoveryEnabled(s.enabled);
      })
      .catch(() => {
        if (!cancelled) setRecoveryEnabled(null);
      });
    return () => {
      cancelled = true;
    };
  }, [sessionToken]);

  const entries = useMemo<HealthEntry[]>(() => {
    const out: HealthEntry[] = [];
    for (const item of v.items) {
      if (item.itemType !== "login") continue;
      const plaintext = v.decrypted.get(item.id);
      if (plaintext?.type === "login") out.push({ item, plaintext: plaintext as LoginItem });
    }
    return out;
  }, [v.items, v.decrypted]);

  const report = useMemo(() => buildReport(entries), [entries]);
  const ready = !v.isLoading;

  const runHibpCheck = useCallback(async () => {
    if (hibpLoading || entries.length === 0) return;
    setHibpLoading(true);
    setHibpError(null);
    const found = new Map<string, number>();
    try {
      for (const entry of entries) {
        const pw = entry.plaintext.password;
        if (!pw) continue;
        const count = await checkHibp(pw);
        if (count > 0) found.set(entry.item.id, count);
        await new Promise((r) => setTimeout(r, 80));
      }
      setBreaches(found);
      setHibpChecked(true);
    } catch {
      setHibpError("Breach check failed. Check your network and try again.");
    } finally {
      setHibpLoading(false);
    }
  }, [entries, hibpLoading, setBreaches]);

  function review(label: string, entriesToReview: HealthEntry[]) {
    setReview({ label, ids: new Set(entriesToReview.map((e) => e.item.id)) });
    router.push("/vault");
  }

  const reviewButton = (label: string, list: HealthEntry[]) => (
    <Button size="sm" disabled={list.length === 0} onClick={() => review(label, list)}>
      Review
    </Button>
  );

  const breachedEntries = entries.filter((e) => breaches.has(e.item.id));

  return (
    <PageShell
      title="Health"
      description={
        ready
          ? `Checked ${entries.length} ${entries.length === 1 ? "login" : "logins"} on this device. Nothing here is sent to the server.`
          : "Reading your vault…"
      }
    >
      {!ready ? (
        <div className="flex items-center gap-2 py-8 text-ui text-muted" role="status">
          <Spinner /> Analysing vault…
        </div>
      ) : (
        <div className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2">
            <HealthCard
              title="Breached"
              count={hibpChecked ? breachedEntries.length : null}
              description={
                hibpChecked
                  ? "Passwords that appear in known data breaches. Change these first."
                  : "Checks each password against Have I Been Pwned. Only the first 5 characters of its SHA-1 hash leave this device."
              }
              action={
                hibpChecked && breachedEntries.length > 0 ? (
                  <div className="flex items-center gap-2">
                    {reviewButton("Breached passwords", breachedEntries)}
                    <Button size="sm" variant="ghost" onClick={runHibpCheck} pending={hibpLoading} pendingLabel="Checking…">
                      Check again
                    </Button>
                  </div>
                ) : (
                  <Button
                    size="sm"
                    onClick={runHibpCheck}
                    disabled={entries.length === 0}
                    pending={hibpLoading}
                    pendingLabel="Checking…"
                  >
                    {hibpChecked ? "Check again" : "Check now"}
                  </Button>
                )
              }
            />
            <HealthCard
              title="Reused"
              count={report.reused.length}
              description="Logins that share a password with another login. One leak exposes all of them."
              action={reviewButton("Reused passwords", report.reused)}
            />
            <HealthCard
              title="Weak"
              count={report.weak.length}
              description="Passwords that can be guessed quickly. Replace them with generated ones."
              action={reviewButton("Weak passwords", report.weak)}
            />
            <HealthCard
              title="Missing 2FA"
              count={report.missing2fa.length}
              description="Logins with no one-time code or passkey saved. Add one where the site supports it."
              action={reviewButton("Missing 2FA", report.missing2fa)}
            />
            <HealthCard
              title="No password"
              count={report.noPassword.length}
              description="Logins whose password field is empty."
              action={reviewButton("No password", report.noPassword)}
            />
          </div>

          {hibpError && <Banner tone="danger">{hibpError}</Banner>}
          {hibpChecked && breachedEntries.length === 0 && !hibpError && (
            <Banner tone="success">None of your passwords appear in known data breaches.</Banner>
          )}

          {recoveryEnabled !== null && (
            <Banner
              tone={recoveryEnabled ? "neutral" : "warning"}
              title={recoveryEnabled ? "Recovery kit is enabled" : "Recovery is off"}
              action={
                <Button size="sm" onClick={() => router.push("/vault/recovery")}>
                  {recoveryEnabled ? "Manage" : "Set up"}
                </Button>
              }
            >
              {recoveryEnabled
                ? "Your kit can restore vault access if you forget your master password."
                : "If you forget your master password, your vault is permanently lost."}
            </Banner>
          )}
        </div>
      )}
    </PageShell>
  );
}
