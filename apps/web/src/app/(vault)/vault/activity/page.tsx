"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useNopassStore } from "@nopass/ui";
import type { ActivityEventInfo } from "@nopass/types";
import { api } from "@/lib/api";

const EVENT_LABELS: Record<string, { label: string; tone: "ok" | "warn" | "neutral" }> = {
  login_succeeded: { label: "Signed in", tone: "ok" },
  login_failed: { label: "Failed sign-in attempt", tone: "warn" },
  recovery_kit_created: { label: "Recovery kit generated", tone: "neutral" },
  recovery_kit_disabled: { label: "Recovery disabled", tone: "warn" },
  recovery_initiated: { label: "Recovery code used", tone: "warn" },
  recovery_completed: { label: "Account recovered — password rotated", tone: "warn" },
  share_created: { label: "Share link created", tone: "neutral" },
  share_viewed: { label: "Share link opened", tone: "neutral" },
  share_revoked: { label: "Share revoked", tone: "neutral" },
  device_registered: { label: "New device registered", tone: "warn" },
  device_revoked: { label: "Device revoked", tone: "neutral" },
  vault_created: { label: "Vault created", tone: "neutral" },
  vault_deleted: { label: "Vault deleted", tone: "neutral" },
};

const TONE_CLASS: Record<"ok" | "warn" | "neutral", string> = {
  ok: "text-[#7CFF6B]",
  warn: "text-amber-400",
  neutral: "text-[#F4F1E8]",
};

function formatTime(iso: string): string {
  const d = new Date(iso);
  return `${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
}

export default function ActivityPage() {
  const router = useRouter();
  const { isUnlocked, sessionToken } = useNopassStore();
  const [events, setEvents] = useState<ActivityEventInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    document.title = "Activity — nopwd";
    if (!isUnlocked()) router.replace("/login");
  }, [isUnlocked, router]);

  const load = useCallback(async () => {
    if (!sessionToken) return;
    setLoading(true);
    setError(null);
    try {
      setEvents(await api.activity.list(sessionToken));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load activity");
    } finally {
      setLoading(false);
    }
  }, [sessionToken]);

  useEffect(() => {
    load();
  }, [load]);

  if (!isUnlocked()) return null;

  return (
    <div className="min-h-screen bg-[#070706]">
      <div className="max-w-2xl mx-auto px-4 py-8">
        <div className="flex items-center gap-3 mb-6">
          <button
            onClick={() => router.push("/vault")}
            className="p-1.5 text-[#9C988D] hover:text-[#F4F1E8] hover:bg-[#181713] transition-colors"
            title="Back to vault"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <path d="M19 12H5M12 5l-7 7 7 7" />
            </svg>
          </button>
          <div>
            <h1 className="font-mono text-sm font-semibold text-[#F4F1E8] uppercase tracking-widest">Activity</h1>
            <p className="text-xs text-[#9C988D] mt-0.5">
              Security events on your account from the last 90 days. Item contents are never logged.
            </p>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 bg-[#E8321A]/10 border border-[#E8321A]/30 text-sm text-[#E8321A]">
            {error}
          </div>
        )}

        <div className="bg-[#11110F] border border-[#2B2923] overflow-hidden">
          {loading ? (
            <div className="divide-y divide-[#2B2923]">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="px-5 py-3.5 animate-pulse">
                  <div className="h-3.5 bg-[#2B2923] w-48 mb-2" />
                  <div className="h-2.5 bg-[#181713] w-32" />
                </div>
              ))}
            </div>
          ) : events.length === 0 ? (
            <div className="py-14 text-center">
              <p className="text-sm text-[#9C988D]">No activity recorded yet.</p>
            </div>
          ) : (
            <div className="divide-y divide-[#2B2923]">
              {events.map((event) => {
                const meta = EVENT_LABELS[event.eventType] ?? {
                  label: event.eventType.replace(/_/g, " "),
                  tone: "neutral" as const,
                };
                return (
                  <div key={event.id} className="px-5 py-3.5 flex items-baseline justify-between gap-4">
                    <div className="min-w-0">
                      <p className={`text-sm font-medium ${TONE_CLASS[meta.tone]}`}>{meta.label}</p>
                      <p className="font-mono text-xs text-[#9C988D] mt-0.5">
                        {event.ip ?? "unknown source"}
                      </p>
                    </div>
                    <p className="font-mono text-xs text-[#9C988D]/60 shrink-0 tabular-nums">
                      {formatTime(event.createdAt)}
                    </p>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
