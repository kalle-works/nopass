"use client";

import { useEffect, useState, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useNopassStore } from "@nopass/ui";
import type { DeviceInfo } from "@nopass/types";
import { api } from "@/lib/api";

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return "never";
  const diff = Date.now() - new Date(dateStr).getTime();
  const minutes = Math.floor(diff / 60_000);
  const hours = Math.floor(diff / 3_600_000);
  const days = Math.floor(diff / 86_400_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  if (hours < 24) return `${hours}h ago`;
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

function DeviceIcon({ type }: { type: string }) {
  if (type === "desktop_mac") {
    return (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
        <rect x="2" y="3" width="20" height="14" rx="2" />
        <path d="M8 21h8M12 17v4" />
      </svg>
    );
  }
  if (type === "android") {
    return (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
        <rect x="5" y="2" width="14" height="20" rx="2" />
        <line x1="12" y1="18" x2="12.01" y2="18" />
      </svg>
    );
  }
  if (type === "extension") {
    return (
      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
        <path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v18m0 0h10a2 2 0 0 0 2-2V9M9 21H5a2 2 0 0 1-2-2V9m0 0h18" />
      </svg>
    );
  }
  return (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  );
}

const DEVICE_TYPE_LABELS: Record<string, string> = {
  desktop_mac: "Mac",
  android: "Android",
  web: "Web",
  extension: "Browser Extension",
};

export default function DevicesPage() {
  const router = useRouter();
  const { isUnlocked, sessionToken } = useNopassStore();
  const [devices, setDevices] = useState<DeviceInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);

  useEffect(() => {
    if (!isUnlocked()) router.replace("/login");
  }, [isUnlocked, router]);

  const loadDevices = useCallback(async () => {
    if (!sessionToken) return;
    setLoading(true);
    setError(null);
    try {
      const list = await api.devices.list(sessionToken);
      setDevices(list);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load devices");
    } finally {
      setLoading(false);
    }
  }, [sessionToken]);

  useEffect(() => {
    loadDevices();
  }, [loadDevices]);

  async function handleRevoke(deviceId: string) {
    if (!sessionToken) return;
    setRevoking(deviceId);
    try {
      await api.devices.remove(deviceId, sessionToken);
      setDevices((d) => d.filter((dev) => dev.id !== deviceId));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to revoke device");
    } finally {
      setRevoking(null);
    }
  }

  if (!isUnlocked()) return null;

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
      <div className="max-w-2xl mx-auto px-4 py-8">
        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <button
            onClick={() => router.push("/vault")}
            className="p-1.5 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-800 rounded-lg transition-colors"
            title="Back to vault"
          >
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <path d="M19 12H5M12 5l-7 7 7 7" />
            </svg>
          </button>
          <div>
            <h1 className="text-lg font-semibold text-gray-900 dark:text-white">Trusted Devices</h1>
            <p className="text-xs text-gray-500 dark:text-gray-400 mt-0.5">
              Devices that have previously authenticated as you. Revoke any you don&apos;t recognize.
            </p>
          </div>
        </div>

        {error && (
          <div className="mb-4 flex items-center gap-2.5 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg text-sm text-red-700 dark:text-red-400">
            <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            {error}
            <button onClick={() => setError(null)} className="ml-auto p-0.5 hover:text-red-600">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          </div>
        )}

        <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
          {loading ? (
            <div className="divide-y divide-gray-100 dark:divide-gray-700">
              {[...Array(3)].map((_, i) => (
                <div key={i} className="flex items-center gap-4 px-5 py-4 animate-pulse">
                  <div className="w-10 h-10 rounded-xl bg-gray-200 dark:bg-gray-700 shrink-0" />
                  <div className="flex-1 space-y-2">
                    <div className="h-3.5 bg-gray-200 dark:bg-gray-700 rounded w-40" />
                    <div className="h-2.5 bg-gray-100 dark:bg-gray-700/50 rounded w-24" />
                  </div>
                </div>
              ))}
            </div>
          ) : devices.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-14 text-center px-4">
              <div className="w-12 h-12 rounded-xl bg-gray-100 dark:bg-gray-700 flex items-center justify-center mb-3">
                <svg className="w-6 h-6 text-gray-400 dark:text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.5">
                  <rect x="2" y="3" width="20" height="14" rx="2" />
                  <path d="M8 21h8M12 17v4" />
                </svg>
              </div>
              <p className="text-sm font-medium text-gray-600 dark:text-gray-400">No trusted devices</p>
              <p className="text-xs text-gray-400 dark:text-gray-500 mt-1">
                Devices are registered automatically when you log in from the CLI or desktop app.
              </p>
            </div>
          ) : (
            <ul className="divide-y divide-gray-100 dark:divide-gray-700">
              {devices.map((device) => (
                <li key={device.id} className="flex items-center gap-4 px-5 py-4">
                  <div className="w-10 h-10 rounded-xl bg-gray-100 dark:bg-gray-700 flex items-center justify-center shrink-0 text-gray-500 dark:text-gray-400">
                    <DeviceIcon type={device.deviceType} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-gray-900 dark:text-white truncate">{device.deviceName}</p>
                    <p className="text-xs text-gray-400 dark:text-gray-500 mt-0.5">
                      {DEVICE_TYPE_LABELS[device.deviceType] ?? device.deviceType}
                      {" · "}
                      Last seen {timeAgo(device.lastSeenAt)}
                      {" · "}
                      Added {timeAgo(device.createdAt)}
                    </p>
                  </div>
                  <button
                    onClick={() => handleRevoke(device.id)}
                    disabled={revoking === device.id}
                    className="shrink-0 px-3 py-1.5 text-xs font-medium text-red-600 dark:text-red-400 border border-red-200 dark:border-red-800 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {revoking === device.id ? "Revoking…" : "Revoke"}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>

        <p className="mt-4 text-xs text-gray-400 dark:text-gray-500 text-center">
          Revoking a device signs out all active sessions from that device.
        </p>
      </div>
    </div>
  );
}
