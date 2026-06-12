"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useNopassStore } from "@nopass/ui";
import {
  computeEmailHash,
  deriveMasterKey,
  deriveRecoveryKeys,
  generateRecoveryCode,
  srpStep1,
  srpStep2,
  stretchMasterKeyAllRaw,
  wrapVaultSubkeys,
} from "@nopass/crypto";
import { DEFAULT_KDF_PARAMS } from "@nopass/types";
import { api } from "@/lib/api";
import { downloadRecoveryKit } from "@/lib/recovery-kit";

type Phase = "idle" | "confirm-password" | "working" | "show-code";

export default function RecoveryPage() {
  const router = useRouter();
  const { isUnlocked, sessionToken, email } = useNopassStore();

  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState<string | null>(null);
  const [savedConfirmed, setSavedConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [disabling, setDisabling] = useState(false);

  useEffect(() => {
    if (!isUnlocked()) router.replace("/login");
  }, [isUnlocked, router]);

  const loadStatus = useCallback(async () => {
    if (!sessionToken) return;
    try {
      const status = await api.recovery.status(sessionToken);
      setEnabled(status.enabled);
      setUpdatedAt(status.updatedAt);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load recovery status");
    }
  }, [sessionToken]);

  useEffect(() => {
    loadStatus();
  }, [loadStatus]);

  async function handleGenerate() {
    if (!sessionToken || !email) return;
    setError(null);
    setPhase("working");
    try {
      // The vault keys in memory are non-extractable, so the kit is built from
      // the entered password — which also means we must prove it's the right
      // one before uploading a blob a future recovery would depend on.
      const masterKey = await deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);

      const step1 = srpStep1();
      const initResp = await api.auth.srpInit({
        emailHash: computeEmailHash(email),
        clientPublicA: step1.clientPublicA,
      });
      const step2 = srpStep2(email, password, initResp.srpSalt, initResp.serverPublicB, step1.privateSession);
      const verifyResp = await api.auth.srpVerify({
        sessionId: initResp.sessionId,
        clientProofM1: step2.clientProofM1,
      });
      step2.verifyServerProof(verifyResp.serverProofM2);
      // The check above opened a session we don't need — close it
      api.auth.logout(verifyResp.sessionToken).catch(() => {});

      const subkeys = await stretchMasterKeyAllRaw(masterKey, email);
      const newCode = generateRecoveryCode();
      const { authKeyB64, wrapKey } = await deriveRecoveryKeys(newCode, email);
      const blob = await wrapVaultSubkeys(subkeys, wrapKey);
      subkeys.smkBytes.fill(0);
      subkeys.encKeyBytes.fill(0);
      subkeys.macKeyBytes.fill(0);

      await api.recovery.set(
        { recoveryAuthKey: authKeyB64, recoveryBlob: blob.blob, recoveryBlobIv: blob.blobIv },
        sessionToken,
      );

      setPassword("");
      setCode(newCode);
      setSavedConfirmed(false);
      setPhase("show-code");
      await loadStatus();
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setError(
        msg.toLowerCase().includes("unauthorized") || msg.toLowerCase().includes("authentication")
          ? "Incorrect master password."
          : msg,
      );
      setPhase("confirm-password");
    }
  }

  async function handleDisable() {
    if (!sessionToken) return;
    if (!confirm("Disable account recovery? If you forget your master password, your vault will be unrecoverable.")) {
      return;
    }
    setDisabling(true);
    setError(null);
    try {
      await api.recovery.disable(sessionToken);
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to disable recovery");
    } finally {
      setDisabling(false);
    }
  }

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
            <h1 className="font-mono text-sm font-semibold text-[#F4F1E8] uppercase tracking-widest">Recovery Kit</h1>
            <p className="text-xs text-[#9C988D] mt-0.5">
              A one-time code that can restore access to your vault if you forget your master password.
            </p>
          </div>
        </div>

        {error && (
          <div className="mb-4 flex items-center gap-2.5 p-3 bg-[#E8321A]/10 border border-[#E8321A]/30 text-sm text-[#E8321A]">
            <svg className="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="8" x2="12" y2="12" />
              <line x1="12" y1="16" x2="12.01" y2="16" />
            </svg>
            {error}
            <button onClick={() => setError(null)} className="ml-auto p-0.5 hover:text-[#F4F1E8]">
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          </div>
        )}

        <div className="bg-[#11110F] border border-[#2B2923] p-6 space-y-5">
          {phase === "show-code" && code ? (
            <>
              <div>
                <h2 className="font-mono text-xs font-semibold text-[#D6FF3F] uppercase tracking-widest mb-2">
                  Your new recovery code
                </h2>
                <p className="text-sm text-[#9C988D] mb-4">
                  This is shown <strong className="text-[#F4F1E8]">once</strong>. Download the kit and store it
                  offline — a printout in a safe place beats a file on this computer.
                </p>
                <div className="font-mono text-sm text-[#F4F1E8] bg-[#070706] border border-[#2B2923] p-4 break-all select-all">
                  {code}
                </div>
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={() => email && downloadRecoveryKit(email, code)}
                  className="px-3.5 py-2 font-mono text-xs font-semibold bg-[#D6FF3F] hover:bg-[#C4EE30] text-[#070706] transition-colors"
                >
                  Download kit (.txt)
                </button>
                <label className="flex items-center gap-2 text-xs text-[#9C988D] cursor-pointer">
                  <input
                    type="checkbox"
                    checked={savedConfirmed}
                    onChange={(e) => setSavedConfirmed(e.target.checked)}
                    className="accent-[#D6FF3F]"
                  />
                  I have stored this code somewhere safe
                </label>
              </div>
              <button
                disabled={!savedConfirmed}
                onClick={() => {
                  setCode(null);
                  setPhase("idle");
                }}
                className="px-3.5 py-2 font-mono text-xs font-semibold border border-[#2B2923] text-[#F4F1E8] hover:bg-[#181713] disabled:opacity-40 transition-colors"
              >
                Done
              </button>
            </>
          ) : phase === "confirm-password" || phase === "working" ? (
            <>
              <div>
                <h2 className="font-mono text-xs font-semibold text-[#F4F1E8] uppercase tracking-widest mb-2">
                  Confirm your master password
                </h2>
                <p className="text-sm text-[#9C988D] mb-4">
                  The kit is derived from your master password on this device. Nothing readable leaves it.
                </p>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                  autoFocus
                  placeholder="Master password"
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && password && phase !== "working") handleGenerate();
                  }}
                  className="w-full px-3 py-2.5 border border-[#2B2923] bg-[#070706] text-[#F4F1E8] text-sm placeholder:text-[#9C988D]/60 focus:outline-none focus:border-[#D6FF3F] transition-colors"
                />
              </div>
              <div className="flex items-center gap-3">
                <button
                  onClick={handleGenerate}
                  disabled={!password || phase === "working"}
                  className="px-3.5 py-2 font-mono text-xs font-semibold bg-[#D6FF3F] hover:bg-[#C4EE30] text-[#070706] disabled:opacity-50 transition-colors"
                >
                  {phase === "working" ? "Generating…" : "Generate recovery code"}
                </button>
                <button
                  onClick={() => {
                    setPassword("");
                    setPhase("idle");
                  }}
                  disabled={phase === "working"}
                  className="px-3.5 py-2 font-mono text-xs text-[#9C988D] hover:text-[#F4F1E8] transition-colors"
                >
                  Cancel
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h2 className="font-mono text-xs font-semibold text-[#F4F1E8] uppercase tracking-widest mb-1.5">
                    Status
                  </h2>
                  {enabled === null ? (
                    <div className="h-4 w-40 bg-[#2B2923] animate-pulse" />
                  ) : enabled ? (
                    <p className="text-sm text-[#7CFF6B]">
                      Recovery is enabled
                      {updatedAt && (
                        <span className="text-[#9C988D]"> · kit generated {new Date(updatedAt).toLocaleDateString()}</span>
                      )}
                    </p>
                  ) : (
                    <p className="text-sm text-amber-400">
                      Recovery is off — if you forget your master password, your vault is gone for good.
                    </p>
                  )}
                </div>
              </div>

              <p className="text-sm text-[#9C988D] leading-relaxed">
                The recovery kit wraps your vault keys with a random 160-bit code that only exists on paper.
                The server stores an encrypted blob it cannot read; the code never leaves your device.
                Generating a new kit invalidates the previous code.
              </p>

              <div className="flex items-center gap-3">
                <button
                  onClick={() => setPhase("confirm-password")}
                  disabled={enabled === null}
                  className="px-3.5 py-2 font-mono text-xs font-semibold bg-[#D6FF3F] hover:bg-[#C4EE30] text-[#070706] disabled:opacity-50 transition-colors"
                >
                  {enabled ? "Generate new kit" : "Enable recovery"}
                </button>
                {enabled && (
                  <button
                    onClick={handleDisable}
                    disabled={disabling}
                    className="px-3.5 py-2 font-mono text-xs font-semibold border border-[#E8321A]/40 text-[#E8321A] hover:bg-[#E8321A]/10 disabled:opacity-50 transition-colors"
                  >
                    {disabling ? "Disabling…" : "Disable"}
                  </button>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
