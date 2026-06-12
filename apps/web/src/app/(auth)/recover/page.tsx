"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  computeEmailHash,
  decryptBytes,
  decryptItem,
  deriveMasterKey,
  deriveRecoveryKeys,
  encryptBytes,
  encryptItem,
  generateRecoveryCode,
  generateSrpRegistration,
  stretchMasterKey,
  stretchMasterKeyAllRaw,
  unwrapVaultSubkeys,
  wrapVaultSubkeys,
} from "@nopass/crypto";
import { DEFAULT_KDF_PARAMS, type RecoveryInitResponse, type ReencryptedItem } from "@nopass/types";
import { api } from "@/lib/api";
import { downloadRecoveryKit } from "@/lib/recovery-kit";

type Step = "code" | "new-password" | "done";

function humanizeError(err: unknown): string {
  const msg = err instanceof Error ? err.message : String(err);
  if (msg === "Failed to fetch" || msg.includes("NetworkError")) {
    return "Could not reach the nopwd server. Check your connection and try again.";
  }
  if (msg.toLowerCase().includes("invalid recovery") || msg.toLowerCase().includes("unauthorized")) {
    return "That email and recovery code combination doesn't match.";
  }
  if (msg.toLowerCase().includes("operationerror") || msg.toLowerCase().includes("decrypt")) {
    return "The recovery code didn't decrypt your vault keys. Double-check it character by character.";
  }
  if (msg.toLowerCase().includes("rate limit") || msg.includes("429")) {
    return "Too many attempts. Wait a moment and try again.";
  }
  return msg || "Something went wrong. Please try again.";
}

const inputClass =
  "w-full px-3 py-2.5 border border-[#2B2923] bg-[#070706] text-[#F4F1E8] text-sm placeholder:text-[#9C988D]/60 focus:outline-none focus:border-[#D6FF3F] transition-colors";

export default function RecoverPage() {
  const router = useRouter();

  const [step, setStep] = useState<Step>("code");
  const [email, setEmail] = useState("");
  const [code, setCode] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newPassword2, setNewPassword2] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState<string | null>(null);
  const [newCode, setNewCode] = useState<string | null>(null);
  const [savedConfirmed, setSavedConfirmed] = useState(false);

  // Carried between steps
  const [init, setInit] = useState<RecoveryInitResponse | null>(null);
  const [oldSubkeys, setOldSubkeys] = useState<{
    smkBytes: Uint8Array<ArrayBuffer>;
    encKeyBytes: Uint8Array<ArrayBuffer>;
    macKeyBytes: Uint8Array<ArrayBuffer>;
  } | null>(null);

  async function handleVerifyCode(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      setProgress("Deriving recovery key…");
      const { authKeyB64, wrapKey } = await deriveRecoveryKeys(code, email);

      setProgress("Verifying with server…");
      const resp = await api.recovery.init({
        emailHash: computeEmailHash(email),
        recoveryAuthKey: authKeyB64,
      });

      setProgress("Unlocking vault keys…");
      const subkeys = await unwrapVaultSubkeys(
        { blob: resp.recoveryBlob, blobIv: resp.recoveryBlobIv, blobMac: "" },
        wrapKey,
      );

      setInit(resp);
      setOldSubkeys(subkeys);
      setStep("new-password");
    } catch (err) {
      setError(humanizeError(err));
    } finally {
      setLoading(false);
      setProgress(null);
    }
  }

  async function handleSetPassword(e: React.FormEvent) {
    e.preventDefault();
    if (!init || !oldSubkeys) return;
    if (newPassword !== newPassword2) {
      setError("The passwords don't match.");
      return;
    }
    setError(null);
    setLoading(true);
    try {
      setProgress("Importing old keys…");
      const importAes = (bytes: Uint8Array<ArrayBuffer>, usages: KeyUsage[]) =>
        crypto.subtle.importKey("raw", bytes, { name: "AES-GCM", length: 256 }, false, usages);
      const oldEncKey = await importAes(oldSubkeys.encKeyBytes, ["decrypt"]);
      const oldMacKey = await crypto.subtle.importKey(
        "raw",
        oldSubkeys.macKeyBytes,
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["verify"],
      );
      const oldSmkKey = await importAes(oldSubkeys.smkBytes, ["decrypt"]);

      setProgress("Deriving new keys (Argon2id)…");
      const newMasterKey = await deriveMasterKey(newPassword, email, DEFAULT_KDF_PARAMS);
      const newKeys = await stretchMasterKey(newMasterKey, email);
      const newRaw = await stretchMasterKeyAllRaw(newMasterKey, email);
      const { srpSalt, srpVerifier } = generateSrpRegistration(email, newPassword);

      setProgress(`Re-encrypting ${init.items.length} item${init.items.length === 1 ? "" : "s"}…`);
      const items: ReencryptedItem[] = [];
      for (const item of init.items) {
        const plaintext = await decryptItem(
          { blob: item.blob, blobIv: item.blobIv, blobMac: item.blobMac },
          oldEncKey,
          oldMacKey,
        );
        const reencrypted = await encryptItem(plaintext, newKeys.vaultEncKey, newKeys.vaultMacKey);
        items.push({
          id: item.id,
          blob: reencrypted.blob,
          blobIv: reencrypted.blobIv,
          blobMac: reencrypted.blobMac,
        });
      }

      setProgress("Re-wrapping keys…");
      const protectedKey = await encryptBytes(newRaw.encKeyBytes, newKeys.stretchedMasterKey);

      let protectedPrivateKey: string | undefined;
      let protectedPrivateKeyIv: string | undefined;
      if (init.protectedPrivateKey && init.protectedPrivateKeyIv) {
        const pkcs8 = await decryptBytes(
          { blob: init.protectedPrivateKey, blobIv: init.protectedPrivateKeyIv, blobMac: "" },
          oldSmkKey,
        );
        const rewrapped = await encryptBytes(pkcs8, newKeys.stretchedMasterKey);
        pkcs8.fill(0);
        protectedPrivateKey = rewrapped.blob;
        protectedPrivateKeyIv = rewrapped.blobIv;
      }

      // The used code is burned server-side — issue a fresh kit in the same pass
      const replacementCode = generateRecoveryCode();
      const replacementKeys = await deriveRecoveryKeys(replacementCode, email);
      const replacementBlob = await wrapVaultSubkeys(newRaw, replacementKeys.wrapKey);

      newRaw.smkBytes.fill(0);
      newRaw.encKeyBytes.fill(0);
      newRaw.macKeyBytes.fill(0);
      oldSubkeys.smkBytes.fill(0);
      oldSubkeys.encKeyBytes.fill(0);
      oldSubkeys.macKeyBytes.fill(0);

      setProgress("Applying…");
      await api.recovery.complete({
        recoveryToken: init.recoveryToken,
        srpSalt,
        srpVerifier,
        protectedSymmetricKey: protectedKey.blob,
        protectedSymmetricKeyIv: protectedKey.blobIv,
        ...(protectedPrivateKey ? { protectedPrivateKey, protectedPrivateKeyIv } : {}),
        items,
        recoveryAuthKey: replacementKeys.authKeyB64,
        recoveryBlob: replacementBlob.blob,
        recoveryBlobIv: replacementBlob.blobIv,
      });

      setInit(null);
      setOldSubkeys(null);
      setNewCode(replacementCode);
      setStep("done");
    } catch (err) {
      setError(humanizeError(err));
    } finally {
      setLoading(false);
      setProgress(null);
    }
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-[#070706] px-4 py-12">
      <div className="mb-8">
        <span className="font-mono text-sm font-semibold text-[#F4F1E8] tracking-tight">nopwd</span>
      </div>

      <div className="w-full max-w-sm">
        <div className="bg-[#11110F] border border-[#2B2923] p-8">
          {step === "code" && (
            <>
              <h1 className="font-mono text-xl font-semibold text-[#F4F1E8] mb-1">Recover your account</h1>
              <p className="text-sm text-[#9C988D] mb-6">
                Enter the recovery code from your kit. Decryption happens on this device.
              </p>
              <form onSubmit={handleVerifyCode} className="space-y-4">
                <div>
                  <label htmlFor="email" className="block text-sm font-medium text-[#F4F1E8] mb-1.5">
                    Email
                  </label>
                  <input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    autoComplete="email"
                    placeholder="you@example.com"
                    className={inputClass}
                  />
                </div>
                <div>
                  <label htmlFor="code" className="block text-sm font-medium text-[#F4F1E8] mb-1.5">
                    Recovery code
                  </label>
                  <input
                    id="code"
                    type="text"
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    required
                    spellCheck={false}
                    autoComplete="off"
                    placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
                    className={`${inputClass} font-mono`}
                  />
                </div>
                {error && <p className="text-sm text-[#FF5C39]">{error}</p>}
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 px-4 bg-[#D6FF3F] hover:bg-[#c8ef3a] disabled:opacity-50 text-[#070706] font-mono font-semibold transition-colors text-sm"
                >
                  {loading ? progress ?? "Working…" : "Continue"}
                </button>
              </form>
              <p className="mt-5 text-center text-sm text-[#9C988D]">
                Remembered it after all?{" "}
                <button
                  onClick={() => router.push("/login")}
                  className="text-[#D6FF3F] hover:underline underline-offset-2 font-medium"
                >
                  Sign in
                </button>
              </p>
            </>
          )}

          {step === "new-password" && (
            <>
              <h1 className="font-mono text-xl font-semibold text-[#F4F1E8] mb-1">Choose a new master password</h1>
              <p className="text-sm text-[#9C988D] mb-6">
                Your vault will be re-encrypted on this device under the new password.
              </p>
              <form onSubmit={handleSetPassword} className="space-y-4">
                <div>
                  <label htmlFor="new-password" className="block text-sm font-medium text-[#F4F1E8] mb-1.5">
                    New master password
                  </label>
                  <input
                    id="new-password"
                    type="password"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                    minLength={8}
                    autoComplete="new-password"
                    className={inputClass}
                  />
                </div>
                <div>
                  <label htmlFor="new-password-2" className="block text-sm font-medium text-[#F4F1E8] mb-1.5">
                    Repeat it
                  </label>
                  <input
                    id="new-password-2"
                    type="password"
                    value={newPassword2}
                    onChange={(e) => setNewPassword2(e.target.value)}
                    required
                    autoComplete="new-password"
                    className={inputClass}
                  />
                </div>
                {error && <p className="text-sm text-[#FF5C39]">{error}</p>}
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full py-2.5 px-4 bg-[#D6FF3F] hover:bg-[#c8ef3a] disabled:opacity-50 text-[#070706] font-mono font-semibold transition-colors text-sm"
                >
                  {loading ? progress ?? "Working…" : "Re-encrypt vault"}
                </button>
              </form>
            </>
          )}

          {step === "done" && newCode && (
            <>
              <h1 className="font-mono text-xl font-semibold text-[#7CFF6B] mb-1">Vault recovered</h1>
              <p className="text-sm text-[#9C988D] mb-4">
                Your old recovery code is now invalid. Here is your{" "}
                <strong className="text-[#F4F1E8]">new</strong> one — shown once:
              </p>
              <div className="font-mono text-sm text-[#F4F1E8] bg-[#070706] border border-[#2B2923] p-4 break-all select-all mb-4">
                {newCode}
              </div>
              <div className="space-y-3">
                <button
                  onClick={() => downloadRecoveryKit(email, newCode)}
                  className="w-full py-2.5 px-4 border border-[#2B2923] text-[#F4F1E8] hover:bg-[#181713] font-mono font-semibold transition-colors text-sm"
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
                  I have stored the new code somewhere safe
                </label>
                <button
                  disabled={!savedConfirmed}
                  onClick={() => router.replace("/login")}
                  className="w-full py-2.5 px-4 bg-[#D6FF3F] hover:bg-[#c8ef3a] disabled:opacity-40 text-[#070706] font-mono font-semibold transition-colors text-sm"
                >
                  Sign in with the new password
                </button>
              </div>
            </>
          )}
        </div>

        <div className="mt-4 flex items-center justify-center gap-1.5 text-xs text-[#9C988D]">
          <span className="font-mono">AES-256-GCM · Argon2id · SRP-6a · Zero-knowledge</span>
        </div>
      </div>
    </div>
  );
}
