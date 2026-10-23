"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  completeAccountRecovery,
  computeEmailHash,
  deriveRecoveryKeys,
  unwrapVaultSubkeys,
} from "@nopass/crypto";
import type { RecoveryInitResponse } from "@nopass/types";
import {
  AuthShell,
  Banner,
  Button,
  estimateStrength,
  Field,
  MASTER_PASSWORD_MIN_LEVEL,
  SecretText,
  StrengthMeter,
} from "@nopass/ui";
import { api } from "@/lib/api";
import { AuthFooter } from "@/components/auth/auth-footer";
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
    // Same policy as registration, so recovery can't set a weaker master password
    if (estimateStrength(newPassword, email ? [email] : []).level < MASTER_PASSWORD_MIN_LEVEL) {
      setError("Choose a stronger master password. It has to reach Strong.");
      return;
    }
    if (newPassword !== newPassword2) {
      setError("The passwords don't match.");
      return;
    }
    setError(null);
    setLoading(true);
    try {
      // The kit holds the account key: re-wrap it under the new password;
      // no item is re-encrypted.
      setProgress("Deriving new keys (Argon2id)…");
      const replacementCode = await completeAccountRecovery(
        { opaqueStart: api.recovery.opaqueStart, complete: api.recovery.complete },
        { email, newPassword, init, recovered: oldSubkeys },
      );

      // Only on success — a failed attempt must stay retryable with the same keys
      oldSubkeys.smkBytes.fill(0);
      oldSubkeys.encKeyBytes.fill(0);
      oldSubkeys.macKeyBytes.fill(0);
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

  const LINK = "rounded-sm text-accent-text underline-offset-2 hover:underline";

  return (
    <AuthShell homeHref="/" footer={<AuthFooter />}>
      {step === "code" && (
        <>
          <h1 className="text-h1 font-semibold text-fg">Recover your account</h1>
          <p className="mt-2 text-body text-muted">
            Enter the recovery code from your kit. Decryption happens on this device.
          </p>
          <form onSubmit={handleVerifyCode} className="mt-8 flex flex-col gap-5">
            <Field
              label="Email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
              placeholder="you@example.com"
            />
            <Field
              label="Recovery code"
              mono
              value={code}
              onChange={(e) => setCode(e.target.value)}
              required
              spellCheck={false}
              autoComplete="off"
              placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
            />
            {error && <Banner tone="danger">{error}</Banner>}
            <Button type="submit" variant="primary" size="lg" pending={loading} pendingLabel={progress ?? "Working…"}>
              Continue
            </Button>
          </form>
          <p className="mt-6 text-ui text-muted">
            Remembered it after all?{" "}
            <button type="button" onClick={() => router.push("/login")} className={LINK}>
              Sign in
            </button>
          </p>
        </>
      )}

      {step === "new-password" && (
        <>
          <h1 className="text-h1 font-semibold text-fg">Choose a new master password</h1>
          <p className="mt-2 text-body text-muted">
            Your vault keys come back from the recovery kit and are locked under the new password. Your items
            stay as they are.
          </p>
          <form onSubmit={handleSetPassword} className="mt-8 flex flex-col gap-5">
            <div className="flex flex-col gap-2">
              <Field
                label="New master password"
                type="password"
                revealable
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                required
                minLength={8}
                autoComplete="new-password"
              />
              <StrengthMeter password={newPassword} userInputs={email ? [email] : undefined} />
            </div>
            <Field
              label="Confirm new master password"
              type="password"
              revealable
              value={newPassword2}
              onChange={(e) => setNewPassword2(e.target.value)}
              required
              autoComplete="new-password"
            />
            {error && <Banner tone="danger">{error}</Banner>}
            <Button type="submit" variant="primary" size="lg" pending={loading} pendingLabel={progress ?? "Working…"}>
              Set new password
            </Button>
          </form>
        </>
      )}

      {step === "done" && newCode && (
        <>
          <h1 className="text-h1 font-semibold text-fg">Vault recovered</h1>
          <p className="mt-2 text-body text-muted">
            Your old recovery code no longer works. This is your new one. It is shown once.
          </p>
          <div className="mt-6 flex flex-col gap-4">
            <div className="select-all rounded-lg border border-border bg-surface p-4 text-mono-sm leading-6 sm:text-ui">
              <SecretText value={newCode} />
            </div>
            <Button onClick={() => downloadRecoveryKit(email, newCode)}>Download recovery kit</Button>
            <label className="flex items-start gap-2.5 text-ui text-fg">
              <input
                type="checkbox"
                checked={savedConfirmed}
                onChange={(e) => setSavedConfirmed(e.target.checked)}
                className="mt-0.5 size-4 accent-accent"
              />
              I&apos;ve saved the new recovery kit
            </label>
            <Button variant="primary" size="lg" disabled={!savedConfirmed} onClick={() => router.replace("/login")}>
              Sign in with the new password
            </Button>
          </div>
        </>
      )}
    </AuthShell>
  );
}
