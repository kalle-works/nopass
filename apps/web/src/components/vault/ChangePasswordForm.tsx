"use client";

import { useState } from "react";
import { changeMasterPassword, IncorrectPasswordError } from "@nopass/crypto";
import {
  ApiError,
  Banner,
  Button,
  estimateStrength,
  Field,
  MASTER_PASSWORD_MIN_LEVEL,
  StrengthMeter,
  useNopassStore,
} from "@nopass/ui";
import { api } from "@/lib/api";

/**
 * Changes the master password. Every item is re-encrypted in this browser,
 * so it takes a few seconds per hundred items. Afterwards the vault locks:
 * items in memory are still the old ciphertext, and signing in again loads
 * them under the new keys.
 */
export function ChangePasswordForm() {
  const { email, sessionToken, lock } = useNopassStore();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [progress, setProgress] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!email || !sessionToken) return;
    setError(null);
    if (estimateStrength(next, [email]).level < MASTER_PASSWORD_MIN_LEVEL) {
      setError("Choose a stronger master password. It has to reach Strong.");
      return;
    }
    if (next !== confirm) {
      setError("The new passwords don't match.");
      return;
    }
    setProgress("Checking your current password…");
    try {
      await changeMasterPassword(api.auth, {
        email,
        sessionToken,
        currentPassword: current,
        newPassword: next,
        onProgress: setProgress,
      });
      setDone(true);
    } catch (err) {
      if (err instanceof IncorrectPasswordError || (err instanceof ApiError && err.status === 401)) {
        setError("Your current master password is incorrect.");
      } else if (err instanceof ApiError && err.status === 429) {
        setError("Too many attempts. Wait a moment and try again.");
      } else {
        setError(err instanceof Error ? err.message : "Couldn't change the password. Nothing was changed.");
      }
    } finally {
      setProgress(null);
      setCurrent("");
    }
  }

  if (done) {
    return (
      <Banner
        tone="success"
        title="Master password changed."
        action={
          <Button size="sm" onClick={lock}>
            Sign in again
          </Button>
        }
      >
        Your other devices are signed out. Your old recovery kit no longer works, so create a new one under Recovery
        after you sign in.
      </Banner>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="flex max-w-md flex-col gap-4">
      <p className="text-ui text-muted">
        Changing it re-encrypts every item on this device, signs out your other devices and turns off your current
        recovery kit.
      </p>
      {error && <Banner tone="danger" title={error} />}
      <Field
        label="Current master password"
        type="password"
        revealable
        value={current}
        onChange={(e) => setCurrent(e.target.value)}
        required
        autoComplete="current-password"
      />
      <div>
        <Field
          label="New master password"
          type="password"
          revealable
          value={next}
          onChange={(e) => setNext(e.target.value)}
          required
          autoComplete="new-password"
        />
        <StrengthMeter password={next} userInputs={email ? [email] : undefined} />
      </div>
      <Field
        label="Confirm new master password"
        type="password"
        revealable
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
        required
        autoComplete="new-password"
      />
      <div>
        <Button type="submit" pending={progress !== null} pendingLabel={progress ?? undefined}>
          Change master password
        </Button>
      </div>
    </form>
  );
}
