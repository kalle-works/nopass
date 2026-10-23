"use client";

import { useState } from "react";
import { changeMasterPassword, IncorrectPasswordError } from "@nopass/crypto";
import { ApiError, type ApiClient } from "../lib/api-client";
import { useNopassStore } from "../store/vault-store";
import { Banner } from "../primitives/Feedback";
import { Button } from "../primitives/Button";
import { Field } from "../primitives/Field";
import { StrengthMeter } from "../primitives/StrengthMeter";
import { estimateStrength, MASTER_PASSWORD_MIN_LEVEL } from "../primitives/strength";

/**
 * Changes the master password. Only the wrap of the account key changes, so
 * the vault stays unlocked with the same keys; other devices are signed out.
 */
export function ChangePasswordForm({ apiClient }: { apiClient: ApiClient }) {
  const { email, sessionToken } = useNopassStore();
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
    setProgress("Changing password…");
    try {
      await changeMasterPassword(apiClient.auth, {
        email,
        sessionToken,
        currentPassword: current,
        newPassword: next,
      });
      setNext("");
      setConfirm("");
      setDone(true);
    } catch (err) {
      if (err instanceof IncorrectPasswordError || (err instanceof ApiError && err.status === 401)) {
        setError("Your current master password is incorrect.");
      } else if (err instanceof ApiError && err.status === 409) {
        setError("Sign out and back in once so your account can be upgraded, then try again.");
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
      <Banner tone="success" title="Master password changed.">
        Your other devices are signed out. Your recovery kit still works.
      </Banner>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="flex max-w-md flex-col gap-4">
      <p className="text-ui text-muted">
        Changing it signs out your other devices. Your items and your recovery kit stay as they are.
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
