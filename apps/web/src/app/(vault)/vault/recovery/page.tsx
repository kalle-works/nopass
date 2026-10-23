"use client";

import { useCallback, useEffect, useState } from "react";
import { Badge, Banner, Button, Dialog, Field, IconButton, SecretText, useNopassStore } from "@nopass/ui";
import { X } from "lucide-react";
import { PageShell } from "@/components/vault/PageShell";
import {
  deriveMasterKey,
  deriveRecoveryKeys,
  generateRecoveryCode,
  loginWithPassword,
  stretchMasterKeyAllRaw,
  wrapVaultSubkeys,
} from "@nopass/crypto";
import { DEFAULT_KDF_PARAMS } from "@nopass/types";
import { api } from "@/lib/api";
import { downloadRecoveryKit } from "@/lib/recovery-kit";

type Phase = "idle" | "confirm-password" | "working" | "show-code";

export default function RecoveryPage() {
  const { sessionToken, email } = useNopassStore();

  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [updatedAt, setUpdatedAt] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState<string | null>(null);
  const [savedConfirmed, setSavedConfirmed] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [disabling, setDisabling] = useState(false);
  const [confirmDisable, setConfirmDisable] = useState(false);

  useEffect(() => {
    document.title = "Recovery — nopwd";
  }, []);

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
    if (!sessionToken) return;
    let cancelled = false;
    api.recovery
      .status(sessionToken)
      .then((status) => {
        if (cancelled) return;
        setEnabled(status.enabled);
        setUpdatedAt(status.updatedAt);
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load recovery status");
      });
    return () => {
      cancelled = true;
    };
  }, [sessionToken]);

  async function handleGenerate() {
    if (!sessionToken || !email) return;
    setError(null);
    setPhase("working");
    let subkeys: Awaited<ReturnType<typeof stretchMasterKeyAllRaw>> | null = null;
    try {
      // The vault keys in memory are non-extractable, so the kit is built from
      // the entered password — which also means we must prove it's the right
      // one before uploading a blob a future recovery would depend on.
      const masterKey = await deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);

      const check = await loginWithPassword(api.auth, { email, password });
      // The check above opened a session we don't need — close it
      api.auth.logout(check.sessionToken).catch(() => {});

      subkeys = await stretchMasterKeyAllRaw(masterKey, email);
      const newCode = generateRecoveryCode();
      const { authKeyB64, wrapKey } = await deriveRecoveryKeys(newCode, email);
      const blob = await wrapVaultSubkeys(subkeys, wrapKey);

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
    } finally {
      // Zero key material on every path, including failures
      subkeys?.smkBytes.fill(0);
      subkeys?.encKeyBytes.fill(0);
      subkeys?.macKeyBytes.fill(0);
    }
  }

  async function handleDisable() {
    if (!sessionToken) return;
    setDisabling(true);
    setError(null);
    try {
      await api.recovery.disable(sessionToken);
      await loadStatus();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to disable recovery");
    } finally {
      setDisabling(false);
      setConfirmDisable(false);
    }
  }

  return (
    <PageShell
      title="Recovery kit"
      description="A one-time code that restores access to your vault if you forget your master password. There is no reset: save your kit."
    >
      {error && (
        <Banner
          tone="danger"
          className="mb-4"
          action={
            <IconButton label="Dismiss error" onClick={() => setError(null)} className="-my-1 -mr-2">
              <X aria-hidden className="size-4" />
            </IconButton>
          }
        >
          {error}
        </Banner>
      )}

      <div className="space-y-5 rounded-lg border border-divider bg-surface p-5">
        {phase === "show-code" && code ? (
          <>
            <div>
              <h2 className="text-h2 font-semibold text-fg">Your new recovery code</h2>
              <p className="mb-4 mt-1 text-ui text-muted">
                This is shown <strong className="font-medium text-fg">once</strong>. Download the kit and store it
                offline. A printout in a safe place beats a file on this computer.
              </p>
              <div className="select-all break-all rounded border border-divider bg-bg-subtle p-4 text-body">
                <SecretText value={code} />
              </div>
            </div>
            <div className="flex flex-wrap items-center gap-4">
              <Button onClick={() => email && downloadRecoveryKit(email, code)}>Download kit (.txt)</Button>
              <label className="flex cursor-pointer items-center gap-2 text-ui text-fg">
                <input
                  type="checkbox"
                  checked={savedConfirmed}
                  onChange={(e) => setSavedConfirmed(e.target.checked)}
                  className="size-4 accent-accent"
                />
                I have stored this code somewhere safe
              </label>
            </div>
            <Button
              variant="primary"
              disabled={!savedConfirmed}
              onClick={() => {
                setCode(null);
                setPhase("idle");
              }}
            >
              Done
            </Button>
          </>
        ) : phase === "confirm-password" || phase === "working" ? (
          <>
            <div className="space-y-3">
              <h2 className="text-h2 font-semibold text-fg">Confirm your master password</h2>
              <p className="text-ui text-muted">
                The kit is derived from your master password on this device. Nothing readable leaves it.
              </p>
              <Field
                label="Master password"
                type="password"
                revealable
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                autoFocus
                onKeyDown={(e) => {
                  if (e.key === "Enter" && password && phase !== "working") handleGenerate();
                }}
              />
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="primary"
                onClick={handleGenerate}
                disabled={!password}
                pending={phase === "working"}
                pendingLabel="Generating…"
              >
                Generate recovery code
              </Button>
              <Button
                variant="ghost"
                onClick={() => {
                  setPassword("");
                  setPhase("idle");
                }}
                disabled={phase === "working"}
              >
                Cancel
              </Button>
            </div>
          </>
        ) : (
          <>
            <div>
              <h2 className="mb-2 text-h2 font-semibold text-fg">Status</h2>
              {enabled === null ? (
                <div className="h-5 w-40 animate-pulse rounded-sm bg-surface-active" />
              ) : enabled ? (
                <p className="flex flex-wrap items-center gap-2 text-ui text-fg">
                  <Badge tone="success">Enabled</Badge>
                  {updatedAt && <span className="text-muted">Kit generated {new Date(updatedAt).toLocaleDateString()}</span>}
                </p>
              ) : (
                <Banner tone="warning" title="Recovery is off">
                  If you forget your master password, your vault is gone for good.
                </Banner>
              )}
            </div>

            <p className="max-w-prose text-ui text-muted">
              The recovery kit wraps your vault keys with a random 160-bit code that only exists on paper. The server
              stores an encrypted blob it cannot read; the code never leaves your device. Generating a new kit
              invalidates the previous code.
            </p>

            <div className="flex items-center gap-2">
              <Button variant="primary" onClick={() => setPhase("confirm-password")} disabled={enabled === null}>
                {enabled ? "Generate new kit" : "Enable recovery"}
              </Button>
              {enabled && (
                <Button variant="secondary" onClick={() => setConfirmDisable(true)} disabled={disabling}>
                  Disable
                </Button>
              )}
            </div>
          </>
        )}
      </div>

      <Dialog
        open={confirmDisable}
        onClose={() => setConfirmDisable(false)}
        title="Disable account recovery?"
        description="If you forget your master password, your vault will be unrecoverable."
        footer={
          <>
            <Button variant="ghost" onClick={() => setConfirmDisable(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={handleDisable} pending={disabling} pendingLabel="Disabling…">
              Disable recovery
            </Button>
          </>
        }
      />
    </PageShell>
  );
}
