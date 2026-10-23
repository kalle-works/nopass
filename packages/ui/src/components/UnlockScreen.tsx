import { useState, useEffect, useRef, type ReactNode } from "react";
import { DEFAULT_KDF_PARAMS } from "@nopass/types";
import {
  computeEmailHash,
  createOpaqueRegistration,
  deriveMasterKey,
  deriveRecoveryKeys,
  generateRecoveryCode,
  loginWithPassword,
  stretchMasterKey,
  importAccountKeys,
  unlockAccount,
  wrapVaultSubkeys,
  zeroAccount,
  type UnlockedAccount,
} from "@nopass/crypto";
import { ApiError, type ApiClient } from "../lib/api-client";
import { useNopassStore } from "../store/vault-store";
import { Banner } from "../primitives/Feedback";
import { Button } from "../primitives/Button";
import { Field } from "../primitives/Field";
import { SecretText } from "../primitives/Secret";
import { StrengthMeter } from "../primitives/StrengthMeter";
import { estimateStrength, MASTER_PASSWORD_MIN_LEVEL } from "../primitives/strength";

interface UnlockScreenProps {
  apiClient: ApiClient;
  mode: "login" | "register";
  onSuccess?: () => void;
  onSwitchMode: () => void;
  /** Shown in login mode — navigates to the recovery-kit flow */
  onForgotPassword?: () => void;
  /**
   * Register mode only. When provided, registration is followed by a recovery
   * kit step that cannot be skipped; `onSuccess` fires after the user confirms
   * they saved the kit. When omitted, registration completes without the step.
   */
  onDownloadRecoveryKit?: (email: string, code: string) => void;
  /** Where the logotype links to. Rendered as plain text when omitted. */
  homeHref?: string;
  /** Page footer content, e.g. links. */
  footer?: ReactNode;
}

/**
 * Page frame shared by the auth screens: logotype top-left, one centered
 * 400px column, optional footer. Follows the system or stored theme.
 */
export function AuthShell({
  children,
  homeHref,
  footer,
}: {
  children: ReactNode;
  homeHref?: string | undefined;
  footer?: ReactNode | undefined;
}) {
  const logotype = "font-mono text-h3 font-semibold tracking-tight text-fg";
  return (
    <div className="flex min-h-screen flex-col bg-bg text-fg">
      <header className="px-6 py-5">
        {homeHref ? (
          <a href={homeHref} className={logotype}>
            nopwd
          </a>
        ) : (
          <span className={logotype}>nopwd</span>
        )}
      </header>
      <main className="mx-auto flex w-full max-w-[432px] flex-1 flex-col justify-center px-4 pb-16">{children}</main>
      {footer && <footer className="px-6 py-5 text-meta text-muted">{footer}</footer>}
    </div>
  );
}

function humanizeError(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.status === 401) return "Incorrect email or master password.";
    if (err.status === 409) return "An account with this email already exists.";
    if (err.status === 429) return "Too many attempts. Wait a moment and try again.";
  }
  const msg = err instanceof Error ? err.message : String(err);
  if (msg === "Failed to fetch" || msg.includes("NetworkError") || msg.includes("ERR_FAILED")) {
    return "Could not reach the nopwd server. Check your connection and try again.";
  }
  if (msg.includes("CORS") || msg.includes("access control")) {
    return "Could not reach the nopwd server. Check your connection and try again.";
  }
  if (msg.toLowerCase().includes("unauthorized") || msg.includes("401")) {
    return "Incorrect email or master password.";
  }
  if (msg.toLowerCase().includes("conflict") || msg.includes("409")) {
    return "An account with this email already exists.";
  }
  if (msg.toLowerCase().includes("rate limit") || msg.includes("429")) {
    return "Too many attempts. Wait a moment and try again.";
  }
  return msg || "Something went wrong. Please try again.";
}

const LAST_EMAIL_STORAGE_KEY = "nopass:lastEmail";

function readLastEmail(): string {
  if (typeof localStorage === "undefined") return "";
  try {
    return localStorage.getItem(LAST_EMAIL_STORAGE_KEY) ?? "";
  } catch {
    return "";
  }
}

function writeLastEmail(email: string): void {
  if (typeof localStorage === "undefined") return;
  try {
    localStorage.setItem(LAST_EMAIL_STORAGE_KEY, email);
  } catch {
    // private mode / quota — remembering the email is best-effort
  }
}

const LINK_CLASS = "rounded-sm text-accent-text underline-offset-2 hover:underline";


type Phase = "form" | "kit";

export function UnlockScreen({
  apiClient,
  mode,
  onSuccess,
  onSwitchMode,
  onForgotPassword,
  onDownloadRecoveryKit,
  homeHref,
  footer,
}: UnlockScreenProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [passwordError, setPasswordError] = useState<string | null>(null);
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const [phase, setPhase] = useState<Phase>("form");
  const [kitCode, setKitCode] = useState<string | null>(null);
  const [kitSaved, setKitSaved] = useState(false);
  const [kitError, setKitError] = useState<string | null>(null);
  const [kitPending, setKitPending] = useState(false);
  // Held only between account creation and kit creation so a failed kit upload
  // can be retried without asking for the password again. Zeroed afterwards.
  const pendingKit = useRef<{ account: UnlockedAccount; sessionToken: string } | null>(null);
  const passwordInput = useRef<HTMLInputElement>(null);

  const { setSession } = useNopassStore();

  // Prefill in an effect, not useState — localStorage is unavailable during SSR
  // and a mismatch with the server-rendered empty input breaks hydration
  useEffect(() => {
    if (mode === "login") {
      const last = readLastEmail();
      if (last) {
        setEmail((current) => current || last);
        passwordInput.current?.focus();
      }
    }
  }, [mode]);

  useEffect(() => {
    document.title = mode === "login" ? "Sign in — nopwd" : "Create account — nopwd";
  }, [mode]);

  useEffect(() => () => clearPendingKit(), []);

  function clearPendingKit() {
    if (pendingKit.current) zeroAccount(pendingKit.current.account);
    pendingKit.current = null;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setPasswordError(null);
    setConfirmError(null);

    if (mode === "register") {
      if (estimateStrength(password, [email]).level < MASTER_PASSWORD_MIN_LEVEL) {
        setPasswordError("Choose a stronger master password. It has to reach Strong.");
        return;
      }
      if (password !== confirm) {
        setConfirmError("The passwords don't match.");
        return;
      }
    }

    setLoading(true);
    try {
      if (mode === "register") {
        await handleRegister();
      } else {
        await handleLogin();
      }
    } catch (err) {
      setError(humanizeError(err));
      setLoading(false);
      return;
    }
    writeLastEmail(email);
    setLoading(false);
    if (mode === "register" && onDownloadRecoveryKit) {
      setPhase("kit");
      await createKit();
    } else {
      onSuccess?.();
    }
  }

  async function handleRegister() {
    const { stretchMasterKeyRaw } = await import("@nopass/crypto");
    const kdfParams = DEFAULT_KDF_PARAMS;
    const emailHash = computeEmailHash(email);

    const masterKey = await deriveMasterKey(password, email, kdfParams);
    const keys = await stretchMasterKey(masterKey, email);

    const { encKeyBytes } = await stretchMasterKeyRaw(masterKey, email);
    const registrationRecord = await createOpaqueRegistration(password, kdfParams, (registrationRequest) =>
      apiClient.auth.opaqueRegisterStart({ emailHash, registrationRequest }),
    );

    const { encryptBytes } = await import("@nopass/crypto");
    const protectedKey = await encryptBytes(encKeyBytes, keys.stretchedMasterKey);
    encKeyBytes.fill(0);

    const { generateUserKeyPair } = await import("@nopass/crypto");
    const keyPair = await generateUserKeyPair(keys.stretchedMasterKey);

    await apiClient.auth.opaqueRegisterFinish({
      emailHash,
      registrationRecord,
      kdfParams,
      protectedSymmetricKey: protectedKey.blob,
      protectedSymmetricKeyIv: protectedKey.blobIv,
      publicKey: keyPair.publicKeyB64,
      protectedPrivateKey: keyPair.protectedPrivateKey,
      protectedPrivateKeyIv: keyPair.protectedPrivateKeyIv,
    });

    masterKey.fill(0);

    let unlocked: Awaited<ReturnType<typeof performLogin>>;
    try {
      // The first unlock moves the new account onto the wrapped account key.
      unlocked = await performLogin();
    } catch {
      // The account exists now; a retry of register would only hit "already exists"
      throw new Error("Your account was created, but signing in failed. Sign in to finish setting up your recovery kit.");
    }
    if (onDownloadRecoveryKit) {
      pendingKit.current = unlocked;
    } else {
      zeroAccount(unlocked.account);
    }
  }

  async function handleLogin() {
    const { account } = await performLogin();
    zeroAccount(account);
  }

  /** Logs in, opens the account key (migrating a legacy account) and loads the session. */
  async function performLogin(): Promise<{ account: UnlockedAccount; sessionToken: string }> {
    const auth = await loginWithPassword(apiClient.auth, { email, password });
    const account = await unlockAccount(apiClient.auth, { email, password, session: auth });
    const keys = await importAccountKeys(account);
    setSession(
      { ...auth, protectedPrivateKey: account.protectedPrivateKey, protectedPrivateKeyIv: account.protectedPrivateKeyIv },
      email,
      keys,
    );
    return { account, sessionToken: auth.sessionToken };
  }

  /** Wraps the account key under a fresh recovery code and uploads the blob. */
  async function createKit() {
    const pending = pendingKit.current;
    if (!pending) return;
    setKitError(null);
    setKitPending(true);
    try {
      const code = generateRecoveryCode();
      const { authKeyB64, wrapKey } = await deriveRecoveryKeys(code, email);
      const blob = await wrapVaultSubkeys(pending.account, wrapKey);
      await apiClient.recovery.set(
        { recoveryAuthKey: authKeyB64, recoveryBlob: blob.blob, recoveryBlobIv: blob.blobIv },
        pending.sessionToken,
      );
      clearPendingKit();
      setKitCode(code);
    } catch (err) {
      setKitError(humanizeError(err));
    } finally {
      setKitPending(false);
    }
  }

  if (phase === "kit") {
    return (
      <AuthShell homeHref={homeHref} footer={footer}>
        <h1 className="text-h1 font-semibold text-fg">Save your recovery kit</h1>
        <p className="mt-2 text-body text-muted">
          Your vault is created. If you forget your master password, this code is the only way back in. We can&apos;t
          reset it for you. It is shown once.
        </p>

        {kitError && (
          <Banner
            tone="danger"
            title="Couldn't create the recovery kit."
            className="mt-6"
            action={
              <Button size="sm" onClick={createKit} pending={kitPending} pendingLabel="Retrying…">
                Try again
              </Button>
            }
          >
            {kitError}
          </Banner>
        )}

        {!kitCode && !kitError && (
          <p role="status" className="mt-6 text-ui text-muted">
            Creating your recovery kit…
          </p>
        )}

        {kitCode && (
          <div className="mt-6 flex flex-col gap-4">
            <div className="select-all rounded-lg border border-border bg-surface p-4 text-mono-sm leading-6 sm:text-ui">
              <SecretText value={kitCode} />
            </div>
            <Button onClick={() => onDownloadRecoveryKit?.(email, kitCode)}>Download recovery kit</Button>
            <p className="text-meta text-muted">
              Print it or keep it offline. Anyone who has this code and your email can take over the account.
            </p>
            <label className="flex items-start gap-2.5 text-ui text-fg">
              <input
                type="checkbox"
                checked={kitSaved}
                onChange={(e) => setKitSaved(e.target.checked)}
                className="mt-0.5 size-4 accent-accent"
              />
              I&apos;ve saved my recovery kit
            </label>
            <Button variant="primary" size="lg" disabled={!kitSaved} onClick={() => onSuccess?.()}>
              Continue to your vault
            </Button>
          </div>
        )}
      </AuthShell>
    );
  }

  const isRegister = mode === "register";

  return (
    <AuthShell homeHref={homeHref} footer={footer}>
      <h1 className="text-h1 font-semibold text-fg">{isRegister ? "Create your vault" : "Unlock your vault"}</h1>
      <p className="mt-2 text-body text-muted">
        {isRegister
          ? "The server stores ciphertext. Your master password never leaves this device."
          : "Your master password never leaves this device."}
      </p>

      <form onSubmit={handleSubmit} className="mt-8 flex flex-col gap-5">
        <Field
          label="Email"
          type="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
          autoComplete="email"
          placeholder="you@example.com"
        />

        <div className="flex flex-col gap-2">
          <Field
            ref={passwordInput}
            label="Master password"
            type="password"
            revealable
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            autoComplete={isRegister ? "new-password" : "current-password"}
            error={passwordError}
          />
          {isRegister && <StrengthMeter password={password} userInputs={email ? [email] : undefined} />}
        </div>

        {isRegister && (
          <Field
            label="Confirm master password"
            type="password"
            revealable
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
            autoComplete="new-password"
            error={confirmError}
          />
        )}

        {isRegister && (
          <Banner tone="warning" title="No reset.">
            If you forget this password, only your recovery kit can get you back in. You&apos;ll save it next.
          </Banner>
        )}

        {error && <Banner tone="danger">{error}</Banner>}

        <Button
          type="submit"
          variant="primary"
          size="lg"
          pending={loading}
          pendingLabel={isRegister ? "Creating your vault…" : "Unlocking your vault…"}
        >
          {isRegister ? "Create vault" : "Unlock"}
        </Button>
        <span role="status" aria-live="polite" className="sr-only">
          {loading ? (isRegister ? "Creating your vault…" : "Unlocking your vault…") : ""}
        </span>
      </form>

      {mode === "login" && onForgotPassword && (
        <p className="mt-6 text-ui text-muted">
          Forgot master password?{" "}
          <button type="button" onClick={onForgotPassword} className={LINK_CLASS}>
            Use your recovery kit
          </button>
        </p>
      )}

      <p className={mode === "login" && onForgotPassword ? "mt-2 text-ui text-muted" : "mt-6 text-ui text-muted"}>
        {isRegister ? "Already have a vault? " : "New to nopwd? "}
        <button type="button" onClick={onSwitchMode} className={LINK_CLASS}>
          {isRegister ? "Sign in" : "Create a vault"}
        </button>
      </p>
    </AuthShell>
  );
}
