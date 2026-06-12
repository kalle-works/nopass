"use client";

import { useState, useEffect } from "react";
import { DEFAULT_KDF_PARAMS } from "@nopass/types";
import { computeEmailHash, deriveMasterKey, stretchMasterKey } from "@nopass/crypto";
import type { ApiClient } from "../lib/api-client";
import { srpStep1, srpStep2 } from "@nopass/crypto";
import { useNopassStore } from "../store/vault-store";

interface UnlockScreenProps {
  apiClient: ApiClient;
  mode: "login" | "register";
  onSuccess?: () => void;
  onSwitchMode: () => void;
  /** Shown in login mode — navigates to the recovery-kit flow */
  onForgotPassword?: () => void;
}

function passwordStrength(pw: string): { score: 0 | 1 | 2 | 3 | 4; label: string; color: string; bg: string } {
  if (!pw) return { score: 0, label: "", color: "", bg: "" };
  let score = 0;
  if (pw.length >= 8) score++;
  if (pw.length >= 16) score++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if (/[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
  const labels = ["", "Weak", "Fair", "Strong", "Very strong"];
  const colors = ["", "text-[#FF5C39]", "text-amber-400", "text-[#D6FF3F]", "text-[#7CFF6B]"];
  const bgs = ["", "bg-[#FF5C39]", "bg-amber-400", "bg-[#D6FF3F]", "bg-[#7CFF6B]"];
  return { score: score as 0 | 1 | 2 | 3 | 4, label: labels[score]!, color: colors[score]!, bg: bgs[score]! };
}

function humanizeError(err: unknown): string {
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

export function UnlockScreen({ apiClient, mode, onSuccess, onSwitchMode, onForgotPassword }: UnlockScreenProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState<"kdf" | "auth" | null>(null);

  const { setSession } = useNopassStore();

  // Prefill in an effect, not useState — localStorage is unavailable during SSR
  // and a mismatch with the server-rendered empty input breaks hydration
  useEffect(() => {
    if (mode === "login") {
      const last = readLastEmail();
      if (last) setEmail((current) => current || last);
    }
  }, [mode]);

  useEffect(() => {
    document.title = mode === "login" ? "Sign in — nopwd" : "Create account — nopwd";
  }, [mode]);

  const strength = mode === "register" ? passwordStrength(password) : null;

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mode === "register") {
        await handleRegister();
      } else {
        await handleLogin();
      }
      writeLastEmail(email);
      onSuccess?.();
    } catch (err) {
      setError(humanizeError(err));
    } finally {
      setLoading(false);
      setLoadingStep(null);
    }
  }

  async function handleRegister() {
    const { generateSrpRegistration, stretchMasterKeyRaw } = await import("@nopass/crypto");
    const kdfParams = DEFAULT_KDF_PARAMS;

    setLoadingStep("kdf");
    const masterKey = await deriveMasterKey(password, email, kdfParams);
    const keys = await stretchMasterKey(masterKey, email);

    const { encKeyBytes } = await stretchMasterKeyRaw(masterKey, email);
    const { srpSalt, srpVerifier } = generateSrpRegistration(email, password);

    const { encryptBytes } = await import("@nopass/crypto");
    const protectedKey = await encryptBytes(encKeyBytes, keys.stretchedMasterKey);
    encKeyBytes.fill(0);

    const { generateUserKeyPair } = await import("@nopass/crypto");
    const keyPair = await generateUserKeyPair(keys.stretchedMasterKey);

    setLoadingStep("auth");
    await apiClient.auth.register({
      emailHash: computeEmailHash(email),
      srpSalt,
      srpVerifier,
      kdfParams,
      protectedSymmetricKey: protectedKey.blob,
      protectedSymmetricKeyIv: protectedKey.blobIv,
      publicKey: keyPair.publicKeyB64,
      protectedPrivateKey: keyPair.protectedPrivateKey,
      protectedPrivateKeyIv: keyPair.protectedPrivateKeyIv,
    });

    await performLogin(keys);
  }

  async function handleLogin() {
    setLoadingStep("kdf");
    const masterKey = await deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);
    const keys = await stretchMasterKey(masterKey, email);
    setLoadingStep("auth");
    await performLogin(keys);
  }

  async function performLogin(keys: Awaited<ReturnType<typeof stretchMasterKey>>) {
    const emailHash = computeEmailHash(email);
    const step1 = srpStep1();

    const initResp = await apiClient.auth.srpInit({
      emailHash,
      clientPublicA: step1.clientPublicA,
    });

    const step2 = srpStep2(
      email,
      password,
      initResp.srpSalt,
      initResp.serverPublicB,
      step1.privateSession,
    );

    const verifyResp = await apiClient.auth.srpVerify({
      sessionId: initResp.sessionId,
      clientProofM1: step2.clientProofM1,
    });

    step2.verifyServerProof(verifyResp.serverProofM2);
    setSession(verifyResp, email, keys);
  }

  const loadingMessage =
    loadingStep === "kdf"
      ? "Deriving key with Argon2id…"
      : loadingStep === "auth"
        ? "Authenticating…"
        : mode === "register"
          ? "Creating account…"
          : "Unlocking…";

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-[#070706] px-4 py-12">
      {/* Logo */}
      <div className="mb-8">
        <span className="font-mono text-sm font-semibold text-[#F4F1E8] tracking-tight">nopwd</span>
      </div>

      <div className="w-full max-w-sm">
        <div className="bg-[#11110F] border border-[#2B2923] p-8">
          <h1 className="font-mono text-xl font-semibold text-[#F4F1E8] mb-1">
            {mode === "login" ? "Unlock your vault" : "Create account"}
          </h1>
          <p className="text-sm text-[#9C988D] mb-6">
            {mode === "login"
              ? "Your master password never leaves this device."
              : "Pick a strong master password — it encrypts your entire vault."}
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
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
                className="w-full px-3 py-2.5 border border-[#2B2923] bg-[#070706] text-[#F4F1E8] text-sm placeholder:text-[#9C988D] focus:outline-none focus:border-[#D6FF3F] transition-colors"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-[#F4F1E8] mb-1.5">
                Master password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoComplete={mode === "register" ? "new-password" : "current-password"}
                  className="w-full px-3 py-2.5 pr-10 border border-[#2B2923] bg-[#070706] text-[#F4F1E8] text-sm focus:outline-none focus:border-[#D6FF3F] transition-colors"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((s) => !s)}
                  className="absolute inset-y-0 right-0 flex items-center px-3 text-[#9C988D] hover:text-[#F4F1E8] transition-colors"
                  tabIndex={-1}
                >
                  {showPassword ? (
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                      <line x1="1" y1="1" x2="23" y2="23" />
                    </svg>
                  ) : (
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
              </div>

              {/* Password strength — register only */}
              {mode === "register" && strength && password && (
                <div className="mt-2">
                  <div className="flex gap-1 mb-1">
                    {[1, 2, 3, 4].map((i) => (
                      <div
                        key={i}
                        className={`h-0.5 flex-1 transition-all duration-300 ${
                          i <= strength.score ? strength.bg : "bg-[#2B2923]"
                        }`}
                      />
                    ))}
                  </div>
                  <p className={`font-mono text-xs ${strength.color}`}>{strength.label}</p>
                </div>
              )}
            </div>

            {/* Recovery warning — register only */}
            {mode === "register" && (
              <div className="flex items-start gap-2.5 p-3 border border-amber-500/20 bg-amber-500/5">
                <svg className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                  <line x1="12" y1="9" x2="12" y2="13" />
                  <line x1="12" y1="17" x2="12.01" y2="17" />
                </svg>
                <p className="text-xs text-amber-400 leading-relaxed">
                  <strong className="font-semibold">Write this password down.</strong> It encrypts your vault and cannot be reset — not even by us.
                </p>
              </div>
            )}

            {error && (
              <div className="flex items-start gap-2.5 p-3 border border-[#FF5C39]/30 bg-[#FF5C39]/5">
                <svg className="w-4 h-4 text-[#FF5C39] mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <p className="text-sm text-[#FF5C39]">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 bg-[#D6FF3F] hover:bg-[#c8ef3a] disabled:opacity-50 text-[#070706] font-mono font-semibold transition-colors text-sm flex items-center justify-center gap-2"
            >
              {loading && (
                <svg className="w-4 h-4 animate-spin shrink-0" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              )}
              {loading ? loadingMessage : mode === "register" ? "Create account" : "Unlock"}
            </button>
          </form>

          <p className="mt-5 text-center text-sm text-[#9C988D]">
            {mode === "login" ? "New to nopwd? " : "Already have an account? "}
            <button
              onClick={onSwitchMode}
              className="text-[#D6FF3F] hover:underline underline-offset-2 font-medium"
            >
              {mode === "login" ? "Create account" : "Sign in"}
            </button>
          </p>

          {mode === "login" && onForgotPassword && (
            <p className="mt-2 text-center text-xs text-[#9C988D]">
              Forgot your master password?{" "}
              <button
                onClick={onForgotPassword}
                className="text-[#9C988D] hover:text-[#D6FF3F] underline underline-offset-2 transition-colors"
              >
                Use your recovery kit
              </button>
            </p>
          )}
        </div>

        {/* Security badge */}
        <div className="mt-4 flex items-center justify-center gap-1.5 text-xs text-[#9C988D]">
          <span className="font-mono">AES-256-GCM · Argon2id · SRP-6a · Zero-knowledge</span>
        </div>
      </div>
    </div>
  );
}
