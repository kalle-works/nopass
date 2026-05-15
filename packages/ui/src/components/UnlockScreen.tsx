"use client";

import { useState } from "react";
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
}

export function UnlockScreen({ apiClient, mode, onSuccess, onSwitchMode }: UnlockScreenProps) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState<"kdf" | "auth" | null>(null);

  const { setSession } = useNopassStore();

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
      onSuccess?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
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

    setLoadingStep("auth");
    await apiClient.auth.register({
      emailHash: computeEmailHash(email),
      srpSalt,
      srpVerifier,
      kdfParams,
      protectedSymmetricKey: protectedKey.blob,
      protectedSymmetricKeyIv: protectedKey.blobIv,
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
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900 px-4">
      <div className="w-full max-w-sm">
        {/* Logo */}
        <div className="flex items-center justify-center mb-8">
          <div className="w-10 h-10 rounded-xl bg-blue-600 flex items-center justify-center">
            <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="1.75">
              <rect x="3" y="11" width="18" height="11" rx="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
          </div>
        </div>

        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-gray-200/80 dark:border-gray-700 p-8">
          <h1 className="text-xl font-semibold text-gray-900 dark:text-white mb-1">
            {mode === "login" ? "Unlock your vault" : "Create account"}
          </h1>
          <p className="text-sm text-gray-500 dark:text-gray-400 mb-6">
            {mode === "login"
              ? "Your master password never leaves this device."
              : "Choose a strong master password — it cannot be recovered."}
          </p>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
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
                className="w-full px-3 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm placeholder:text-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1.5">
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
                  className="w-full px-3 py-2.5 pr-10 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((s) => !s)}
                  className="absolute inset-y-0 right-0 flex items-center px-3 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300"
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
            </div>

            {error && (
              <div className="flex items-start gap-2.5 p-3 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
                <svg className="w-4 h-4 text-red-500 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
                </svg>
                <p className="text-sm text-red-700 dark:text-red-400">{error}</p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 disabled:opacity-70 text-white font-medium rounded-lg transition-colors text-sm flex items-center justify-center gap-2"
            >
              {loading && (
                <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
              )}
              {loading ? loadingMessage : mode === "register" ? "Create account" : "Unlock"}
            </button>
          </form>

          <p className="mt-5 text-center text-sm text-gray-500 dark:text-gray-400">
            {mode === "login" ? "New to nopass? " : "Already have an account? "}
            <button
              onClick={onSwitchMode}
              className="text-blue-600 dark:text-blue-400 hover:underline font-medium"
            >
              {mode === "login" ? "Create account" : "Sign in"}
            </button>
          </p>
        </div>

        {/* Security badge */}
        <div className="mt-5 flex items-center justify-center gap-1.5 text-xs text-gray-400 dark:text-gray-500">
          <svg className="w-3.5 h-3.5 text-green-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          AES-256-GCM · Argon2id · SRP-6a · Zero-knowledge
        </div>
      </div>
    </div>
  );
}
