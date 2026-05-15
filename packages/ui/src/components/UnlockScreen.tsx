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
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

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
    }
  }

  async function handleRegister() {
    const { generateSrpRegistration, stretchMasterKeyRaw } = await import("@nopass/crypto");
    const kdfParams = DEFAULT_KDF_PARAMS;

    // Derive master key (Argon2id, ~2s)
    const masterKey = await deriveMasterKey(password, email, kdfParams);
    const keys = await stretchMasterKey(masterKey, email);

    // Get raw vault key bytes — exportKey would fail because keys are non-extractable CryptoKeys
    const { encKeyBytes } = await stretchMasterKeyRaw(masterKey, email);

    // Generate SRP registration material
    const { srpSalt, srpVerifier } = generateSrpRegistration(email, password);

    // Encrypt the vault key with the stretched master key for server storage
    const { encryptBytes } = await import("@nopass/crypto");
    const protectedKey = await encryptBytes(encKeyBytes, keys.stretchedMasterKey);
    encKeyBytes.fill(0);

    await apiClient.auth.register({
      emailHash: computeEmailHash(email),
      srpSalt,
      srpVerifier,
      kdfParams,
      protectedSymmetricKey: protectedKey.blob,
      protectedSymmetricKeyIv: protectedKey.blobIv,
    });

    // Auto-login after registration
    await performLogin(keys);
  }

  async function handleLogin() {
    const masterKey = await deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);
    const keys = await stretchMasterKey(masterKey, email);
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
      clientPublicA: step1.clientPublicA,
      clientProofM1: step2.clientProofM1,
    });

    // Verify server proof (ensures server knows the verifier — mutual auth)
    step2.verifyServerProof(verifyResp.serverProofM2);

    setSession(verifyResp, email, keys);
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-900">
      <div className="w-full max-w-md p-8 bg-white dark:bg-gray-800 rounded-2xl shadow-lg">
        <h1 className="text-2xl font-semibold text-gray-900 dark:text-white mb-1">
          {mode === "login" ? "Unlock vault" : "Create account"}
        </h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mb-8">
          {mode === "login"
            ? "Your master password never leaves this device."
            : "Choose a strong master password — it cannot be recovered."}
        </p>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              htmlFor="email"
              className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
            >
              Email
            </label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              autoComplete="email"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          <div>
            <label
              htmlFor="password"
              className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1"
            >
              Master password
            </label>
            <input
              id="password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete={mode === "register" ? "new-password" : "current-password"}
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            />
          </div>

          {error && (
            <p className="text-sm text-red-600 dark:text-red-400">{error}</p>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-400 text-white font-medium rounded-lg transition-colors"
          >
            {loading
              ? mode === "register"
                ? "Creating account…"
                : "Unlocking…"
              : mode === "register"
                ? "Create account"
                : "Unlock"}
          </button>
        </form>

        <p className="mt-6 text-center text-sm text-gray-500 dark:text-gray-400">
          {mode === "login" ? "New to nopass? " : "Already have an account? "}
          <button
            onClick={onSwitchMode}
            className="text-blue-600 dark:text-blue-400 hover:underline font-medium"
          >
            {mode === "login" ? "Create account" : "Sign in"}
          </button>
        </p>
      </div>
    </div>
  );
}
