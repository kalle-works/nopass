// @vitest-environment node
import { describe, it, expect, beforeAll } from "vitest";
import {
  changeMasterPassword,
  completeAccountRecovery,
  computeEmailHash,
  createOpaqueRegistration,
  decryptItem,
  decryptUserPrivateKey,
  deriveMasterKey,
  deriveRecoveryKeys,
  encryptBytes,
  encryptItem,
  generateRecoveryCode,
  generateUserKeyPair,
  importAccountKeys,
  loginWithPassword,
  stretchMasterKey,
  stretchMasterKeyRaw,
  unlockAccount,
  unwrapVaultSubkeys,
  wrapVaultSubkeys,
} from "../index.js";
import { DEFAULT_KDF_PARAMS, type LoginItem } from "@nopass/types";
import { liveAuthApi } from "./support/live-api";

// (this package has no Node types, so read process.env through globalThis)
const env = (globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env;
const BASE = env?.["NOPASS_TEST_API_URL"] ?? "http://127.0.0.1:3001/v1";

async function apiCall(method: string, path: string, body?: unknown, token?: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  const r = await fetch(`${BASE}${path}`, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`${method} ${path} → ${r.status}: ${text}`);
  return text ? JSON.parse(text) : null;
}

const auth = liveAuthApi(apiCall);

async function register(email: string, password: string) {
  const masterKey = await deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);
  const keys = await stretchMasterKey(masterKey, email);
  const { encKeyBytes } = await stretchMasterKeyRaw(masterKey, email);
  const emailHash = computeEmailHash(email);
  const registrationRecord = await createOpaqueRegistration(password, DEFAULT_KDF_PARAMS, (registrationRequest) =>
    auth.opaqueRegisterStart({ emailHash, registrationRequest }),
  );
  const protectedKey = await encryptBytes(encKeyBytes, keys.stretchedMasterKey);
  const keyPair = await generateUserKeyPair(keys.stretchedMasterKey);

  await auth.opaqueRegisterFinish({
    emailHash,
    registrationRecord,
    kdfParams: DEFAULT_KDF_PARAMS,
    protectedSymmetricKey: protectedKey.blob,
    protectedSymmetricKeyIv: protectedKey.blobIv,
    publicKey: keyPair.publicKeyB64,
    protectedPrivateKey: keyPair.protectedPrivateKey,
    protectedPrivateKeyIv: keyPair.protectedPrivateKeyIv,
  });

  return { masterKey, keys };
}

/** What every client does: log in, then open (or on first use, migrate to) the account key. */
async function login(email: string, password: string) {
  const verifyResp = await loginWithPassword(auth, { email, password });
  const account = await unlockAccount(auth, { email, password, session: verifyResp });
  const keys = await importAccountKeys(account);
  return { keys, account, token: verifyResp.sessionToken, userId: verifyResp.userId, vaultId: verifyResp.defaultVaultId };
}

const EMAIL = `recovery-${Date.now()}@nopass.test`;
const PASSWORD = "original-passphrase-it-is-long";
const CHANGED_PASSWORD = "the-changed-passphrase-17";
const NEW_PASSWORD = "the-replacement-passphrase-42";

const SECRET_ITEM: LoginItem = {
  type: "login",
  name: "Bank Login",
  username: "alice",
  password: "hunter2-but-actually-long",
  totp: "",
  urls: ["https://bank.example"],
  notes: "do not lose this",
  customFields: [],
};

// Requires a running API server — skip cleanly when it isn't reachable
const apiAvailable = await fetch(`${BASE}/health`)
  .then((r) => r.ok)
  .catch(() => false);

describe.skipIf(!apiAvailable)("Recovery kit — end-to-end", () => {
  let recoveryCode: string;
  let itemId: string;

  beforeAll(async () => {
    await register(EMAIL, PASSWORD);
  }, 120_000);

  it("stores an item and enables the recovery kit", async () => {
    const { keys, account, token, vaultId } = await login(EMAIL, PASSWORD);

    const encrypted = await encryptItem(SECRET_ITEM, keys.vaultEncKey, keys.vaultMacKey);
    const created = await apiCall("POST", `/vaults/${vaultId}/items`, {
      itemType: "login",
      blob: encrypted.blob,
      blobIv: encrypted.blobIv,
      blobMac: encrypted.blobMac,
    }, token);
    itemId = created.id;

    recoveryCode = generateRecoveryCode();
    const { authKeyB64, wrapKey } = await deriveRecoveryKeys(recoveryCode, EMAIL);
    const blob = await wrapVaultSubkeys(account, wrapKey);

    await apiCall("PUT", "/auth/recovery", {
      recoveryAuthKey: authKeyB64,
      recoveryBlob: blob.blob,
      recoveryBlobIv: blob.blobIv,
    }, token);

    const status = await apiCall("GET", "/auth/recovery", undefined, token);
    expect(status.enabled).toBe(true);
  }, 120_000);

  it("changes the password without touching items; the old password stops working", async () => {
    const { token, userId } = await login(EMAIL, PASSWORD);
    await changeMasterPassword(auth, {
      email: EMAIL,
      userId,
      sessionToken: token,
      currentPassword: PASSWORD,
      newPassword: CHANGED_PASSWORD,
    });

    const { keys, vaultId, token: fresh } = await login(EMAIL, CHANGED_PASSWORD);
    const items = await apiCall("GET", `/vaults/${vaultId}/items`, undefined, fresh);
    expect(items[0].version).toBe(1);
    expect(await decryptItem(items[0], keys.vaultEncKey, keys.vaultMacKey)).toEqual(SECRET_ITEM);
    await expect(login(EMAIL, PASSWORD)).rejects.toThrow(/401/);
  }, 240_000);

  it("recovers with the kit made before the password change", async () => {
    const { authKeyB64, wrapKey } = await deriveRecoveryKeys(recoveryCode, EMAIL);
    const init = await apiCall("POST", "/auth/recovery/init", {
      emailHash: computeEmailHash(EMAIL),
      recoveryAuthKey: authKeyB64,
    });
    const recovered = await unwrapVaultSubkeys(
      { blob: init.recoveryBlob, blobIv: init.recoveryBlobIv, blobMac: "" },
      wrapKey,
    );
    await completeAccountRecovery(
      {
        opaqueStart: (req) => apiCall("POST", "/auth/recovery/opaque/start", req),
        complete: (req) => apiCall("POST", "/auth/recovery/complete", req),
      },
      { email: EMAIL, newPassword: NEW_PASSWORD, init, recovered },
    );
  }, 240_000);

  it("logs in with the new password and decrypts the item", async () => {
    const { keys, account, token, vaultId } = await login(EMAIL, NEW_PASSWORD);
    const items = await apiCall("GET", `/vaults/${vaultId}/items`, undefined, token);
    expect(items).toHaveLength(1);

    const plaintext = await decryptItem(
      { blob: items[0].blob, blobIv: items[0].blobIv, blobMac: items[0].blobMac },
      keys.vaultEncKey,
      keys.vaultMacKey,
    );
    expect(plaintext).toEqual(SECRET_ITEM);

    // The re-wrapped org keypair opens under the new stretched master key too
    const privateKey = await decryptUserPrivateKey(
      account.protectedPrivateKey!,
      account.protectedPrivateKeyIv!,
      keys.stretchedMasterKey,
    );
    expect(privateKey.type).toBe("private");
  }, 240_000);

  it("rejects the previous password and the burned recovery code", async () => {
    await expect(login(EMAIL, CHANGED_PASSWORD)).rejects.toThrow(/401/);

    const { authKeyB64 } = await deriveRecoveryKeys(recoveryCode, EMAIL);
    await expect(
      apiCall("POST", "/auth/recovery/init", {
        emailHash: computeEmailHash(EMAIL),
        recoveryAuthKey: authKeyB64,
      }),
    ).rejects.toThrow(/401/);
  }, 240_000);
});
