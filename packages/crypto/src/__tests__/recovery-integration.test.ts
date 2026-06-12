// @vitest-environment node
import { describe, it, expect, beforeAll } from "vitest";
import {
  computeEmailHash,
  deriveMasterKey,
  stretchMasterKey,
  stretchMasterKeyRaw,
  stretchMasterKeyAllRaw,
  srpStep1,
  srpStep2,
  generateSrpRegistration,
  generateUserKeyPair,
  decryptUserPrivateKey,
  encryptBytes,
  encryptItem,
  decryptItem,
  generateRecoveryCode,
  deriveRecoveryKeys,
  wrapVaultSubkeys,
  unwrapVaultSubkeys,
} from "../index.js";
import { DEFAULT_KDF_PARAMS, type LoginItem } from "@nopass/types";

const BASE = "http://127.0.0.1:3001/v1";

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

async function register(email: string, password: string) {
  const masterKey = await deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);
  const keys = await stretchMasterKey(masterKey, email);
  const { encKeyBytes } = await stretchMasterKeyRaw(masterKey, email);
  const { srpSalt, srpVerifier } = generateSrpRegistration(email, password);
  const protectedKey = await encryptBytes(encKeyBytes, keys.stretchedMasterKey);
  const keyPair = await generateUserKeyPair(keys.stretchedMasterKey);

  await apiCall("POST", "/auth/register", {
    emailHash: computeEmailHash(email),
    srpSalt,
    srpVerifier,
    kdfParams: DEFAULT_KDF_PARAMS,
    protectedSymmetricKey: protectedKey.blob,
    protectedSymmetricKeyIv: protectedKey.blobIv,
    publicKey: keyPair.publicKeyB64,
    protectedPrivateKey: keyPair.protectedPrivateKey,
    protectedPrivateKeyIv: keyPair.protectedPrivateKeyIv,
  });

  return { masterKey, keys };
}

async function login(email: string, password: string) {
  const masterKey = await deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);
  const keys = await stretchMasterKey(masterKey, email);
  const step1 = srpStep1();
  const initResp = await apiCall("POST", "/auth/srp/init", {
    emailHash: computeEmailHash(email),
    clientPublicA: step1.clientPublicA,
  });
  const step2 = srpStep2(email, password, initResp.srpSalt, initResp.serverPublicB, step1.privateSession);
  const verifyResp = await apiCall("POST", "/auth/srp/verify", {
    sessionId: initResp.sessionId,
    clientProofM1: step2.clientProofM1,
  });
  step2.verifyServerProof(verifyResp.serverProofM2);
  return { keys, token: verifyResp.sessionToken as string, vaultId: verifyResp.defaultVaultId as string, verifyResp };
}

const EMAIL = `recovery-${Date.now()}@nopass.test`;
const PASSWORD = "original-passphrase-it-is-long";
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
    const { keys, token, vaultId } = await login(EMAIL, PASSWORD);

    const encrypted = await encryptItem(SECRET_ITEM, keys.vaultEncKey, keys.vaultMacKey);
    const created = await apiCall("POST", `/vaults/${vaultId}/items`, {
      itemType: "login",
      blob: encrypted.blob,
      blobIv: encrypted.blobIv,
      blobMac: encrypted.blobMac,
    }, token);
    itemId = created.id;

    const masterKey = await deriveMasterKey(PASSWORD, EMAIL, DEFAULT_KDF_PARAMS);
    const subkeys = await stretchMasterKeyAllRaw(masterKey, EMAIL);
    recoveryCode = generateRecoveryCode();
    const { authKeyB64, wrapKey } = await deriveRecoveryKeys(recoveryCode, EMAIL);
    const blob = await wrapVaultSubkeys(subkeys, wrapKey);

    await apiCall("PUT", "/auth/recovery", {
      recoveryAuthKey: authKeyB64,
      recoveryBlob: blob.blob,
      recoveryBlobIv: blob.blobIv,
    }, token);

    const status = await apiCall("GET", "/auth/recovery", undefined, token);
    expect(status.enabled).toBe(true);
  }, 120_000);

  it("recovers the vault with the code and rotates to a new password", async () => {
    // ── What the /recover page does, step by step ──
    const { authKeyB64, wrapKey } = await deriveRecoveryKeys(recoveryCode, EMAIL);
    const init = await apiCall("POST", "/auth/recovery/init", {
      emailHash: computeEmailHash(EMAIL),
      recoveryAuthKey: authKeyB64,
    });
    expect(init.items).toHaveLength(1);

    const old = await unwrapVaultSubkeys(
      { blob: init.recoveryBlob, blobIv: init.recoveryBlobIv, blobMac: "" },
      wrapKey,
    );
    const oldEncKey = await crypto.subtle.importKey("raw", old.encKeyBytes, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    const oldMacKey = await crypto.subtle.importKey("raw", old.macKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const oldSmkKey = await crypto.subtle.importKey("raw", old.smkBytes, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);

    // The recovered keys really decrypt the vault
    const recovered = await decryptItem(
      { blob: init.items[0]!.blob, blobIv: init.items[0]!.blobIv, blobMac: init.items[0]!.blobMac },
      oldEncKey,
      oldMacKey,
    );
    expect(recovered).toEqual(SECRET_ITEM);

    // Re-encrypt under the new password
    const newMasterKey = await deriveMasterKey(NEW_PASSWORD, EMAIL, DEFAULT_KDF_PARAMS);
    const newKeys = await stretchMasterKey(newMasterKey, EMAIL);
    const newRaw = await stretchMasterKeyAllRaw(newMasterKey, EMAIL);
    const { srpSalt, srpVerifier } = generateSrpRegistration(EMAIL, NEW_PASSWORD);
    const reencrypted = await encryptItem(recovered, newKeys.vaultEncKey, newKeys.vaultMacKey);
    const protectedKey = await encryptBytes(newRaw.encKeyBytes, newKeys.stretchedMasterKey);

    const pkcs8 = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: Uint8Array.from(atob(init.protectedPrivateKeyIv), (c) => c.charCodeAt(0)) },
      oldSmkKey,
      Uint8Array.from(atob(init.protectedPrivateKey), (c) => c.charCodeAt(0)),
    );
    const rewrappedPrivate = await encryptBytes(new Uint8Array(pkcs8), newKeys.stretchedMasterKey);

    const replacementCode = generateRecoveryCode();
    const replacementKeys = await deriveRecoveryKeys(replacementCode, EMAIL);
    const replacementBlob = await wrapVaultSubkeys(newRaw, replacementKeys.wrapKey);

    await apiCall("POST", "/auth/recovery/complete", {
      recoveryToken: init.recoveryToken,
      srpSalt,
      srpVerifier,
      protectedSymmetricKey: protectedKey.blob,
      protectedSymmetricKeyIv: protectedKey.blobIv,
      protectedPrivateKey: rewrappedPrivate.blob,
      protectedPrivateKeyIv: rewrappedPrivate.blobIv,
      items: [{
        id: itemId,
        blob: reencrypted.blob,
        blobIv: reencrypted.blobIv,
        blobMac: reencrypted.blobMac,
      }],
      recoveryAuthKey: replacementKeys.authKeyB64,
      recoveryBlob: replacementBlob.blob,
      recoveryBlobIv: replacementBlob.blobIv,
    });
  }, 240_000);

  it("logs in with the new password and decrypts the item", async () => {
    const { keys, token, vaultId, verifyResp } = await login(EMAIL, NEW_PASSWORD);
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
      verifyResp.protectedPrivateKey,
      verifyResp.protectedPrivateKeyIv,
      keys.stretchedMasterKey,
    );
    expect(privateKey.type).toBe("private");
  }, 240_000);

  it("rejects the old password and the burned recovery code", async () => {
    await expect(login(EMAIL, PASSWORD)).rejects.toThrow(/401/);

    const { authKeyB64 } = await deriveRecoveryKeys(recoveryCode, EMAIL);
    await expect(
      apiCall("POST", "/auth/recovery/init", {
        emailHash: computeEmailHash(EMAIL),
        recoveryAuthKey: authKeyB64,
      }),
    ).rejects.toThrow(/401/);
  }, 240_000);
});
