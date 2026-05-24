import { generateKeyPairSync } from "crypto";
import { hostname, platform } from "os";
import {
  deriveMasterKey,
  stretchMasterKeyRaw,
  computeEmailHash,
  srpStep1,
  srpStep2,
} from "@nopass/crypto";
import { DEFAULT_KDF_PARAMS } from "@nopass/types";
import { createApiClient } from "./api-client.js";
import { saveSession, loadDeviceId, saveDeviceId, type Session } from "./session.js";

function deviceType(): "desktop_mac" | "android" | "web" | "extension" {
  return platform() === "darwin" ? "desktop_mac" : "desktop_mac";
}

function devicePublicKeyB64(): string {
  const { publicKey } = generateKeyPairSync("x25519");
  return publicKey.export({ type: "spki", format: "der" }).toString("base64");
}

export async function loginWithCredentials(
  email: string,
  password: string,
  apiUrl: string,
): Promise<void> {
  const masterKey = await deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);
  const { encKeyBytes, macKeyBytes } = await stretchMasterKeyRaw(masterKey, email);

  const api = createApiClient(apiUrl);
  const emailHash = computeEmailHash(email);
  const step1 = srpStep1();

  const initResp = await api.auth.srpInit({ emailHash, clientPublicA: step1.clientPublicA });

  // Include previously-registered device_id so server links the session
  const existingDeviceId = loadDeviceId();
  const step2 = srpStep2(email, password, initResp.srpSalt, initResp.serverPublicB, step1.privateSession);
  const verifyResp = await api.auth.srpVerify({
    sessionId: initResp.sessionId,
    clientProofM1: step2.clientProofM1,
    ...(existingDeviceId ? { deviceId: existingDeviceId } : {}),
  });

  step2.verifyServerProof(verifyResp.serverProofM2);

  // Register this machine as a trusted device on first login
  let deviceId = existingDeviceId;
  if (!deviceId) {
    try {
      const { deviceId: newId } = await api.devices.register(
        {
          deviceName: `${hostname()} (CLI)`,
          deviceType: deviceType(),
          devicePublicKey: devicePublicKeyB64(),
        },
        verifyResp.sessionToken,
      );
      deviceId = newId;
      saveDeviceId(deviceId);
    } catch {
      // Non-fatal: device registration failure doesn't prevent vault access
    }
  }

  const session: Session = {
    sessionToken: verifyResp.sessionToken,
    email,
    vaultEncKeyB64: Buffer.from(encKeyBytes).toString("base64"),
    vaultMacKeyB64: Buffer.from(macKeyBytes).toString("base64"),
    defaultVaultId: verifyResp.defaultVaultId,
    apiUrl,
    ...(deviceId ? { deviceId } : {}),
  };

  encKeyBytes.fill(0);
  macKeyBytes.fill(0);

  saveSession(session);
}

export async function importKeys(
  session: Session,
): Promise<{ vaultEncKey: CryptoKey; vaultMacKey: CryptoKey }> {
  const encKeyBytes = Buffer.from(session.vaultEncKeyB64, "base64");
  const macKeyBytes = Buffer.from(session.vaultMacKeyB64, "base64");

  const [vaultEncKey, vaultMacKey] = await Promise.all([
    crypto.subtle.importKey("raw", encKeyBytes, { name: "AES-GCM", length: 256 }, false, ["decrypt"]),
    crypto.subtle.importKey("raw", macKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]),
  ]);

  encKeyBytes.fill(0);
  macKeyBytes.fill(0);

  return { vaultEncKey, vaultMacKey };
}
