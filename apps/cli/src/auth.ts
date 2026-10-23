import { generateKeyPairSync } from "crypto";
import { hostname, platform } from "os";
import { loginWithPassword, unlockAccount, zeroAccount } from "@nopass/crypto";
import type { DeviceType } from "@nopass/types";
import { createApiClient } from "./api-client.js";
import { fileAccountState, saveSession, loadDeviceId, saveDeviceId, type Session } from "./session.js";

function deviceType(): DeviceType {
  switch (platform()) {
    case "darwin":
      return "desktop_mac";
    case "win32":
      return "desktop_windows";
    default:
      return "desktop_linux";
  }
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
  const api = createApiClient(apiUrl);

  // Include previously-registered device_id so server links the session
  const existingDeviceId = loadDeviceId();
  const accountState = fileAccountState();
  const auth = await loginWithPassword(api.auth, {
    email,
    password,
    accountState,
    ...(existingDeviceId ? { deviceId: existingDeviceId } : {}),
  });
  // Opens the account key; a legacy account is migrated to it here.
  const account = await unlockAccount(api.auth, { email, password, session: auth, accountState });
  const { encKeyBytes, macKeyBytes } = account;

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
        auth.sessionToken,
      );
      deviceId = newId;
      saveDeviceId(deviceId);
    } catch {
      // Non-fatal: device registration failure doesn't prevent vault access
    }
  }

  const session: Session = {
    sessionToken: auth.sessionToken,
    email,
    userId: auth.userId,
    vaultEncKeyB64: Buffer.from(encKeyBytes).toString("base64"),
    vaultMacKeyB64: Buffer.from(macKeyBytes).toString("base64"),
    defaultVaultId: auth.defaultVaultId,
    apiUrl,
    ...(deviceId ? { deviceId } : {}),
  };

  zeroAccount(account);

  saveSession(session);
}

/**
 * Imports the vault keys from the session. They are read-only unless `write`
 * is set, so commands that only fetch secrets can't produce new ciphertext.
 */
export async function importKeys(
  session: Session,
  { write = false }: { write?: boolean } = {},
): Promise<{ vaultEncKey: CryptoKey; vaultMacKey: CryptoKey }> {
  const encKeyBytes = Buffer.from(session.vaultEncKeyB64, "base64");
  const macKeyBytes = Buffer.from(session.vaultMacKeyB64, "base64");

  const [vaultEncKey, vaultMacKey] = await Promise.all([
    crypto.subtle.importKey("raw", encKeyBytes, { name: "AES-GCM", length: 256 }, false, write ? ["encrypt", "decrypt"] : ["decrypt"]),
    // sign is needed even read-only: local trust state is named by an HMAC under this key
    crypto.subtle.importKey("raw", macKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]),
  ]);

  encKeyBytes.fill(0);
  macKeyBytes.fill(0);

  return { vaultEncKey, vaultMacKey };
}
