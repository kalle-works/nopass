import {
  deriveMasterKey,
  stretchMasterKeyRaw,
  computeEmailHash,
  srpStep1,
  srpStep2,
} from "@nopass/crypto";
import { DEFAULT_KDF_PARAMS } from "@nopass/types";
import { createApiClient } from "./api-client.js";
import { saveSession, type Session } from "./session.js";

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
  const step2 = srpStep2(email, password, initResp.srpSalt, initResp.serverPublicB, step1.privateSession);
  const verifyResp = await api.auth.srpVerify({ sessionId: initResp.sessionId, clientProofM1: step2.clientProofM1 });

  step2.verifyServerProof(verifyResp.serverProofM2);

  const session: Session = {
    sessionToken: verifyResp.sessionToken,
    email,
    vaultEncKeyB64: Buffer.from(encKeyBytes).toString("base64"),
    vaultMacKeyB64: Buffer.from(macKeyBytes).toString("base64"),
    defaultVaultId: verifyResp.defaultVaultId,
    apiUrl,
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
