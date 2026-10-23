/**
 * Master-password change. Vault items are encrypted under keys derived from
 * the master password, so a change re-encrypts every item; the server swaps
 * them in together with the new OPAQUE record in one transaction, after
 * checking a fresh OPAQUE proof of the current password. The recovery kit
 * wrapped the old keys and is cleared; other sessions are revoked.
 */
import * as opaque from "@serenity-kit/opaque";
import {
  DEFAULT_KDF_PARAMS,
  type PasswordChangeFinishRequest,
  type PasswordChangeStartRequest,
  type PasswordChangeStartResponse,
  type ReencryptedItem,
} from "@nopass/types";

import { decryptBytes, decryptItem, encryptBytes, encryptItem } from "./aes-gcm";
import { computeEmailHash, deriveMasterKey, stretchMasterKey, stretchMasterKeyAllRaw } from "./kdf";
import type { DerivedKeys } from "./types";

export interface PasswordChangeApi {
  passwordChangeStart(req: PasswordChangeStartRequest, token: string): Promise<PasswordChangeStartResponse>;
  passwordChangeFinish(req: PasswordChangeFinishRequest, token: string): Promise<void>;
}

/** The current password didn't open the server's login response. */
export class IncorrectPasswordError extends Error {
  constructor() {
    super("Current master password is incorrect.");
    this.name = "IncorrectPasswordError";
  }
}

export interface PasswordChangeOptions {
  email: string;
  sessionToken: string;
  currentPassword: string;
  newPassword: string;
  onProgress?: (step: string) => void;
}

function keyStretching(params: { iterations: number; memoryKib: number; parallelism: number }) {
  return {
    "argon2id-custom": { iterations: params.iterations, memory: params.memoryKib, parallelism: params.parallelism },
  } as const;
}

/** Changes the master password; returns the new vault keys for the session. */
export async function changeMasterPassword(
  api: PasswordChangeApi,
  { email, sessionToken, currentPassword, newPassword, onProgress }: PasswordChangeOptions,
): Promise<DerivedKeys> {
  await opaque.ready;
  const login = opaque.client.startLogin({ password: currentPassword });
  const registration = opaque.client.startRegistration({ password: newPassword });
  const started = await api.passwordChangeStart(
    {
      emailHash: computeEmailHash(email),
      startLoginRequest: login.startLoginRequest,
      registrationRequest: registration.registrationRequest,
    },
    sessionToken,
  );

  const proof = opaque.client.finishLogin({
    clientLoginState: login.clientLoginState,
    loginResponse: started.loginResponse,
    password: currentPassword,
    keyStretching: keyStretching(started.kdfParams),
  });
  if (!proof) throw new IncorrectPasswordError();
  const { registrationRecord } = opaque.client.finishRegistration({
    clientRegistrationState: registration.clientRegistrationState,
    registrationResponse: started.registrationResponse,
    password: newPassword,
    keyStretching: keyStretching(started.kdfParams),
  });

  // Vault keys come from the same fixed parameters every client derives them with.
  onProgress?.("Deriving keys…");
  const oldMaster = await deriveMasterKey(currentPassword, email, DEFAULT_KDF_PARAMS);
  const oldKeys = await stretchMasterKey(oldMaster, email);
  oldMaster.fill(0);
  const newMaster = await deriveMasterKey(newPassword, email, DEFAULT_KDF_PARAMS);
  const newKeys = await stretchMasterKey(newMaster, email);
  const newRaw = await stretchMasterKeyAllRaw(newMaster, email);
  newMaster.fill(0);

  try {
    onProgress?.(`Re-encrypting ${started.items.length} item${started.items.length === 1 ? "" : "s"}…`);
    const items: ReencryptedItem[] = [];
    for (const item of started.items) {
      const plaintext = await decryptItem(
        { blob: item.blob, blobIv: item.blobIv, blobMac: item.blobMac },
        oldKeys.vaultEncKey,
        oldKeys.vaultMacKey,
      );
      const reencrypted = await encryptItem(plaintext, newKeys.vaultEncKey, newKeys.vaultMacKey);
      items.push({ id: item.id, ...reencrypted });
    }

    const protectedKey = await encryptBytes(newRaw.encKeyBytes, newKeys.stretchedMasterKey);
    let privateKey: Pick<PasswordChangeFinishRequest, "protectedPrivateKey" | "protectedPrivateKeyIv"> = {};
    if (started.protectedPrivateKey && started.protectedPrivateKeyIv) {
      const pkcs8 = await decryptBytes(
        { blob: started.protectedPrivateKey, blobIv: started.protectedPrivateKeyIv, blobMac: "" },
        oldKeys.stretchedMasterKey,
      );
      const rewrapped = await encryptBytes(pkcs8, newKeys.stretchedMasterKey);
      pkcs8.fill(0);
      privateKey = { protectedPrivateKey: rewrapped.blob, protectedPrivateKeyIv: rewrapped.blobIv };
    }

    onProgress?.("Applying…");
    await api.passwordChangeFinish(
      {
        changeId: started.changeId,
        finishLoginRequest: proof.finishLoginRequest,
        registrationRecord,
        protectedSymmetricKey: protectedKey.blob,
        protectedSymmetricKeyIv: protectedKey.blobIv,
        ...privateKey,
        items,
      },
      sessionToken,
    );
    return newKeys;
  } finally {
    newRaw.smkBytes.fill(0);
    newRaw.encKeyBytes.fill(0);
    newRaw.macKeyBytes.fill(0);
  }
}
