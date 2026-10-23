/**
 * Finishing a recovery with the account key the kit holds. The kit wraps the
 * vault keys (enc + mac), which are the account key, so recovery re-wraps
 * them under the new password and leaves every item as it is.
 */
import {
  DEFAULT_KDF_PARAMS,
  type OpaqueRegisterStartResponse,
  type RecoveryCompleteRequest,
  type RecoveryInitResponse,
} from "@nopass/types";

import { accountSmkBytes, wrapAccountKey } from "./account-key";
import { decryptBytes, encryptBytes } from "./aes-gcm";
import { computeEmailHash, deriveMasterKey } from "./kdf";
import { createOpaqueRegistration } from "./password-login";
import { deriveRecoveryKeys, generateRecoveryCode, wrapVaultSubkeys } from "./recovery";

export interface RecoveryCompletionApi {
  opaqueStart(req: { recoveryToken: string; emailHash: string; registrationRequest: string }): Promise<OpaqueRegisterStartResponse>;
  complete(req: RecoveryCompleteRequest): Promise<void>;
}

function importAes(bytes: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

/** Opens the private key with the account-key smk, or with the kit's legacy smk for unmigrated accounts. */
async function openPrivateKey(
  init: RecoveryInitResponse,
  smk: Uint8Array<ArrayBuffer>,
  kitSmk: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const blob = { blob: init.protectedPrivateKey!, blobIv: init.protectedPrivateKeyIv!, blobMac: "" };
  try {
    return await decryptBytes(blob, await importAes(smk));
  } catch {
    return decryptBytes(blob, await importAes(kitSmk));
  }
}

/** Sets the new password and returns the replacement recovery code (the used one is burned). */
export async function completeAccountRecovery(
  api: RecoveryCompletionApi,
  {
    email,
    newPassword,
    init,
    recovered,
  }: {
    email: string;
    newPassword: string;
    init: RecoveryInitResponse;
    /** What the kit unwrapped to */
    recovered: { smkBytes: Uint8Array<ArrayBuffer>; encKeyBytes: Uint8Array<ArrayBuffer>; macKeyBytes: Uint8Array<ArrayBuffer> };
  },
): Promise<string> {
  const account = { encKeyBytes: recovered.encKeyBytes, macKeyBytes: recovered.macKeyBytes };
  const smkBytes = accountSmkBytes(account);
  const masterKey = await deriveMasterKey(newPassword, email, DEFAULT_KDF_PARAMS);
  try {
    const registrationRecord = await createOpaqueRegistration(newPassword, DEFAULT_KDF_PARAMS, (registrationRequest) =>
      api.opaqueStart({ recoveryToken: init.recoveryToken, emailHash: computeEmailHash(email), registrationRequest }),
    );
    const wrapped = await wrapAccountKey(account, masterKey, email, init.userId);
    const smk = await importAes(smkBytes);
    const protectedKey = await encryptBytes(account.encKeyBytes, smk);

    let privateKey: Pick<RecoveryCompleteRequest, "protectedPrivateKey" | "protectedPrivateKeyIv"> = {};
    if (init.protectedPrivateKey && init.protectedPrivateKeyIv) {
      const pkcs8 = await openPrivateKey(init, smkBytes, recovered.smkBytes);
      const rewrapped = await encryptBytes(pkcs8, smk);
      pkcs8.fill(0);
      privateKey = { protectedPrivateKey: rewrapped.blob, protectedPrivateKeyIv: rewrapped.blobIv };
    }

    const replacementCode = generateRecoveryCode();
    const replacementKeys = await deriveRecoveryKeys(replacementCode, email);
    const replacementBlob = await wrapVaultSubkeys({ smkBytes, ...account }, replacementKeys.wrapKey);

    await api.complete({
      recoveryToken: init.recoveryToken,
      registrationRecord,
      protectedSymmetricKey: protectedKey.blob,
      protectedSymmetricKeyIv: protectedKey.blobIv,
      ...privateKey,
      ...wrapped,
      recoveryAuthKey: replacementKeys.authKeyB64,
      recoveryBlob: replacementBlob.blob,
      recoveryBlobIv: replacementBlob.blobIv,
    });
    return replacementCode;
  } finally {
    masterKey.fill(0);
    smkBytes.fill(0);
  }
}
