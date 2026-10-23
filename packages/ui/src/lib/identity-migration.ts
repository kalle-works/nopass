/**
 * Publishes the user's identity key the first time a client that knows about
 * identity keys unlocks the account, and checks on every unlock that the
 * server still serves the user's own key bundle unchanged.
 */
import type { PasswordProof } from "@nopass/types";
import { deriveIdentityKey, signKeyBundle } from "@nopass/crypto";
import { ApiError, type ApiClient } from "./api-client";

export interface OwnKeyMaterial {
  userId: string;
  protectedPrivateKey: string;
  protectedPrivateKeyIv: string;
  stretchedMasterKey: CryptoKey;
}

export class OwnKeyMismatchError extends Error {
  constructor(what: string) {
    super(
      `The server is publishing a different ${what} for your account than the one this device holds. Others may be encrypting to a key you do not control — contact support before sharing anything.`,
    );
    this.name = "OwnKeyMismatchError";
  }
}

/**
 * `prove` supplies a fresh password proof, which the server requires for the
 * first publish. Callers without the password omit it: the check still runs,
 * and publishing waits for the next sign-in.
 */
export async function ensureIdentityPublished(
  api: ApiClient,
  token: string,
  own: OwnKeyMaterial,
  prove?: () => Promise<PasswordProof>,
): Promise<void> {
  let published;
  try {
    published = await api.keys.me(token);
  } catch (err) {
    // No RSA key yet: nothing to vouch for until the first org is created
    if (err instanceof ApiError && err.status === 404) return;
    throw err;
  }

  const identity = await deriveIdentityKey(own.protectedPrivateKey, own.protectedPrivateKeyIv, own.stretchedMasterKey);
  try {
    if (published.publicKey !== identity.rsaPublicKeyB64) throw new OwnKeyMismatchError("public key");
    if (published.identityPublicKey === identity.publicKeyB64) return;
    if (published.identityPublicKey !== null) throw new OwnKeyMismatchError("identity key");
    if (!prove) return;

    await api.keys.setIdentity(
      {
        identityPublicKey: identity.publicKeyB64,
        publicKeySignature: signKeyBundle(own.userId, identity.rsaPublicKeyB64, identity.secretKey),
        proof: await prove(),
      },
      token,
    );
  } finally {
    identity.secretKey.fill(0);
  }
}
