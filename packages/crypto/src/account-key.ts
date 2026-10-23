/**
 * Password-independent account key.
 *
 * The account key is the pair of vault keys (enc + mac) that encrypt every
 * item. For accounts created before it existed, it is exactly the pair the
 * password used to derive, so no item is ever re-encrypted. It is stored on
 * the server AES-GCM-wrapped under a key-encryption key (KEK) derived from
 * the master password, with AAD binding the user id and purpose; a password
 * change only re-wraps it.
 *
 *   masterKey = Argon2id(password, SHA-256("nopass-v1-kdf:" + email))   (unchanged)
 *   KEK       = HKDF-SHA256(masterKey, salt = email, info = "nopass-v2-account-kek")
 *   wrapped   = AES-256-GCM(KEK, enc || mac, AAD = "nopass-v2-account-key:" + userId)
 *   smk       = HKDF-SHA256(enc || mac, info = "nopass-v2-smk")
 *
 * The smk (which wraps the RSA private key and the protected symmetric key)
 * also comes from the account key now, so nothing tied to the password is
 * left. The recovery kit already wraps enc + mac, so it keeps working across
 * password changes.
 */
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import {
  DEFAULT_KDF_PARAMS,
  type LoginResponse,
  type SetAccountKeyRequest,
} from "@nopass/types";

import { decryptBytes, encryptBytes } from "./aes-gcm";
import { deriveMasterKey, stretchMasterKeyAllRaw } from "./kdf";
import type { DerivedKeys } from "./types";

const enc = new TextEncoder();
const toAb = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(bytes);

export interface AccountKey {
  encKeyBytes: Uint8Array<ArrayBuffer>;
  macKeyBytes: Uint8Array<ArrayBuffer>;
}

export interface WrappedAccountKey {
  wrappedAccountKey: string;
  wrappedAccountKeyIv: string;
}

/** The account key could not be opened — the server returned a blob that isn't this account's. */
export class AccountKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccountKeyError";
  }
}

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function aad(userId: string): Uint8Array<ArrayBuffer> {
  return toAb(enc.encode(`nopass-v2-account-key:${userId}`));
}

async function kek(masterKey: Uint8Array, email: string): Promise<CryptoKey> {
  const bytes = hkdf(sha256, masterKey, enc.encode(email.toLowerCase()), enc.encode("nopass-v2-account-kek"), 32);
  return crypto.subtle.importKey("raw", toAb(bytes), { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

function importAes(bytes: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

/** The key that wraps the RSA private key, derived from the account key. */
export function accountSmkBytes(account: AccountKey): Uint8Array<ArrayBuffer> {
  const ikm = new Uint8Array(64);
  ikm.set(account.encKeyBytes, 0);
  ikm.set(account.macKeyBytes, 32);
  const smk = toAb(hkdf(sha256, ikm, new Uint8Array(0), enc.encode("nopass-v2-smk"), 32));
  ikm.fill(0);
  return smk;
}

export async function wrapAccountKey(
  account: AccountKey,
  masterKey: Uint8Array,
  email: string,
  userId: string,
): Promise<WrappedAccountKey> {
  const plaintext = new Uint8Array(64);
  plaintext.set(account.encKeyBytes, 0);
  plaintext.set(account.macKeyBytes, 32);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad(userId) },
    await kek(masterKey, email),
    plaintext,
  );
  plaintext.fill(0);
  return { wrappedAccountKey: toBase64(new Uint8Array(ciphertext)), wrappedAccountKeyIv: toBase64(iv) };
}

export async function unwrapAccountKey(
  wrapped: WrappedAccountKey,
  masterKey: Uint8Array,
  email: string,
  userId: string,
): Promise<AccountKey> {
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromBase64(wrapped.wrappedAccountKeyIv), additionalData: aad(userId) },
        await kek(masterKey, email),
        fromBase64(wrapped.wrappedAccountKey),
      ),
    );
  } catch {
    throw new AccountKeyError("The account key could not be opened with this password.");
  }
  const account = { encKeyBytes: toAb(plaintext.slice(0, 32)), macKeyBytes: toAb(plaintext.slice(32, 64)) };
  plaintext.fill(0);
  return account;
}

/** The unlocked account: vault keys plus the smk that matches the stored private-key wrap. */
export interface UnlockedAccount extends AccountKey {
  smkBytes: Uint8Array<ArrayBuffer>;
  /** The private-key wrap that `smkBytes` opens (it changes when a legacy account migrates). */
  protectedPrivateKey: string | null;
  protectedPrivateKeyIv: string | null;
}

export async function importAccountKeys(account: UnlockedAccount): Promise<DerivedKeys> {
  const [stretchedMasterKey, vaultEncKey, vaultMacKey] = await Promise.all([
    importAes(account.smkBytes),
    importAes(account.encKeyBytes),
    crypto.subtle.importKey("raw", account.macKeyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]),
  ]);
  return { stretchedMasterKey, vaultEncKey, vaultMacKey };
}

export function zeroAccount(account: Partial<Pick<UnlockedAccount, "encKeyBytes" | "macKeyBytes" | "smkBytes">>): void {
  account.encKeyBytes?.fill(0);
  account.macKeyBytes?.fill(0);
  account.smkBytes?.fill(0);
}

export interface AccountKeyApi {
  setAccountKey(req: SetAccountKeyRequest, token: string): Promise<void>;
}

/**
 * Opens the account after a successful login. Migrated accounts unwrap the
 * stored account key. Legacy accounts derive their keys the old way — those
 * keys become the account key — and upload them wrapped, moving the private
 * key to the account-key-derived wrap in the same request. If that upload
 * fails the account stays legacy for this session and migrates next time.
 */
export async function unlockAccount(
  api: AccountKeyApi,
  { email, password, session }: { email: string; password: string; session: LoginResponse },
): Promise<UnlockedAccount> {
  const masterKey = await deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);
  try {
    if (session.wrappedAccountKey && session.wrappedAccountKeyIv) {
      const account = await unwrapAccountKey(
        { wrappedAccountKey: session.wrappedAccountKey, wrappedAccountKeyIv: session.wrappedAccountKeyIv },
        masterKey,
        email,
        session.userId,
      );
      return {
        ...account,
        smkBytes: accountSmkBytes(account),
        protectedPrivateKey: session.protectedPrivateKey ?? null,
        protectedPrivateKeyIv: session.protectedPrivateKeyIv ?? null,
      };
    }

    const legacy = await stretchMasterKeyAllRaw(masterKey, email);
    const account = { encKeyBytes: legacy.encKeyBytes, macKeyBytes: legacy.macKeyBytes };
    const smkBytes = accountSmkBytes(account);
    const wrapped = await wrapAccountKey(account, masterKey, email, session.userId);

    let privateKey: Pick<SetAccountKeyRequest, "protectedPrivateKey" | "protectedPrivateKeyIv"> = {};
    if (session.protectedPrivateKey && session.protectedPrivateKeyIv) {
      const pkcs8 = await decryptBytes(
        { blob: session.protectedPrivateKey, blobIv: session.protectedPrivateKeyIv, blobMac: "" },
        await importAes(legacy.smkBytes),
      );
      const rewrapped = await encryptBytes(pkcs8, await importAes(smkBytes));
      pkcs8.fill(0);
      privateKey = { protectedPrivateKey: rewrapped.blob, protectedPrivateKeyIv: rewrapped.blobIv };
    }

    try {
      await api.setAccountKey({ ...wrapped, ...privateKey }, session.sessionToken);
    } catch (err) {
      // 409: another device migrated first — same account key, so carry on
      // as migrated. Its private-key wrap isn't known here, so org keys wait
      // for the next unlock.
      if ((err as { status?: number }).status !== 409) {
        smkBytes.fill(0);
        return {
          ...account,
          smkBytes: legacy.smkBytes,
          protectedPrivateKey: session.protectedPrivateKey ?? null,
          protectedPrivateKeyIv: session.protectedPrivateKeyIv ?? null,
        };
      }
      legacy.smkBytes.fill(0);
      return { ...account, smkBytes, protectedPrivateKey: null, protectedPrivateKeyIv: null };
    }
    legacy.smkBytes.fill(0);
    return {
      ...account,
      smkBytes,
      protectedPrivateKey: privateKey.protectedPrivateKey ?? session.protectedPrivateKey ?? null,
      protectedPrivateKeyIv: privateKey.protectedPrivateKeyIv ?? session.protectedPrivateKeyIv ?? null,
    };
  } finally {
    masterKey.fill(0);
  }
}
