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
 *   wrapped   = AES-256-GCM(KEK, enc || mac, AAD = "nopass-v2-account-key:" + emailHash)
 *   smk       = HKDF-SHA256(enc || mac, info = "nopass-v2-smk")
 *
 * The smk (which wraps the RSA private key and the protected symmetric key)
 * also comes from the account key now, so nothing tied to the password is
 * left. The recovery kit already wraps enc + mac, so it keeps working across
 * password changes.
 */
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";
import * as opaque from "@serenity-kit/opaque";
import {
  DEFAULT_KDF_PARAMS,
  type LoginResponse,
  type SetAccountKeyRequest,
  type UpgradeFinishRequest,
  type UpgradeFinishResponse,
  type UpgradeStartRequest,
  type UpgradeStartResponse,
} from "@nopass/types";

import { assertKdfFloor, type AccountStateStore } from "./account-state";
import { decryptBytes, encryptBytes } from "./aes-gcm";
import { computeEmailHash, deriveMasterKey, stretchMasterKeyAllRaw } from "./kdf";
import {
  keyStretching,
  provePassword,
  type PasswordLoginResult,
  type PasswordProofApi,
} from "./password-login";
import { srpStep1, srpStep2 } from "./srp-client";
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

/**
 * Binds a wrap to its purpose and account. The account is named by the email
 * hash, which the client computes itself, rather than by a user id the server
 * supplies: a server can't steer which AAD the client checks against.
 */
function aad(email: string): Uint8Array<ArrayBuffer> {
  return toAb(enc.encode(`nopass-v2-account-key:${computeEmailHash(email)}`));
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
): Promise<WrappedAccountKey> {
  const plaintext = new Uint8Array(64);
  plaintext.set(account.encKeyBytes, 0);
  plaintext.set(account.macKeyBytes, 32);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad(email) },
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
): Promise<AccountKey> {
  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: fromBase64(wrapped.wrappedAccountKeyIv), additionalData: aad(email) },
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

export interface AccountKeyApi extends PasswordProofApi {
  setAccountKey(req: SetAccountKeyRequest, token: string): Promise<void>;
  upgradeStart(req: UpgradeStartRequest, token: string): Promise<UpgradeStartResponse>;
  upgradeFinish(req: UpgradeFinishRequest, token: string): Promise<UpgradeFinishResponse>;
}

async function rewrapPrivateKey(
  session: LoginResponse,
  from: Uint8Array<ArrayBuffer>,
  to: Uint8Array<ArrayBuffer>,
): Promise<Pick<SetAccountKeyRequest, "protectedPrivateKey" | "protectedPrivateKeyIv">> {
  if (!session.protectedPrivateKey || !session.protectedPrivateKeyIv) return {};
  const pkcs8 = await decryptBytes(
    { blob: session.protectedPrivateKey, blobIv: session.protectedPrivateKeyIv, blobMac: "" },
    await importAes(from),
  );
  const rewrapped = await encryptBytes(pkcs8, await importAes(to));
  pkcs8.fill(0);
  return { protectedPrivateKey: rewrapped.blob, protectedPrivateKeyIv: rewrapped.blobIv };
}

/**
 * Opens the account after a successful login.
 *
 * - Migrated accounts unwrap the stored account key. If this device knows the
 *   account is migrated and the server leaves the wrap out, that's refused:
 *   legacy keys are never derived again after migration.
 * - An account that logged in over SRP upgrades now, in one request with a
 *   fresh SRP proof: OPAQUE registration, the wrapped account key (its legacy
 *   keys) and the private key moved to the account-key wrap.
 * - An OPAQUE account still on legacy keys wraps them under a fresh password
 *   proof.
 *
 * Any failure throws; the session is not used with half-migrated keys.
 */
export async function unlockAccount(
  api: AccountKeyApi,
  {
    email,
    password,
    session,
    accountState,
  }: { email: string; password: string; session: PasswordLoginResult; accountState: AccountStateStore },
): Promise<UnlockedAccount> {
  const emailHash = computeEmailHash(email);
  const masterKey = await deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);
  try {
    if (session.wrappedAccountKey && session.wrappedAccountKeyIv) {
      const account = await unwrapAccountKey(
        { wrappedAccountKey: session.wrappedAccountKey, wrappedAccountKeyIv: session.wrappedAccountKeyIv },
        masterKey,
        email,
      );
      await accountState.update(emailHash, { accountKey: true });
      return {
        ...account,
        smkBytes: accountSmkBytes(account),
        protectedPrivateKey: session.protectedPrivateKey ?? null,
        protectedPrivateKeyIv: session.protectedPrivateKeyIv ?? null,
      };
    }
    if ((await accountState.get(emailHash)).accountKey) {
      throw new AccountKeyError("The server didn't return this account's key. Not unlocking.");
    }

    const legacy = await stretchMasterKeyAllRaw(masterKey, email);
    const account = { encKeyBytes: legacy.encKeyBytes, macKeyBytes: legacy.macKeyBytes };
    const smkBytes = accountSmkBytes(account);
    try {
      const wrapped = await wrapAccountKey(account, masterKey, email);
      const privateKey = await rewrapPrivateKey(session, legacy.smkBytes, smkBytes);

      if (session.method === "srp") {
        await upgradeFromSrp(api, { email, password, sessionToken: session.sessionToken, wrapped, privateKey });
        await accountState.update(emailHash, { opaque: true, accountKey: true });
      } else {
        const proof = await provePassword(api, { email, password, sessionToken: session.sessionToken });
        await api.setAccountKey({ proof, ...wrapped, ...privateKey }, session.sessionToken);
        await accountState.update(emailHash, { accountKey: true });
      }
      return {
        ...account,
        smkBytes,
        protectedPrivateKey: privateKey.protectedPrivateKey ?? null,
        protectedPrivateKeyIv: privateKey.protectedPrivateKeyIv ?? null,
      };
    } catch (err) {
      smkBytes.fill(0);
      zeroAccount(account);
      throw err;
    } finally {
      legacy.smkBytes.fill(0);
    }
  } finally {
    masterKey.fill(0);
  }
}

/** SRP → OPAQUE upgrade: fresh SRP proof + OPAQUE registration + account key, one request. */
async function upgradeFromSrp(
  api: AccountKeyApi,
  {
    email,
    password,
    sessionToken,
    wrapped,
    privateKey,
  }: {
    email: string;
    password: string;
    sessionToken: string;
    wrapped: WrappedAccountKey;
    privateKey: Pick<SetAccountKeyRequest, "protectedPrivateKey" | "protectedPrivateKeyIv">;
  },
): Promise<void> {
  await opaque.ready;
  const step1 = srpStep1();
  const registration = opaque.client.startRegistration({ password });
  const started = await api.upgradeStart(
    {
      emailHash: computeEmailHash(email),
      clientPublicA: step1.clientPublicA,
      registrationRequest: registration.registrationRequest,
    },
    sessionToken,
  );
  const step2 = srpStep2(email, password, started.srpSalt, started.serverPublicB, step1.privateSession);
  const { registrationRecord } = opaque.client.finishRegistration({
    clientRegistrationState: registration.clientRegistrationState,
    registrationResponse: started.registrationResponse,
    password,
    keyStretching: keyStretching(assertKdfFloor(started.kdfParams)),
  });
  const finished = await api.upgradeFinish(
    {
      upgradeId: started.upgradeId,
      clientProofM1: step2.clientProofM1,
      registrationRecord,
      ...wrapped,
      ...privateKey,
    },
    sessionToken,
  );
  step2.verifyServerProof(finished.serverProofM2);
}
