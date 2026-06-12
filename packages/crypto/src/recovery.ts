/**
 * Recovery kit crypto.
 *
 * A recovery code is a 160-bit random secret rendered as Crockford base32.
 * From it we derive (via Argon2id + HKDF, mirroring the password KDF design):
 *   - an auth key: sent to the server at setup; the server stores its SHA-256
 *     hash and uses it to gate access to the recovery blob. It cannot decrypt
 *     anything.
 *   - a wrap key: never leaves the device; encrypts the three vault subkeys
 *     (smk || enc || mac, 96 bytes) into the recovery blob stored server-side.
 *
 * Recovering = present auth key → receive blob → unwrap subkeys → decrypt the
 * vault → choose a new password → re-encrypt everything client-side.
 */
import { argon2id } from "@noble/hashes/argon2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { encryptBytes, decryptBytes } from "./aes-gcm";
import type { EncryptedBlob, KdfParams } from "./types";

const enc = new TextEncoder();

/**
 * KDF params for recovery-key derivation. These are pinned for protocol
 * version v1 and must NEVER change without bumping the "nopass-v1-recovery"
 * salt/info strings: the client has to derive the auth key before it can talk
 * to the server, so there is no place to look params up from. A 160-bit random
 * code doesn't rely on KDF hardness the way a human password does, so frozen
 * params are safe.
 */
export const RECOVERY_KDF_PARAMS: KdfParams = {
  type: "argon2id",
  memoryKib: 65536,
  iterations: 3,
  parallelism: 4,
};

// Crockford base32 — no I, L, O, U to avoid transcription mistakes
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Generate a 160-bit recovery code formatted as 8 dash-separated groups of 4. */
export function generateRecoveryCode(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);

  let bits = 0;
  let acc = 0;
  let out = "";
  for (const byte of bytes) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(acc >>> bits) & 31];
    }
  }
  return out.match(/.{4}/g)!.join("-");
}

/**
 * Normalize user input: uppercase, map easily-confused letters to their
 * Crockford canonical character, strip separators. U never appears in
 * generated codes, so a typed U can only be a misread V.
 */
export function normalizeRecoveryCode(code: string): string {
  return code
    .toUpperCase()
    .replace(/[\s-]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1")
    .replace(/U/g, "V");
}

export interface RecoveryKeys {
  /** base64; sent to the server, which stores only its SHA-256 hash */
  authKeyB64: string;
  /** AES-256-GCM key that encrypts the vault subkeys; never leaves the device */
  wrapKey: CryptoKey;
}

/** Derive the auth and wrap keys from a recovery code. */
export async function deriveRecoveryKeys(
  code: string,
  email: string,
  params: KdfParams = RECOVERY_KDF_PARAMS,
): Promise<RecoveryKeys> {
  const normalized = normalizeRecoveryCode(code);
  const saltInput = `nopass-v1-recovery:${email.toLowerCase()}`;
  const salt = sha256(enc.encode(saltInput));

  const recoveryKey = argon2id(enc.encode(normalized), salt, {
    t: params.iterations,
    m: params.memoryKib,
    p: params.parallelism,
    dkLen: 32,
  });

  const hkdfSalt = enc.encode(email.toLowerCase());
  const authBytes = hkdf(sha256, recoveryKey, hkdfSalt, enc.encode("nopass-v1-recovery-auth"), 32);
  const wrapBytes = hkdf(sha256, recoveryKey, hkdfSalt, enc.encode("nopass-v1-recovery-wrap"), 32);
  recoveryKey.fill(0);

  const wrapKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(wrapBytes),
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
  wrapBytes.fill(0);

  let authKeyB64 = "";
  for (const b of authBytes) authKeyB64 += String.fromCharCode(b);
  authBytes.fill(0);

  return { authKeyB64: btoa(authKeyB64), wrapKey };
}

export interface VaultSubkeys {
  smkBytes: Uint8Array<ArrayBuffer>;
  encKeyBytes: Uint8Array<ArrayBuffer>;
  macKeyBytes: Uint8Array<ArrayBuffer>;
}

/** Encrypt smk || enc || mac (96 bytes) under the recovery wrap key. */
export async function wrapVaultSubkeys(
  subkeys: VaultSubkeys,
  wrapKey: CryptoKey,
): Promise<EncryptedBlob> {
  const concat = new Uint8Array(96);
  concat.set(subkeys.smkBytes, 0);
  concat.set(subkeys.encKeyBytes, 32);
  concat.set(subkeys.macKeyBytes, 64);
  const blob = await encryptBytes(concat, wrapKey);
  concat.fill(0);
  return blob;
}

/** Decrypt the recovery blob back into the three vault subkeys. */
export async function unwrapVaultSubkeys(
  blob: EncryptedBlob,
  wrapKey: CryptoKey,
): Promise<VaultSubkeys> {
  const concat = await decryptBytes(blob, wrapKey);
  if (concat.length !== 96) {
    throw new Error("recovery blob has unexpected length");
  }
  const subkeys: VaultSubkeys = {
    smkBytes: concat.slice(0, 32),
    encKeyBytes: concat.slice(32, 64),
    macKeyBytes: concat.slice(64, 96),
  };
  concat.fill(0);
  return subkeys;
}
