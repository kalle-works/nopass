/**
 * Key derivation functions.
 *
 * Argon2id: @noble/hashes/argon2.js (no libsodium dependency needed)
 * HKDF-SHA256: @noble/hashes/hkdf.js
 *
 * All parameters must exactly match the Rust implementation (nopass-crypto crate)
 * so that derived keys are identical across platforms.
 */
import { argon2id } from "@noble/hashes/argon2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256 } from "@noble/hashes/sha2.js";

import type { DerivedKeys, KdfParams } from "./types";

const enc = new TextEncoder();

/**
 * Derive the 32-byte master key from the master password using Argon2id.
 *
 * Salt = SHA-256("nopass-v1-kdf:" || lowercase(email)) — deterministic, same on all devices.
 * This exactly matches the Rust derive_master_key() function.
 */
export async function deriveMasterKey(
  masterPassword: string,
  email: string,
  params: KdfParams,
): Promise<Uint8Array> {
  const saltInput = `nopass-v1-kdf:${email.toLowerCase()}`;
  const salt = sha256(enc.encode(saltInput));

  const masterKey = argon2id(enc.encode(masterPassword), salt, {
    t: params.iterations,
    m: params.memoryKib,
    p: params.parallelism,
    dkLen: 32,
  });

  return masterKey;
}

/**
 * Expand the 32-byte master key into three 32-byte subkeys via HKDF-SHA256.
 * Info strings exactly match the Rust stretch_master_key() function.
 */
export async function stretchMasterKey(
  masterKey: Uint8Array,
  email: string,
): Promise<DerivedKeys> {
  const salt = enc.encode(email.toLowerCase());

  const smkBytes = hkdf(sha256, masterKey, salt, enc.encode("nopass-v1-smk"), 32);
  const encKeyBytes = hkdf(sha256, masterKey, salt, enc.encode("nopass-v1-enc"), 32);
  const macKeyBytes = hkdf(sha256, masterKey, salt, enc.encode("nopass-v1-mac"), 32);

  const toAb = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(bytes);

  const importAesKey = (bytes: Uint8Array) =>
    crypto.subtle.importKey("raw", toAb(bytes), { name: "AES-GCM", length: 256 }, false, [
      "encrypt",
      "decrypt",
    ]);

  const importHmacKey = (bytes: Uint8Array) =>
    crypto.subtle.importKey("raw", toAb(bytes), { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
      "verify",
    ]);

  const [stretchedMasterKey, vaultEncKey, vaultMacKey] = await Promise.all([
    importAesKey(smkBytes),
    importAesKey(encKeyBytes),
    importHmacKey(macKeyBytes),
  ]);

  return { stretchedMasterKey, vaultEncKey, vaultMacKey };
}

/**
 * Raw subkeys for contexts that need to pass key material across a trust boundary
 * (e.g. extension popup → service worker). Caller is responsible for zeroing buffers.
 */
export async function stretchMasterKeyRaw(
  masterKey: Uint8Array,
  email: string,
): Promise<{ encKeyBytes: Uint8Array<ArrayBuffer>; macKeyBytes: Uint8Array<ArrayBuffer> }> {
  const salt = enc.encode(email.toLowerCase());
  const toAb = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(bytes);
  return {
    encKeyBytes: toAb(hkdf(sha256, masterKey, salt, enc.encode("nopass-v1-enc"), 32)),
    macKeyBytes: toAb(hkdf(sha256, masterKey, salt, enc.encode("nopass-v1-mac"), 32)),
  };
}

/**
 * All three raw subkeys, for flows that re-wrap key material (recovery kit
 * setup, password change). Caller is responsible for zeroing buffers.
 */
export async function stretchMasterKeyAllRaw(
  masterKey: Uint8Array,
  email: string,
): Promise<{
  smkBytes: Uint8Array<ArrayBuffer>;
  encKeyBytes: Uint8Array<ArrayBuffer>;
  macKeyBytes: Uint8Array<ArrayBuffer>;
}> {
  const salt = enc.encode(email.toLowerCase());
  const toAb = (bytes: Uint8Array): Uint8Array<ArrayBuffer> => new Uint8Array(bytes);
  return {
    smkBytes: toAb(hkdf(sha256, masterKey, salt, enc.encode("nopass-v1-smk"), 32)),
    encKeyBytes: toAb(hkdf(sha256, masterKey, salt, enc.encode("nopass-v1-enc"), 32)),
    macKeyBytes: toAb(hkdf(sha256, masterKey, salt, enc.encode("nopass-v1-mac"), 32)),
  };
}

/** Compute the email hash sent to the server: SHA-256("nopass-v1-email:" + lowercase(email)) */
export function computeEmailHash(email: string): string {
  const bytes = sha256(enc.encode(`nopass-v1-email:${email.toLowerCase()}`));
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
