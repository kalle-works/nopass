/**
 * AES-256-GCM encryption/decryption using the Web Crypto API.
 * HMAC-SHA256 provides an additional MAC over (iv || ciphertext).
 */
import type { EncryptedBlob, VaultItemPlaintext } from "./types";

function toBase64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromBase64(b64: string): Uint8Array {
  const s = atob(b64);
  const buf = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) buf[i] = s.charCodeAt(i);
  return buf;
}

/**
 * Encrypt a vault item. Returns base64-encoded ciphertext, IV, and MAC.
 * The plaintext is serialized to JSON before encryption.
 */
export async function encryptItem(
  plaintext: VaultItemPlaintext,
  vaultEncKey: CryptoKey,
  vaultMacKey: CryptoKey,
): Promise<EncryptedBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintextBytes = new TextEncoder().encode(JSON.stringify(plaintext));

  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    vaultEncKey,
    plaintextBytes,
  );

  // MAC over (iv || ciphertext) to detect tampering outside the AES-GCM tag
  const macData = new Uint8Array(iv.length + ciphertext.byteLength);
  macData.set(iv, 0);
  macData.set(new Uint8Array(ciphertext), iv.length);

  const mac = await crypto.subtle.sign("HMAC", vaultMacKey, macData);

  return {
    blob: toBase64(ciphertext),
    blobIv: toBase64(iv),
    blobMac: toBase64(mac),
  };
}

/**
 * Decrypt a vault item. Verifies MAC before decryption.
 * Throws if MAC verification fails or ciphertext is corrupt.
 */
export async function decryptItem(
  encrypted: EncryptedBlob,
  vaultEncKey: CryptoKey,
  vaultMacKey: CryptoKey,
): Promise<VaultItemPlaintext> {
  const iv = fromBase64(encrypted.blobIv);
  const ciphertext = fromBase64(encrypted.blob);
  const mac = fromBase64(encrypted.blobMac);

  // Verify MAC before decryption (fail-fast on tampered data)
  const macData = new Uint8Array(iv.length + ciphertext.length);
  macData.set(iv, 0);
  macData.set(ciphertext, iv.length);

  const valid = await crypto.subtle.verify("HMAC", vaultMacKey, mac, macData);
  if (!valid) {
    throw new Error("MAC verification failed — vault item may have been tampered with");
  }

  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, vaultEncKey, ciphertext);

  return JSON.parse(new TextDecoder().decode(plaintext)) as VaultItemPlaintext;
}

/**
 * Encrypt raw bytes (used for ProtectedSymmetricKey).
 */
export async function encryptBytes(plaintext: Uint8Array, key: CryptoKey): Promise<EncryptedBlob> {
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);

  return {
    blob: toBase64(ciphertext),
    blobIv: toBase64(iv),
    blobMac: "", // not needed for key material — AES-GCM AEAD provides integrity
  };
}

export async function decryptBytes(encrypted: EncryptedBlob, key: CryptoKey): Promise<Uint8Array> {
  const iv = fromBase64(encrypted.blobIv);
  const ciphertext = fromBase64(encrypted.blob);

  const plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
  return new Uint8Array(plaintext);
}
