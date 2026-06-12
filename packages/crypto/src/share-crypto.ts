/**
 * Item-share crypto. A share encrypts one item snapshot under a random
 * 256-bit key that travels only in the share URL fragment (`#k=…`) — the
 * fragment is never sent to any server, so the share stays zero-knowledge.
 */
import type { VaultItemPlaintext } from "@nopass/types";
import { encryptBytes, decryptBytes } from "./aes-gcm";
import type { EncryptedBlob } from "./types";

function toBase64Url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(b64url: string): Uint8Array<ArrayBuffer> {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const s = atob(padded);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export interface ShareKey {
  key: CryptoKey;
  /** URL-fragment-safe encoding of the raw key */
  keyB64url: string;
}

export async function generateShareKey(): Promise<ShareKey> {
  const raw = new Uint8Array(32);
  crypto.getRandomValues(raw);
  const key = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, [
    "encrypt",
    "decrypt",
  ]);
  const keyB64url = toBase64Url(raw);
  raw.fill(0);
  return { key, keyB64url };
}

export async function importShareKey(keyB64url: string): Promise<CryptoKey> {
  const raw = fromBase64Url(keyB64url);
  if (raw.length !== 32) throw new Error("share key has unexpected length");
  const key = await crypto.subtle.importKey("raw", raw, { name: "AES-GCM", length: 256 }, false, [
    "decrypt",
  ]);
  raw.fill(0);
  return key;
}

export async function encryptSharePayload(
  item: VaultItemPlaintext,
  key: CryptoKey,
): Promise<EncryptedBlob> {
  const bytes = new TextEncoder().encode(JSON.stringify(item));
  return encryptBytes(new Uint8Array(bytes), key);
}

export async function decryptSharePayload(
  blob: EncryptedBlob,
  key: CryptoKey,
): Promise<VaultItemPlaintext> {
  const bytes = await decryptBytes(blob, key);
  return JSON.parse(new TextDecoder().decode(bytes)) as VaultItemPlaintext;
}
