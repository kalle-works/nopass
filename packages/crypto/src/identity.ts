/**
 * Key transparency-lite for org key wrapping.
 *
 * Every user has an Ed25519 identity key that signs their key bundle
 * (user id + RSA-OAEP public key). Before wrapping an org key to someone, the
 * client checks the bundle signature and compares the identity key with the
 * one it pinned the first time it saw that user (TOFU). A server that swaps
 * the RSA key must also swap the identity key, which a pin turns into a hard
 * failure and a safety-number comparison makes visible on first contact.
 *
 * The identity seed is derived from the user's RSA private key with HKDF
 * instead of being stored separately: it needs no new protected blob, it
 * survives password changes and account recovery exactly like the RSA key
 * already does, and a server that can read it could already read the RSA key.
 */
import { ed25519 } from "@noble/curves/ed25519.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import type { KeyBundle } from "@nopass/types";
import { decryptBytes } from "./aes-gcm";

const enc = new TextEncoder();
const BUNDLE_LABEL = enc.encode("nopwd-key-bundle-v1");
const SAFETY_LABEL = enc.encode("nopwd-safety-number-v1");

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromBase64(b64: string): Uint8Array<ArrayBuffer> {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function uuidBytes(uuid: string): Uint8Array {
  const hex = uuid.replace(/-/g, "");
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) throw new Error(`not a UUID: ${uuid}`);
  return Uint8Array.from({ length: 16 }, (_, i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

export interface IdentityKey {
  /** 32-byte Ed25519 seed; zero it when done */
  secretKey: Uint8Array;
  publicKeyB64: string;
  /** SPKI of the RSA public key matching the private key it was derived from */
  rsaPublicKeyB64: string;
}

/**
 * Derive the identity key from the user's protected RSA private key. Also
 * returns the RSA public key computed from the private key, so the caller
 * signs the key it actually holds rather than whatever the server serves.
 */
export async function deriveIdentityKey(
  protectedPrivateKeyB64: string,
  protectedPrivateKeyIvB64: string,
  stretchedMasterKey: CryptoKey,
): Promise<IdentityKey> {
  const pkcs8 = await decryptBytes(
    { blob: protectedPrivateKeyB64, blobIv: protectedPrivateKeyIvB64, blobMac: "" },
    stretchedMasterKey,
  );
  try {
    const secretKey = hkdf(sha256, pkcs8, undefined, enc.encode("nopwd-identity-ed25519-v1"), 32);
    const privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "RSA-OAEP", hash: "SHA-256" }, true, [
      "decrypt",
    ]);
    const { n, e } = await crypto.subtle.exportKey("jwk", privateKey);
    if (!n || !e) throw new Error("RSA private key is missing its modulus or exponent");
    const publicJwk: JsonWebKey = { kty: "RSA", n, e, alg: "RSA-OAEP-256", ext: true };
    const publicKey = await crypto.subtle.importKey(
      "jwk",
      publicJwk,
      { name: "RSA-OAEP", hash: "SHA-256" },
      true,
      ["encrypt"],
    );
    const spki = new Uint8Array(await crypto.subtle.exportKey("spki", publicKey));
    return {
      secretKey,
      publicKeyB64: toBase64(ed25519.getPublicKey(secretKey)),
      rsaPublicKeyB64: toBase64(spki),
    };
  } finally {
    pkcs8.fill(0);
  }
}

/** Canonical signed message: label || 0 || userId (16 bytes) || RSA SPKI. */
function bundleMessage(userId: string, rsaPublicKeyB64: string): Uint8Array {
  return concat(BUNDLE_LABEL, Uint8Array.of(0), uuidBytes(userId), fromBase64(rsaPublicKeyB64));
}

export function signKeyBundle(userId: string, rsaPublicKeyB64: string, identitySecretKey: Uint8Array): string {
  return toBase64(ed25519.sign(bundleMessage(userId, rsaPublicKeyB64), identitySecretKey));
}

/** Strict RFC 8032 verification of a bundle's self-signature. */
export function verifyKeyBundle(bundle: KeyBundle): boolean {
  if (!bundle.identityPublicKey || !bundle.publicKeySignature) return false;
  try {
    return ed25519.verify(
      fromBase64(bundle.publicKeySignature),
      bundleMessage(bundle.userId, bundle.publicKey),
      fromBase64(bundle.identityPublicKey),
      { zip215: false },
    );
  } catch {
    return false;
  }
}

/**
 * 30-digit safety number for a user's identity key, shown as six groups of
 * five digits. Two people comparing it out of band confirm they see the same
 * key. The user id is mixed in so a key reused across accounts reads
 * differently.
 */
export function safetyNumber(userId: string, identityPublicKeyB64: string): string {
  let digest = concat(SAFETY_LABEL, uuidBytes(userId), fromBase64(identityPublicKeyB64));
  // Iterated like Signal's fingerprints to slow down searching for a key
  // whose number collides with a target's.
  for (let i = 0; i < 5200; i++) digest = sha512(digest);
  const groups: string[] = [];
  for (let g = 0; g < 6; g++) {
    let n = 0;
    for (let i = 0; i < 5; i++) n = n * 256 + digest[g * 5 + i]!;
    groups.push(String(n % 100000).padStart(5, "0"));
  }
  return groups.join(" ");
}

/** Identity keys pinned per user id. */
export interface KeyPinStore {
  get(userId: string): string | undefined;
  set(userId: string, identityPublicKeyB64: string): void;
}

export class PinnedKeyChangedError extends Error {
  constructor(readonly userId: string) {
    super(
      `The identity key for user ${userId} changed since you last saw it. Do not share anything with them until you have compared safety numbers in person or over a trusted channel.`,
    );
    this.name = "PinnedKeyChangedError";
  }
}

export class UnverifiableKeyError extends Error {
  constructor(readonly userId: string, reason: string) {
    super(reason);
    this.name = "UnverifiableKeyError";
  }
}

export interface VerifiedKey {
  rsaPublicKeyB64: string;
  safetyNumber: string;
  /** true when this call pinned the key (first contact — compare safety numbers) */
  firstSeen: boolean;
}

/**
 * Accept a member's RSA key only if their bundle is self-signed and their
 * identity key matches the pin (pinning it on first contact).
 */
export function verifyMemberKey(bundle: KeyBundle, pins: KeyPinStore): VerifiedKey {
  if (!bundle.identityPublicKey || !bundle.publicKeySignature) {
    throw new UnverifiableKeyError(
      bundle.userId,
      "This user has not published an identity key yet. Ask them to sign in once, then try again.",
    );
  }
  if (!verifyKeyBundle(bundle)) {
    throw new UnverifiableKeyError(bundle.userId, "This user's key bundle has an invalid signature.");
  }
  const pinned = pins.get(bundle.userId);
  if (pinned !== undefined && pinned !== bundle.identityPublicKey) {
    throw new PinnedKeyChangedError(bundle.userId);
  }
  if (pinned === undefined) pins.set(bundle.userId, bundle.identityPublicKey);
  return {
    rsaPublicKeyB64: bundle.publicKey,
    safetyNumber: safetyNumber(bundle.userId, bundle.identityPublicKey),
    firstSeen: pinned === undefined,
  };
}
