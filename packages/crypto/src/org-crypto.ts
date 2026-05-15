/**
 * Organisation key management.
 *
 * Each org has a random 256-bit AES-GCM key (the "org key").  To share it
 * zero-knowledge the org key is RSA-OAEP-encrypted separately for every
 * member using their stored public key. The server never sees the plaintext.
 *
 * Key types used:
 *   - RSA-OAEP 4096-bit with SHA-256 for asymmetric wrapping
 *   - AES-256-GCM for the org key itself and for protecting the private key
 */

const RSA_PARAMS: RsaHashedKeyGenParams = {
  name: "RSA-OAEP",
  modulusLength: 4096,
  publicExponent: new Uint8Array([1, 0, 1]),
  hash: "SHA-256",
};

// ── Key-pair generation ───────────────────────────────────────────────────────

export interface UserKeyPair {
  /** SPKI DER, base64 — stored on server, shared publicly */
  publicKeyB64: string;
  /** AES-256-GCM encrypted PKCS8 private key */
  protectedPrivateKey: string;
  protectedPrivateKeyIv: string;
}

/**
 * Generate an RSA-OAEP key pair for a user.
 * The private key is immediately encrypted with the user's stretchedMasterKey.
 */
export async function generateUserKeyPair(
  stretchedMasterKey: CryptoKey,
): Promise<UserKeyPair> {
  const keyPair = await crypto.subtle.generateKey(RSA_PARAMS, true, [
    "encrypt",
    "decrypt",
  ]);

  const publicSpki = await crypto.subtle.exportKey("spki", keyPair.publicKey);
  const privatePkcs8 = await crypto.subtle.exportKey(
    "pkcs8",
    keyPair.privateKey,
  );

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encPrivate = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    stretchedMasterKey,
    privatePkcs8,
  );

  return {
    publicKeyB64: btoa(String.fromCharCode(...new Uint8Array(publicSpki))),
    protectedPrivateKey: btoa(
      String.fromCharCode(...new Uint8Array(encPrivate)),
    ),
    protectedPrivateKeyIv: btoa(String.fromCharCode(...iv)),
  };
}

// ── Org-key generation ────────────────────────────────────────────────────────

/** Generate a random 256-bit org AES-GCM key. */
export async function generateOrgKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );
}

/** Export an org key as base64. */
export async function exportOrgKey(orgKey: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", orgKey);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

/** Import an org key from base64. */
export async function importOrgKey(b64: string): Promise<CryptoKey> {
  const raw = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

// ── Wrapping / unwrapping with RSA-OAEP ──────────────────────────────────────

/**
 * Encrypt an org key with a member's RSA public key.
 * Returns base64 ciphertext stored in organization_members.encrypted_org_key.
 */
export async function encryptOrgKeyForMember(
  orgKey: CryptoKey,
  recipientPublicKeyB64: string,
): Promise<string> {
  const spki = Uint8Array.from(atob(recipientPublicKeyB64), (c) =>
    c.charCodeAt(0),
  );
  const pubKey = await crypto.subtle.importKey(
    "spki",
    spki,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );

  const rawOrgKey = await crypto.subtle.exportKey("raw", orgKey);
  const encrypted = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    pubKey,
    rawOrgKey,
  );

  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

/**
 * Decrypt an org key using the member's RSA private key.
 * Private key must be decrypted first using decryptUserPrivateKey().
 */
export async function decryptOrgKey(
  encryptedOrgKeyB64: string,
  privateKey: CryptoKey,
): Promise<CryptoKey> {
  const ciphertext = Uint8Array.from(atob(encryptedOrgKeyB64), (c) =>
    c.charCodeAt(0),
  );
  const rawOrgKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    ciphertext,
  );
  return crypto.subtle.importKey(
    "raw",
    rawOrgKey,
    { name: "AES-GCM" },
    false,
    ["encrypt", "decrypt"],
  );
}

// ── Private key decryption ────────────────────────────────────────────────────

/**
 * Decrypt the user's protected RSA private key using their stretchedMasterKey.
 */
export async function decryptUserPrivateKey(
  protectedPrivateKeyB64: string,
  protectedPrivateKeyIvB64: string,
  stretchedMasterKey: CryptoKey,
): Promise<CryptoKey> {
  const ciphertext = Uint8Array.from(atob(protectedPrivateKeyB64), (c) =>
    c.charCodeAt(0),
  );
  const iv = Uint8Array.from(atob(protectedPrivateKeyIvB64), (c) =>
    c.charCodeAt(0),
  );

  const pkcs8 = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    stretchedMasterKey,
    ciphertext,
  );

  return crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["decrypt"],
  );
}
