export type VaultItemType = "login" | "note" | "card" | "identity" | "ssh_key";

// ─── Plaintext types — exist ONLY in memory on-device, NEVER written to disk or network ──────────

export interface CustomField {
  name: string;
  value: string;
  fieldType: "text" | "hidden" | "boolean";
}

/** A WebAuthn passkey credential bound to a login item. Lives inside the
 *  encrypted blob like every other secret. */
export interface PasskeyCredential {
  /** base64url credential ID returned to relying parties */
  credentialIdB64u: string;
  /** the rp.id this credential was created for (registrable domain) */
  rpId: string;
  /** base64url user.id handle supplied by the RP at registration */
  userHandleB64u: string;
  /** RP-side account display (user.name) — shown when picking a passkey */
  userName: string;
  /** base64 PKCS#8 ES256 (P-256) private key */
  privateKeyPkcs8B64: string;
  /** signature counter; incremented on every assertion */
  signCount: number;
  createdAt: string;
}

export interface LoginItem {
  type: "login";
  name: string;
  tags?: string[];
  username: string;
  password: string;
  urls: string[];
  totp?: string;
  notes?: string;
  customFields: CustomField[];
  passkey?: PasskeyCredential;
}

export interface NoteItem {
  type: "note";
  name: string;
  tags?: string[];
  content: string;
}

export interface CardItem {
  type: "card";
  name: string;
  tags?: string[];
  cardholderName: string;
  number: string;
  expMonth: string;
  expYear: string;
  cvv: string;
  notes?: string;
}

export interface IdentityItem {
  type: "identity";
  name: string;
  tags?: string[];
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  address: string;
  city: string;
  country: string;
  notes?: string;
}

export interface SshKeyItem {
  type: "ssh_key";
  name: string;
  tags?: string[];
  privateKey: string;
  publicKey?: string;
  passphrase?: string;
  comment?: string;
  notes?: string;
  /** Whether to expose this key through the nopass SSH agent socket. Default false for existing keys. */
  useInAgent?: boolean;
}

export type VaultItemPlaintext = LoginItem | NoteItem | CardItem | IdentityItem | SshKeyItem;

// ─── Encrypted form — what the server stores and what travels over the network ──────────────────

export interface EncryptedVaultItem {
  id: string;
  vaultId: string;
  userId: string;
  /** null = personal item; UUID = org-shared item */
  orgId?: string | null;
  itemType: VaultItemType;
  /** base64(AES-256-GCM ciphertext of JSON-serialized VaultItemPlaintext) */
  blob: string;
  /** base64(12-byte IV) */
  blobIv: string;
  /** base64(HMAC-SHA256(iv || ciphertext)) */
  blobMac: string;
  version: number;
  deletedAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface CreateVaultItemRequest {
  itemType: VaultItemType;
  blob: string;
  blobIv: string;
  blobMac: string;
}

export interface UpdateVaultItemRequest {
  blob: string;
  blobIv: string;
  blobMac: string;
  version: number;
}
