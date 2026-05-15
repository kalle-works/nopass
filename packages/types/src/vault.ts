export type VaultItemType = "login" | "note" | "card" | "identity";

// ─── Plaintext types — exist ONLY in memory on-device, NEVER written to disk or network ──────────

export interface CustomField {
  name: string;
  value: string;
  fieldType: "text" | "hidden" | "boolean";
}

export interface LoginItem {
  type: "login";
  name: string;
  username: string;
  password: string;
  urls: string[];
  totp?: string;
  notes?: string;
  customFields: CustomField[];
}

export interface NoteItem {
  type: "note";
  name: string;
  content: string;
}

export interface CardItem {
  type: "card";
  name: string;
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
  firstName: string;
  lastName: string;
  email: string;
  phone: string;
  address: string;
  city: string;
  country: string;
  notes?: string;
}

export type VaultItemPlaintext = LoginItem | NoteItem | CardItem | IdentityItem;

// ─── Encrypted form — what the server stores and what travels over the network ──────────────────

export interface EncryptedVaultItem {
  id: string;
  vaultId: string;
  userId: string;
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
