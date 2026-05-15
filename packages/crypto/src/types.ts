import type { KdfParams } from "@nopass/types";

export interface DerivedKeys {
  /** Used to decrypt the ProtectedSymmetricKey stored on the server */
  stretchedMasterKey: CryptoKey;
  /** AES-256-GCM key for vault item encryption */
  vaultEncKey: CryptoKey;
  /** HMAC-SHA256 key for vault item MAC */
  vaultMacKey: CryptoKey;
}

export interface EncryptedBlob {
  /** base64(AES-256-GCM ciphertext) */
  blob: string;
  /** base64(12-byte IV) */
  blobIv: string;
  /** base64(HMAC-SHA256(iv || ciphertext)) */
  blobMac: string;
}

export type { KdfParams };
