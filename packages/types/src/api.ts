// ─── Auth ────────────────────────────────────────────────────────────────────

export interface KdfParams {
  type: "argon2id";
  memoryKib: number;
  iterations: number;
  parallelism: number;
}

export const DEFAULT_KDF_PARAMS: KdfParams = {
  type: "argon2id",
  memoryKib: 65536,
  iterations: 3,
  parallelism: 4,
};

export interface RegisterRequest {
  /** SHA-256("nopass-v1-email:" + lowercase(email)) */
  emailHash: string;
  /** base64 Argon2id salt */
  srpSalt: string;
  /** base64 SRP-6a verifier */
  srpVerifier: string;
  kdfParams: KdfParams;
  /** base64 AES-GCM encrypted vault key */
  protectedSymmetricKey: string;
  protectedSymmetricKeyIv: string;
}

export interface RegisterResponse {
  userId: string;
}

export interface SrpInitRequest {
  emailHash: string;
  /** base64 client ephemeral public A */
  clientPublicA: string;
}

export interface SrpInitResponse {
  sessionId: string;
  /** base64 server ephemeral public B */
  serverPublicB: string;
  /** base64 SRP salt */
  srpSalt: string;
  kdfParams: KdfParams;
}

export interface SrpVerifyRequest {
  sessionId: string;
  /** base64 SRP client proof M1 */
  clientProofM1: string;
}

export interface SrpVerifyResponse {
  /** base64 server proof M2 — client MUST verify this before trusting the session */
  serverProofM2: string;
  sessionToken: string;
  userId: string;
  defaultVaultId: string;
  protectedSymmetricKey: string;
  protectedSymmetricKeyIv: string;
}

// ─── Devices ─────────────────────────────────────────────────────────────────

export type DeviceType = "desktop_mac" | "android" | "web" | "extension";

export interface RegisterDeviceRequest {
  deviceName: string;
  deviceType: DeviceType;
  /** base64 X25519 public key */
  devicePublicKey: string;
  /** base64 vault key re-encrypted for biometric unlock (optional) */
  protectedDeviceKey?: string;
  protectedDeviceKeyIv?: string;
}

export interface DeviceInfo {
  id: string;
  deviceName: string;
  deviceType: DeviceType;
  lastSeenAt: string | null;
  createdAt: string;
}

// ─── Generic ─────────────────────────────────────────────────────────────────

export interface ApiError {
  error: string;
}

export interface ConflictResponse {
  conflict: true;
  serverVersion: number;
}
