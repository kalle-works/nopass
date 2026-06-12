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
  /** base64 RSA-OAEP SPKI public key */
  publicKey?: string;
  /** AES-256-GCM encrypted RSA private key */
  protectedPrivateKey?: string;
  protectedPrivateKeyIv?: string;
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
  /** Optional: link this session to an existing trusted device. */
  deviceId?: string;
}

export interface SrpVerifyResponse {
  /** base64 server proof M2 — client MUST verify this before trusting the session */
  serverProofM2: string;
  sessionToken: string;
  userId: string;
  defaultVaultId: string;
  protectedSymmetricKey: string;
  protectedSymmetricKeyIv: string;
  protectedPrivateKey?: string | null;
  protectedPrivateKeyIv?: string | null;
}

// ─── Devices ─────────────────────────────────────────────────────────────────

export type DeviceType =
  | "desktop_mac"
  | "desktop_linux"
  | "desktop_windows"
  | "android"
  | "web"
  | "extension";

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

// ─── Organizations ───────────────────────────────────────────────────────────

export type OrgRole = "owner" | "admin" | "member";
export type OrgMemberStatus = "pending" | "active";

export interface CreateOrgRequest {
  name: string;
  /** base64 RSA-OAEP SPKI public key */
  publicKey: string;
  /** AES-256-GCM encrypted RSA private key */
  protectedPrivateKey: string;
  protectedPrivateKeyIv: string;
  /** Org AES-256-GCM key encrypted with the owner's RSA public key */
  encryptedOrgKey: string;
}

export interface OrgSummary {
  id: string;
  name: string;
  role: OrgRole;
  memberCount: number;
  createdAt: string;
}

export interface OrgMember {
  userId: string;
  role: OrgRole;
  status: OrgMemberStatus;
  joinedAt: string | null;
}

export interface OrgDetails extends OrgSummary {
  members: OrgMember[];
  /** Org AES key encrypted with the caller's RSA public key */
  encryptedOrgKey: string;
}

export interface InviteMemberRequest {
  /** SHA-256("nopass-v1-email:" + lowercase(email)) — server never receives plaintext */
  emailHash: string;
  role: Exclude<OrgRole, "owner">;
  /** Org AES key pre-encrypted with the invitee's RSA public key */
  encryptedOrgKey: string;
}

export interface AcceptInviteRequest {
  orgId: string;
}

export interface PublicKeyResponse {
  userId: string;
  publicKey: string;
}

// ─── Billing ─────────────────────────────────────────────────────────────────

export type SubscriptionPlan = "free" | "pro" | "teams" | "enterprise";
export type SubscriptionStatus = "active" | "past_due" | "canceled" | "trialing";

export interface BillingStatus {
  plan: SubscriptionPlan;
  status: SubscriptionStatus;
  currentPeriodEnd: string | null;
  stripeCustomerId: string | null;
}

export interface CreateCheckoutRequest {
  priceId: string;
  successUrl: string;
  cancelUrl: string;
}

export interface CheckoutSessionResponse {
  url: string;
}

export interface CreatePortalRequest {
  returnUrl: string;
}

export interface PortalSessionResponse {
  url: string;
}

// ─── Generic ─────────────────────────────────────────────────────────────────

export interface ApiError {
  error: string;
}

export interface ConflictResponse {
  conflict: true;
  serverVersion: number;
}
