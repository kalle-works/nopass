import type { EncryptedVaultItem } from "./vault";

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

// OPAQUE (RFC 9807) messages are base64url without padding, as produced and
// consumed by @serenity-kit/opaque.

export interface OpaqueRegisterStartRequest {
  /** SHA-256("nopass-v1-email:" + lowercase(email)), hex — also the OPAQUE credential identifier */
  emailHash: string;
  registrationRequest: string;
}

export interface OpaqueRegisterStartResponse {
  registrationResponse: string;
}

export interface OpaqueRegisterFinishRequest {
  emailHash: string;
  registrationRecord: string;
  /** Argon2id parameters for both the vault KDF and the OPAQUE key-stretching function */
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

/** Replaces the account's login credential in a fresh session (SRP → OPAQUE migration). */
export interface OpaqueReregisterFinishRequest {
  registrationRecord: string;
}

export interface OpaqueLoginStartRequest {
  emailHash: string;
  startLoginRequest: string;
}

/** Identical in status and shape whether or not the account exists. */
export interface OpaqueLoginStartResponse {
  loginId: string;
  loginResponse: string;
  kdfParams: KdfParams;
}

export interface OpaqueLoginFinishRequest {
  loginId: string;
  finishLoginRequest: string;
  /** Optional: link this session to an existing trusted device. */
  deviceId?: string;
}

/** A successful login, by OPAQUE or legacy SRP. */
export interface LoginResponse {
  sessionToken: string;
  userId: string;
  defaultVaultId: string;
  protectedSymmetricKey: string;
  protectedSymmetricKeyIv: string;
  protectedPrivateKey?: string | null;
  protectedPrivateKeyIv?: string | null;
  /** Account key wrapped under the password KEK; absent until the account has migrated */
  wrappedAccountKey?: string | null;
  wrappedAccountKeyIv?: string | null;
}

/** One-time migration to the password-independent account key (fresh session only). */
export interface SetAccountKeyRequest {
  wrappedAccountKey: string;
  wrappedAccountKeyIv: string;
  /** RSA private key moved from the password-derived wrap to the account-key-derived one */
  protectedPrivateKey?: string;
  protectedPrivateKeyIv?: string;
}

// Legacy SRP login — only for accounts that haven't logged in since OPAQUE
// shipped. See docs/auth.md "Removing SRP".

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

export interface SrpVerifyResponse extends LoginResponse {
  /** base64 server proof M2 — client MUST verify this before trusting the session */
  serverProofM2: string;
}

// ─── Password change ─────────────────────────────────────────────────────────

/** Round 1: OPAQUE login with the current password plus registration of the new one. */
export interface PasswordChangeStartRequest {
  emailHash: string;
  startLoginRequest: string;
  registrationRequest: string;
}

export interface PasswordChangeStartResponse {
  changeId: string;
  loginResponse: string;
  kdfParams: KdfParams;
  registrationResponse: string;
  /** current account-key wrap, to open with the current password and re-wrap */
  wrappedAccountKey: string;
  wrappedAccountKeyIv: string;
}

export interface PasswordChangeFinishRequest {
  changeId: string;
  /** proof of the current password */
  finishLoginRequest: string;
  registrationRecord: string;
  /** the same account key, wrapped under the new password's KEK */
  wrappedAccountKey: string;
  wrappedAccountKeyIv: string;
}

// ─── Recovery ────────────────────────────────────────────────────────────────

/** Enable or rotate the account recovery kit (authenticated). */
export interface SetRecoveryRequest {
  /** base64 auth key derived from the recovery code; server stores only its SHA-256 */
  recoveryAuthKey: string;
  /** base64 AES-GCM(smk || enc || mac) under the recovery wrap key */
  recoveryBlob: string;
  recoveryBlobIv: string;
}

export interface RecoveryStatusResponse {
  enabled: boolean;
  updatedAt: string | null;
}

export interface RecoveryInitRequest {
  emailHash: string;
  /** base64 auth key re-derived from the entered recovery code */
  recoveryAuthKey: string;
}

export interface RecoveryInitResponse {
  /** short-lived token authorizing the recovery completion */
  recoveryToken: string;
  /** binds the re-wrapped account key to this account */
  userId: string;
  recoveryBlob: string;
  recoveryBlobIv: string;
  protectedPrivateKey?: string | null;
  protectedPrivateKeyIv?: string | null;
  /** every encrypted item the client must re-encrypt under the new password */
  items: EncryptedVaultItem[];
}

export interface ReencryptedItem {
  id: string;
  blob: string;
  blobIv: string;
  blobMac: string;
}

/** OPAQUE registration round 1 for the new master password, authorized by the recovery token. */
export interface RecoveryOpaqueStartRequest {
  recoveryToken: string;
  emailHash: string;
  registrationRequest: string;
}

export interface RecoveryCompleteRequest {
  recoveryToken: string;
  /** OPAQUE record for the new master password (from recovery/opaque/start) */
  registrationRecord: string;
  protectedSymmetricKey: string;
  protectedSymmetricKeyIv: string;
  /** RSA private key re-wrapped under the new stretched master key (when the user has one) */
  protectedPrivateKey?: string;
  protectedPrivateKeyIv?: string;
  /** the account key from the kit, wrapped under the new password's KEK */
  wrappedAccountKey: string;
  wrappedAccountKeyIv: string;
  /** replacement recovery kit — the used code is burned */
  recoveryAuthKey: string;
  recoveryBlob: string;
  recoveryBlobIv: string;
}

// ─── Activity ────────────────────────────────────────────────────────────────

/** Security audit event — metadata only, never item contents. */
export interface ActivityEventInfo {
  id: string;
  eventType: string;
  ip: string | null;
  deviceId: string | null;
  createdAt: string;
}

// ─── Vaults ──────────────────────────────────────────────────────────────────

export interface VaultInfo {
  id: string;
  /** base64 AES-GCM encrypted vault name (the registration default is a
   *  plaintext placeholder that fails decryption — render a fallback) */
  nameBlob: string;
  nameIv: string;
  createdAt: string;
}

export interface CreateVaultRequest {
  nameBlob: string;
  nameIv: string;
}

export interface MoveItemRequest {
  toVaultId: string;
}

// ─── Shares ──────────────────────────────────────────────────────────────────

/** One-time/expiring share — blob key travels only in the URL fragment. */
export interface CreateShareRequest {
  blob: string;
  blobIv: string;
  /** item name encrypted under the owner's vault key, for the owner's list */
  labelBlob: string;
  labelIv: string;
  /** 1–10 */
  maxViews: number;
  /** 1–168 */
  expiresInHours: number;
}

export interface CreateShareResponse {
  shareId: string;
}

export interface ShareInfo {
  id: string;
  labelBlob: string;
  labelIv: string;
  maxViews: number;
  viewCount: number;
  expiresAt: string;
  createdAt: string;
}

export interface ViewShareResponse {
  blob: string;
  blobIv: string;
  remainingViews: number;
  expiresAt: string;
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
  /** Client-chosen UUID, so the creator can sign their own org-key wrap */
  id?: string;
  name: string;
  /** base64 RSA-OAEP SPKI public key */
  publicKey: string;
  /** AES-256-GCM encrypted RSA private key */
  protectedPrivateKey: string;
  protectedPrivateKeyIv: string;
  /** Org AES-256-GCM key encrypted with the owner's RSA public key */
  encryptedOrgKey: string;
  /** Creator's identity-key signature over their own wrap (signOrgKeyWrap) */
  wrapSignature?: string;
  /** Org key epoch the creator's wrap was signed for */
  keyEpoch?: number;
}

export interface OrgSummary {
  id: string;
  name: string;
  role: OrgRole;
  memberCount: number;
  createdAt: string;
}

/** A user's published keys; verify with verifyKeyBundle before trusting publicKey. */
export interface KeyBundle {
  userId: string;
  /** RSA-OAEP SPKI, base64 */
  publicKey: string;
  /** Ed25519 public key, base64; null until the user's client has migrated */
  identityPublicKey: string | null;
  /** Ed25519 signature over the bundle, base64 */
  publicKeySignature: string | null;
}

export interface OrgMember {
  userId: string;
  role: OrgRole;
  status: OrgMemberStatus;
  joinedAt: string | null;
  publicKey: string | null;
  identityPublicKey: string | null;
  publicKeySignature: string | null;
}

export interface OrgDetails extends OrgSummary {
  members: OrgMember[];
  /** Org AES key encrypted with the caller's RSA public key */
  encryptedOrgKey: string;
  /** Signed chain for the caller's wrap, starting with it; verify with verifyOrgKeyChain */
  wrapChain: WrapLink[];
}

/** One member's org-key wrap and the key bundle of whoever signed it. */
export interface WrapLink {
  recipientUserId: string;
  role: OrgRole;
  encryptedOrgKey: string;
  /** null for wraps made before signing existed */
  wrapSignature: string | null;
  keyEpoch: number | null;
  signerUserId: string;
  signer: KeyBundle;
}

/** A pending invite as the invitee sees it — verify wrapChain before accepting. */
export interface PendingInvite {
  orgId: string;
  orgName: string;
  role: OrgRole;
  wrapChain: WrapLink[];
}

/** Owner-only org key rotation; see POST /organizations/{id}/rotate. */
export interface RotateKeyRequest {
  newEpoch: number;
  removeUserId?: string;
  wraps: RewrapRequest["wraps"];
  items: Array<{ id: string; blob: string; blobIv: string; blobMac: string }>;
}

export interface RewrapRequest {
  wraps: Array<{ userId: string; encryptedOrgKey: string; wrapSignature: string; keyEpoch: number }>;
}

export interface InviteMemberRequest {
  /** SHA-256("nopass-v1-email:" + lowercase(email)) — server never receives plaintext */
  emailHash: string;
  role: Exclude<OrgRole, "owner">;
  /** Org AES key pre-encrypted with the invitee's RSA public key */
  encryptedOrgKey: string;
  /** Inviter's identity-key signature over the wrap (signOrgKeyWrap) */
  wrapSignature: string;
  /** Org key epoch the wrap was signed for */
  keyEpoch: number;
}

export interface AcceptInviteRequest {
  orgId: string;
}

export type PublicKeyResponse = KeyBundle;

/** HMAC under the vault MAC key saying every item is v2; see applyV2OnlyMarker */
export interface VaultFormatMarker {
  marker: string | null;
}

export interface SetIdentityRequest {
  identityPublicKey: string;
  publicKeySignature: string;
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
