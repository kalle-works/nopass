use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Auth ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParams {
    #[serde(rename = "type")]
    pub kdf_type: String, // "argon2id"
    pub memory_kib: u32,   // 65536
    pub iterations: u32,   // 3
    pub parallelism: u32,  // 4
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            kdf_type: "argon2id".into(),
            memory_kib: 65536,
            iterations: 3,
            parallelism: 4,
        }
    }
}

// OPAQUE (RFC 9807) messages are base64url without padding, exactly as
// @serenity-kit/opaque produces and consumes them.

/// Registration round 1. Used for new accounts (public route) and for
/// re-registration in an authenticated session (SRP migration).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueRegisterStartRequest {
    /// SHA-256("nopass-v1-email:" + lowercase(email)), hex — also the OPAQUE credential identifier
    pub email_hash: String,
    pub registration_request: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueRegisterStartResponse {
    pub registration_response: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueRegisterFinishRequest {
    pub email_hash: String,
    pub registration_record: String,
    /// Argon2id parameters for both the vault KDF and the OPAQUE KSF
    pub kdf_params: KdfParams,
    /// AES-256-GCM encrypted vault key (encrypted with stretchedMasterKey)
    pub protected_symmetric_key: String,
    pub protected_symmetric_key_iv: String,
    /// RSA-OAEP-4096 SPKI public key, base64 (for org-key sharing)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// AES-256-GCM encrypted PKCS8 private key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_private_key_iv: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    pub user_id: Uuid,
}

/// Authenticated re-registration finish: replaces the account's credential
/// (and deletes any SRP verifier).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueReregisterFinishRequest {
    pub registration_record: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueLoginStartRequest {
    pub email_hash: String,
    pub start_login_request: String,
}

/// Identical in status and shape whether or not the account exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueLoginStartResponse {
    pub login_id: Uuid,
    pub login_response: String,
    pub kdf_params: KdfParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpaqueLoginFinishRequest {
    pub login_id: Uuid,
    pub finish_login_request: String,
    /// Optional device UUID — if provided, links the new session to this trusted device
    /// and updates device.last_seen_at. Silently ignored if the device doesn't belong to the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Uuid>,
}

/// A successful login, by OPAQUE or legacy SRP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub session_token: String,
    pub user_id: Uuid,
    pub default_vault_id: Uuid,
    pub protected_symmetric_key: String,
    pub protected_symmetric_key_iv: String,
    /// RSA-OAEP key pair — only present if the user has one registered
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_private_key_iv: Option<String>,
}

// Legacy SRP login — only for accounts that haven't logged in since OPAQUE
// shipped. See docs/auth.md "Removing SRP" for the plan to delete it.

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SrpInitRequest {
    pub email_hash: String,
    /// Base64-encoded client ephemeral public key A
    pub client_public_a: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SrpInitResponse {
    pub session_id: Uuid,
    /// Base64-encoded server ephemeral public key B
    pub server_public_b: String,
    pub srp_salt: String,
    pub kdf_params: KdfParams,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SrpVerifyRequest {
    pub session_id: Uuid,
    /// Base64-encoded client proof M1
    pub client_proof_m1: String,
    /// Optional device UUID — if provided, links the new session to this trusted device
    /// and updates device.last_seen_at. Silently ignored if the device doesn't belong to the user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SrpVerifyResponse {
    /// Base64-encoded server proof M2 (client must verify)
    pub server_proof_m2: String,
    #[serde(flatten)]
    pub session: LoginResponse,
}

// ─── Password change ─────────────────────────────────────────────────────────

/// Authenticated password change, round 1: an OPAQUE login with the current
/// password plus an OPAQUE registration for the new one.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChangeStartRequest {
    pub email_hash: String,
    /// OPAQUE login request made with the current password
    pub start_login_request: String,
    /// OPAQUE registration request made with the new password
    pub registration_request: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChangeStartResponse {
    pub change_id: Uuid,
    pub login_response: String,
    pub kdf_params: KdfParams,
    pub registration_response: String,
    /// Every item (tombstones included); all must come back re-encrypted
    pub items: Vec<crate::EncryptedVaultItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_private_key_iv: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChangeFinishRequest {
    pub change_id: Uuid,
    /// Proof of the current password
    pub finish_login_request: String,
    /// OPAQUE record for the new password
    pub registration_record: String,
    pub protected_symmetric_key: String,
    pub protected_symmetric_key_iv: String,
    pub protected_private_key: Option<String>,
    pub protected_private_key_iv: Option<String>,
    pub items: Vec<ReencryptedItem>,
}

// ─── Recovery ────────────────────────────────────────────────────────────────

/// Enable or rotate the account recovery kit (authenticated).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetRecoveryRequest {
    /// Base64 auth key derived from the recovery code; only its SHA-256 is stored
    pub recovery_auth_key: String,
    /// Base64 AES-GCM(smk || enc || mac) under the recovery wrap key
    pub recovery_blob: String,
    pub recovery_blob_iv: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryStatusResponse {
    pub enabled: bool,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryInitRequest {
    pub email_hash: String,
    pub recovery_auth_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryInitResponse {
    /// Short-lived token authorizing the recovery completion
    pub recovery_token: String,
    pub recovery_blob: String,
    pub recovery_blob_iv: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected_private_key_iv: Option<String>,
    /// Every encrypted item the client must re-encrypt under the new password
    pub items: Vec<crate::EncryptedVaultItem>,
}

/// OPAQUE registration round 1 during recovery, authorized by the recovery token.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryOpaqueStartRequest {
    pub recovery_token: String,
    pub email_hash: String,
    pub registration_request: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReencryptedItem {
    pub id: Uuid,
    pub blob: String,
    pub blob_iv: String,
    pub blob_mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryCompleteRequest {
    pub recovery_token: String,
    /// New OPAQUE record for the new master password (from recovery/opaque/start)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_record: Option<String>,
    /// Legacy: SRP credentials from clients that predate OPAQUE. Accepted so an
    /// old client can still finish a recovery; the account then migrates to
    /// OPAQUE on its next login.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub srp_salt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub srp_verifier: Option<String>,
    pub protected_symmetric_key: String,
    pub protected_symmetric_key_iv: String,
    /// RSA private key re-wrapped under the new stretched master key
    pub protected_private_key: Option<String>,
    pub protected_private_key_iv: Option<String>,
    pub items: Vec<ReencryptedItem>,
    /// Replacement recovery kit — the used code is burned
    pub recovery_auth_key: String,
    pub recovery_blob: String,
    pub recovery_blob_iv: String,
}

// ─── Shares ──────────────────────────────────────────────────────────────────

/// Create a one-time/expiring share of a single item snapshot.
/// The blob is encrypted under a random key that lives only in the share URL
/// fragment; the label is encrypted under the owner's vault key for listing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateShareRequest {
    pub blob: String,
    pub blob_iv: String,
    pub label_blob: String,
    pub label_iv: String,
    /// 1–10 views before the share stops resolving
    pub max_views: i32,
    /// 1–168 hours (7 days max)
    pub expires_in_hours: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateShareResponse {
    pub share_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShareInfo {
    pub id: Uuid,
    pub label_blob: String,
    pub label_iv: String,
    pub max_views: i32,
    pub view_count: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ViewShareResponse {
    pub blob: String,
    pub blob_iv: String,
    pub remaining_views: i32,
    pub expires_at: DateTime<Utc>,
}

// ─── Devices ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    pub device_name: String,
    pub device_type: String, // "desktop_mac" | "desktop_linux" | "desktop_windows" | "android" | "web" | "extension"
    /// Base64-encoded X25519 public key for encrypted device channel
    pub device_public_key: String,
    /// Optional: vault key re-encrypted for biometric unlock (base64)
    pub protected_device_key: Option<String>,
    pub protected_device_key_iv: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceInfo {
    pub id: Uuid,
    pub device_name: String,
    pub device_type: String,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

// ─── Vaults ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub id: Uuid,
    /// Base64 AES-GCM encrypted vault name
    pub name_blob: String,
    pub name_iv: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultRequest {
    pub name_blob: String,
    pub name_iv: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveItemRequest {
    pub to_vault_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityEventInfo {
    pub id: Uuid,
    pub event_type: String,
    pub ip: Option<String>,
    pub device_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

// ─── Generic ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConflictResponse {
    pub conflict: bool,
    pub server_version: i64,
}
