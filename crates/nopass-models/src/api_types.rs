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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterRequest {
    /// SHA-256("nopass-v1-email:" + lowercase(email)) — server never stores plaintext email
    pub email_hash: String,
    /// Base64-encoded random salt used for SRP verifier derivation
    pub srp_salt: String,
    /// Base64-encoded SRP-6a verifier (g^x mod N)
    pub srp_verifier: String,
    pub kdf_params: KdfParams,
    /// AES-256-GCM encrypted vault key (encrypted with stretchedMasterKey)
    pub protected_symmetric_key: String,
    pub protected_symmetric_key_iv: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterResponse {
    pub user_id: Uuid,
}

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SrpVerifyResponse {
    /// Base64-encoded server proof M2 (client must verify)
    pub server_proof_m2: String,
    pub session_token: String,
    pub user_id: Uuid,
    pub default_vault_id: Uuid,
    pub protected_symmetric_key: String,
    pub protected_symmetric_key_iv: String,
}

// ─── Devices ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterDeviceRequest {
    pub device_name: String,
    pub device_type: String, // "desktop_mac" | "android" | "web" | "extension"
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
