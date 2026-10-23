use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    /// Keyed account key once `email_hash_keyed`, see AppState::account_key
    pub email_hash: String,
    /// Legacy SRP credentials — NULL once the account has migrated to OPAQUE
    pub srp_salt: Option<Vec<u8>>,
    pub srp_verifier: Option<Vec<u8>>,
    pub kdf_params: Value,
    pub protected_symmetric_key: Vec<u8>,
    pub protected_symmetric_key_iv: Vec<u8>,
    /// SPKI DER, base64 — RSA-OAEP public key for org-key wrapping
    pub public_key: Option<String>,
    pub protected_private_key: Option<String>,
    pub protected_private_key_iv: Option<String>,
    /// SHA-256 of the recovery auth key — gates access to the recovery blob
    pub recovery_auth_hash: Option<Vec<u8>>,
    /// AES-GCM(smk || enc || mac) under the client-side recovery wrap key
    pub recovery_blob: Option<Vec<u8>>,
    pub recovery_blob_iv: Option<Vec<u8>>,
    pub recovery_updated_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub opaque_record: Option<Vec<u8>>,
    pub email_hash_keyed: bool,
    /// Account key (vault enc + mac keys) wrapped under the password KEK; NULL before migration
    pub wrapped_account_key: Option<Vec<u8>>,
    pub wrapped_account_key_iv: Option<Vec<u8>>,
}
