use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email_hash: String,
    pub srp_salt: Vec<u8>,
    pub srp_verifier: Vec<u8>,
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
}
