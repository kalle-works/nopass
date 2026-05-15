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
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
