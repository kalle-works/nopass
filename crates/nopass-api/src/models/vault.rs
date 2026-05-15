use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct Vault {
    pub id: Uuid,
    pub user_id: Uuid,
    pub name_blob: Vec<u8>,
    pub name_iv: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct VaultItem {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub user_id: Uuid,
    pub item_type: String,
    pub blob: Vec<u8>,
    pub blob_iv: Vec<u8>,
    pub blob_mac: Vec<u8>,
    pub version: i64,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
pub struct SyncEvent {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Uuid,
    pub sequence_number: i64,
    pub event_type: String,
    pub item_id: Uuid,
    pub encrypted_delta: Option<Vec<u8>>,
    pub delta_iv: Option<Vec<u8>>,
    pub created_at: DateTime<Utc>,
}
