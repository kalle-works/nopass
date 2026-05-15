use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaultItemType {
    Login,
    Note,
    Card,
    Identity,
}

/// The encrypted form stored on-server. No plaintext data ever leaves the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedVaultItem {
    pub id: Uuid,
    pub vault_id: Uuid,
    pub user_id: Uuid,
    pub item_type: VaultItemType,
    /// Base64-encoded AES-256-GCM ciphertext
    pub blob: String,
    /// Base64-encoded 12-byte IV
    pub blob_iv: String,
    /// Base64-encoded HMAC-SHA256 of (iv || ciphertext)
    pub blob_mac: String,
    pub version: i64,
    pub deleted_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request body for creating a vault item
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateVaultItemRequest {
    pub item_type: VaultItemType,
    pub blob: String,
    pub blob_iv: String,
    pub blob_mac: String,
}

/// Request body for updating a vault item (with optimistic locking)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateVaultItemRequest {
    pub blob: String,
    pub blob_iv: String,
    pub blob_mac: String,
    pub version: i64,
}
