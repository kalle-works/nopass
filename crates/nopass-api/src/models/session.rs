use chrono::{DateTime, Utc};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub device_id: Option<Uuid>,
    pub token_hash: String, // SHA-256 of the raw token
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}
