use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

#[derive(Debug, Clone, FromRow)]
pub struct Share {
    pub id: Uuid,
    pub user_id: Uuid,
    pub blob: Vec<u8>,
    pub blob_iv: Vec<u8>,
    pub label_blob: Vec<u8>,
    pub label_iv: Vec<u8>,
    pub max_views: i32,
    pub view_count: i32,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

pub async fn create_share(
    pool: &PgPool,
    user_id: Uuid,
    blob: &[u8],
    blob_iv: &[u8],
    label_blob: &[u8],
    label_iv: &[u8],
    max_views: i32,
    expires_at: DateTime<Utc>,
) -> Result<Uuid> {
    // Opportunistic housekeeping — expired shares hold ciphertext for no reason
    sqlx::query("DELETE FROM shares WHERE expires_at < NOW()")
        .execute(pool)
        .await?;

    let row = sqlx::query_as::<_, (Uuid,)>(
        r#"
        INSERT INTO shares (user_id, blob, blob_iv, label_blob, label_iv, max_views, expires_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id
        "#,
    )
    .bind(user_id)
    .bind(blob)
    .bind(blob_iv)
    .bind(label_blob)
    .bind(label_iv)
    .bind(max_views)
    .bind(expires_at)
    .fetch_one(pool)
    .await?;
    Ok(row.0)
}

pub async fn list_shares_for_user(pool: &PgPool, user_id: Uuid) -> Result<Vec<Share>> {
    let shares = sqlx::query_as::<_, Share>(
        "SELECT * FROM shares WHERE user_id = $1 AND expires_at > NOW() ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;
    Ok(shares)
}

pub async fn delete_share(pool: &PgPool, share_id: Uuid, user_id: Uuid) -> Result<bool> {
    let result = sqlx::query("DELETE FROM shares WHERE id = $1 AND user_id = $2")
        .bind(share_id)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(result.rows_affected() > 0)
}

/// Atomically consume one view. Returns None when the share doesn't exist,
/// is expired, or has no views left — indistinguishable to the caller.
pub async fn consume_view(pool: &PgPool, share_id: Uuid) -> Result<Option<Share>> {
    let share = sqlx::query_as::<_, Share>(
        r#"
        UPDATE shares
        SET view_count = view_count + 1
        WHERE id = $1 AND expires_at > NOW() AND view_count < max_views
        RETURNING *
        "#,
    )
    .bind(share_id)
    .fetch_optional(pool)
    .await?;
    Ok(share)
}
