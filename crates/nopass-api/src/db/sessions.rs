use anyhow::Result;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Duration, Utc};
use rand::RngCore;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::session::Session;

fn hash_token(token: &str) -> String {
    let hash = Sha256::digest(token.as_bytes());
    hex::encode(hash)
}

/// Create a new session. Returns the raw token (only time it is ever available in plaintext).
pub async fn create_session(
    pool: &PgPool,
    user_id: Uuid,
    device_id: Option<Uuid>,
) -> Result<String> {
    let mut raw = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let raw_token = URL_SAFE_NO_PAD.encode(raw);

    let token_hash = hash_token(&raw_token);
    let expires_at = Utc::now() + Duration::days(30);

    sqlx::query(
        "INSERT INTO sessions (user_id, device_id, token_hash, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(user_id)
    .bind(device_id)
    .bind(&token_hash)
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(raw_token)
}

pub async fn find_session_by_token(pool: &PgPool, raw_token: &str) -> Result<Option<Session>> {
    let token_hash = hash_token(raw_token);
    let session = sqlx::query_as::<_, Session>(
        "SELECT * FROM sessions WHERE token_hash = $1 AND expires_at > NOW()",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?;
    Ok(session)
}

pub async fn delete_session_by_token(pool: &PgPool, raw_token: &str) -> Result<()> {
    let token_hash = hash_token(raw_token);
    sqlx::query("DELETE FROM sessions WHERE token_hash = $1")
        .bind(token_hash)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn delete_sessions_for_user(pool: &PgPool, user_id: Uuid) -> Result<()> {
    sqlx::query("DELETE FROM sessions WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Remove sessions that have passed their expiry. Called from the hourly
/// housekeeping task — without this they accumulate indefinitely since
/// `find_session_by_token` filters them out but never deletes them.
pub async fn prune_expired(pool: &PgPool) -> Result<u64> {
    let result = sqlx::query("DELETE FROM sessions WHERE expires_at <= NOW()")
        .execute(pool)
        .await?;
    Ok(result.rows_affected())
}
