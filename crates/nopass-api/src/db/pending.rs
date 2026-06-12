use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Pending SRP handshake (init → verify), persisted so any replica can finish
/// a login another replica started.
#[derive(Debug, Clone, FromRow)]
pub struct PendingSrpSession {
    pub id: Uuid,
    pub user_id: Uuid,
    pub srp_verifier: Vec<u8>,
    pub server_ephemeral_b: Vec<u8>,
    pub client_public_a: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

pub async fn insert_srp(
    pool: &PgPool,
    id: Uuid,
    user_id: Uuid,
    srp_verifier: &[u8],
    server_ephemeral_b: &[u8],
    client_public_a: &[u8],
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO pending_srp_sessions (id, user_id, srp_verifier, server_ephemeral_b, client_public_a)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(id)
    .bind(user_id)
    .bind(srp_verifier)
    .bind(server_ephemeral_b)
    .bind(client_public_a)
    .execute(pool)
    .await?;
    Ok(())
}

/// Atomically consume the handshake — DELETE … RETURNING means a proof can
/// only ever be checked once, even across replicas racing.
pub async fn take_srp(pool: &PgPool, id: Uuid) -> Result<Option<PendingSrpSession>> {
    let session = sqlx::query_as::<_, PendingSrpSession>(
        "DELETE FROM pending_srp_sessions WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(session)
}

#[derive(Debug, Clone, FromRow)]
pub struct PendingRecoverySession {
    pub token: Uuid,
    pub user_id: Uuid,
    pub created_at: DateTime<Utc>,
}

pub async fn insert_recovery(pool: &PgPool, token: Uuid, user_id: Uuid) -> Result<()> {
    sqlx::query("INSERT INTO pending_recovery_sessions (token, user_id) VALUES ($1, $2)")
        .bind(token)
        .bind(user_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Peek without consuming — recovery completion must stay retryable after
/// transient failures (see routes/recovery.rs); the token burns on success.
pub async fn peek_recovery(pool: &PgPool, token: Uuid) -> Result<Option<PendingRecoverySession>> {
    let session = sqlx::query_as::<_, PendingRecoverySession>(
        "SELECT * FROM pending_recovery_sessions WHERE token = $1",
    )
    .bind(token)
    .fetch_optional(pool)
    .await?;
    Ok(session)
}

/// Sweep expired handshakes/tokens; runs from the periodic cleanup task.
pub async fn prune_expired(pool: &PgPool, srp_ttl_secs: i64, recovery_ttl_secs: i64) -> Result<u64> {
    let a = sqlx::query("DELETE FROM pending_srp_sessions WHERE created_at < NOW() - ($1 * INTERVAL '1 second')")
        .bind(srp_ttl_secs)
        .execute(pool)
        .await?;
    let b = sqlx::query("DELETE FROM pending_recovery_sessions WHERE created_at < NOW() - ($1 * INTERVAL '1 second')")
        .bind(recovery_ttl_secs)
        .execute(pool)
        .await?;
    Ok(a.rows_affected() + b.rows_affected())
}
