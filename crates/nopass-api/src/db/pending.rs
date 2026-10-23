use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, PgPool};
use uuid::Uuid;

/// Login handshakes kept per account; older ones are dropped on insert. Two or
/// three devices logging in at once fit; a flood of starts for one account
/// can't grow the table.
pub const MAX_PENDING_LOGINS_PER_ACCOUNT: i64 = 5;

/// Pending OPAQUE login (start → finish). `user_id` is None for the fake
/// response given to unknown or not-yet-migrated accounts.
#[derive(Debug, Clone, FromRow)]
pub struct PendingOpaqueLogin {
    pub id: Uuid,
    pub account_key: String,
    pub user_id: Option<Uuid>,
    pub server_state: Vec<u8>,
    pub created_at: DateTime<Utc>,
}

pub async fn insert_opaque_login(
    pool: &PgPool,
    id: Uuid,
    account_key: &str,
    user_id: Option<Uuid>,
    server_state: &[u8],
) -> Result<()> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO pending_opaque_logins (id, account_key, user_id, server_state) VALUES ($1, $2, $3, $4)",
    )
    .bind(id)
    .bind(account_key)
    .bind(user_id)
    .bind(server_state)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"
        DELETE FROM pending_opaque_logins
        WHERE account_key = $1 AND id NOT IN (
            SELECT id FROM pending_opaque_logins WHERE account_key = $1
            ORDER BY created_at DESC LIMIT $2
        )
        "#,
    )
    .bind(account_key)
    .bind(MAX_PENDING_LOGINS_PER_ACCOUNT)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(())
}

/// Consume the handshake atomically, like `take_srp`: one finish per start.
pub async fn take_opaque_login(pool: &PgPool, id: Uuid) -> Result<Option<PendingOpaqueLogin>> {
    let login = sqlx::query_as::<_, PendingOpaqueLogin>(
        "DELETE FROM pending_opaque_logins WHERE id = $1 RETURNING *",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(login)
}

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
    let mut tx = pool.begin().await?;
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
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"
        DELETE FROM pending_srp_sessions
        WHERE user_id = $1 AND id NOT IN (
            SELECT id FROM pending_srp_sessions WHERE user_id = $1
            ORDER BY created_at DESC LIMIT $2
        )
        "#,
    )
    .bind(user_id)
    .bind(MAX_PENDING_LOGINS_PER_ACCOUNT)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
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
pub async fn prune_expired(pool: &PgPool, login_ttl_secs: i64, recovery_ttl_secs: i64) -> Result<u64> {
    let a = sqlx::query("DELETE FROM pending_srp_sessions WHERE created_at < NOW() - ($1 * INTERVAL '1 second')")
        .bind(login_ttl_secs)
        .execute(pool)
        .await?;
    let c = sqlx::query("DELETE FROM pending_opaque_logins WHERE created_at < NOW() - ($1 * INTERVAL '1 second')")
        .bind(login_ttl_secs)
        .execute(pool)
        .await?;
    let b = sqlx::query("DELETE FROM pending_recovery_sessions WHERE created_at < NOW() - ($1 * INTERVAL '1 second')")
        .bind(recovery_ttl_secs)
        .execute(pool)
        .await?;
    Ok(a.rows_affected() + b.rows_affected() + c.rows_affected())
}
